"""
X.509 certificate parsing.

Everything here operates on a real certificate -- PEM or DER bytes off the
wire or off disk -- and returns plain data. No network, no database, no
guessing: if a field is absent from the certificate it comes back as None
rather than being invented.

The fields exposed are the ones a lifecycle system actually acts on:
identity (who is this for), provenance (who signed it), the validity window
(when does it break), and key strength (is it still acceptable).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass
class CertificateFacts:
    """What we know about one certificate, all of it read from the cert."""

    common_name: str | None
    sans: list[str]
    issuer: str | None
    issuer_organization: str | None
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str | None
    key_type: str
    key_bits: int | None
    fingerprint_sha256: str
    is_self_signed: bool
    is_ca: bool
    key_usage: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        data = asdict(self)
        data["not_before"] = self.not_before.isoformat()
        data["not_after"] = self.not_after.isoformat()
        return data


def load_certificate(data: bytes) -> x509.Certificate:
    """
    Load a certificate from PEM or DER, whichever it turns out to be.

    Callers get bytes from three places -- a file, a TLS handshake, an ACME
    download -- and only one of those is reliably PEM, so sniffing beats
    making every caller declare the encoding.
    """
    stripped = data.lstrip()
    if stripped.startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def _name_attribute(name: x509.Name, oid) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return values[0].value if values else None


def _describe_key(cert: x509.Certificate) -> tuple[str, int | None]:
    """
    Algorithm name and effective size.

    EC key size is the curve size, not a modulus length -- P-256 is 256 bits
    and is stronger than RSA-2048, so never compare these numbers directly.
    Ed25519 has no size parameter at all, hence the None.
    """
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC ({key.curve.name})", key.curve.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", None
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    return type(key).__name__, None


def _subject_alt_names(cert: x509.Certificate) -> list[str]:
    """
    DNS names from the SAN extension.

    SAN is the field that governs hostname matching. CN has been deprecated
    for that purpose since RFC 2818 and browsers stopped honouring it years
    ago, so a certificate with a CN and no SAN is broken in practice even
    though it parses fine.
    """
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


def _key_usage(cert: x509.Certificate) -> list[str]:
    try:
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return []

    flags = [
        ("digital_signature", usage.digital_signature),
        ("content_commitment", usage.content_commitment),
        ("key_encipherment", usage.key_encipherment),
        ("data_encipherment", usage.data_encipherment),
        ("key_agreement", usage.key_agreement),
        ("key_cert_sign", usage.key_cert_sign),
        ("crl_sign", usage.crl_sign),
    ]
    return [name for name, enabled in flags if enabled]


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(
            cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
        )
    except x509.ExtensionNotFound:
        return False


def describe(cert: x509.Certificate) -> CertificateFacts:
    """Extract everything the lifecycle engine needs from one certificate."""
    algorithm: str | None
    try:
        algorithm = cert.signature_algorithm_oid._name
    except AttributeError:  # pragma: no cover - defensive across library versions
        algorithm = None

    key_type, key_bits = _describe_key(cert)

    return CertificateFacts(
        common_name=_name_attribute(cert.subject, NameOID.COMMON_NAME),
        sans=_subject_alt_names(cert),
        issuer=_name_attribute(cert.issuer, NameOID.COMMON_NAME),
        issuer_organization=_name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME),
        serial_number=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        signature_algorithm=algorithm,
        key_type=key_type,
        key_bits=key_bits,
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        # Self-signed here means "subject equals issuer", which is a cheap
        # structural check. Verifying the signature against its own key would
        # prove it properly; for inventory purposes the name match is enough
        # to flag "this did not come from a CA".
        is_self_signed=cert.subject == cert.issuer,
        is_ca=_is_ca(cert),
        key_usage=_key_usage(cert),
    )


def describe_bytes(data: bytes) -> CertificateFacts:
    return describe(load_certificate(data))


def fingerprint(data: bytes) -> str:
    """
    SHA-256 fingerprint, the identifier used to dedupe the inventory.

    Computed over the DER encoding, which is why it is stable: the same
    certificate delivered as PEM from a file and as DER from a handshake
    produces the same fingerprint.
    """
    return load_certificate(data).fingerprint(hashes.SHA256()).hex()


def days_until_expiry(not_after: datetime, now: datetime | None = None) -> int:
    """
    Whole days remaining. Negative once expired.

    Two details that are easy to get wrong and hard to notice:

    1. Naive datetimes are treated as UTC rather than local time.
       Certificates are always UTC, and quietly interpreting one as local
       time shifts every expiry calculation by the machine's offset -- a bug
       that only shows up in production on a differently-configured host.

    2. This truncates toward zero instead of using timedelta.days, which
       floors. For a certificate that expired 30 days and one second ago,
       timedelta.days reports -31. Truncating reports -30, which is what
       both a human and an alert threshold expect. On the positive side both
       agree: 44.9 days remaining reports 44, erring toward renewing early.
    """
    now = now or datetime.now(UTC)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return int((not_after - now).total_seconds() / 86400)
