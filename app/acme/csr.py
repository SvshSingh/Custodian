"""
Domain keys and certificate signing requests.

This is the *other* keypair. The account key in jws.py identifies you to the
CA and is long-lived; the domain key here is the key the certificate is
actually issued against, lives on the server that terminates TLS, and is
normally rotated at every renewal.

Keeping them separate matters practically, not just conceptually: the
account key must be reachable by whatever runs renewals, while the domain
private key ideally never leaves the host that will serve it. Reusing one
key for both collapses that boundary.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey


def generate_domain_key(
    key_type: str = "ec", rsa_bits: int = 2048, curve: str = "secp256r1"
) -> PrivateKey:
    """
    Generate the private key a certificate will be issued against.

    EC is the default. P-256 gives roughly 128-bit security against RSA-2048's
    ~112, in a key an order of magnitude smaller, with faster handshakes. RSA
    remains available because some load balancers and older middleboxes still
    require it.
    """
    if key_type.lower() == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)

    curves = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }
    if curve.lower() not in curves:
        raise ValueError(
            f"unsupported curve {curve!r}; choose one of {', '.join(curves)}"
        )
    return ec.generate_private_key(curves[curve.lower()])


def build_csr(key: PrivateKey, domains: list[str]) -> x509.CertificateSigningRequest:
    """
    Build a CSR for one or more domains.

    Every domain goes in the SAN extension, including the first one. Putting
    it only in the CN produces a certificate modern clients reject, because
    hostname verification reads SAN and ignores CN entirely. The CN is set as
    well purely for human-readable output in `openssl x509 -text`.

    ACME servers ignore most of what you can put in a CSR -- the CA decides
    validity dates, key usage and issuer. What it reads is the public key and
    the requested names, and it will refuse names you have not proven control
    of, so this must match the order's identifiers exactly.
    """
    if not domains:
        raise ValueError("at least one domain is required")

    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
        critical=False,
    )
    return builder.sign(key, hashes.SHA256())


def csr_der(csr: x509.CertificateSigningRequest) -> bytes:
    """
    DER bytes, which is what ACME wants.

    RFC 8555 finalize takes base64url(DER), not PEM. Sending PEM is a common
    first mistake and the resulting CA error message rarely says so.
    """
    return csr.public_bytes(serialization.Encoding.DER)


def save_private_key(key: PrivateKey, path: str | Path) -> None:
    """Write an unencrypted PKCS#8 PEM private key, atomically, mode 0600."""
    import os

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(pem)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


def save_certificate(pem: bytes, path: str | Path) -> None:
    """
    Write the issued certificate chain.

    Deliberately not 0600: the certificate is public by definition -- it is
    sent to every client in the handshake -- and making it unreadable is a
    good way to break a web server running as a different user.
    """
    import os

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(pem)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
