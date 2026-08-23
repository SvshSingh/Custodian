"""Domain key and CSR tests."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.acme.csr import (
    build_csr,
    csr_der,
    generate_domain_key,
    save_certificate,
    save_private_key,
)


def test_default_key_is_ec_p256():
    key = generate_domain_key()

    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert key.curve.name == "secp256r1"


def test_rsa_is_available_for_older_infrastructure():
    key = generate_domain_key("rsa", rsa_bits=2048)

    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_unknown_curve_is_rejected_with_a_useful_message():
    with pytest.raises(ValueError, match="secp256r1"):
        generate_domain_key("ec", curve="p256")


def test_csr_signature_is_valid():
    csr = build_csr(generate_domain_key(), ["api.example.com"])

    assert csr.is_signature_valid


def test_every_domain_appears_in_the_san_extension():
    """
    Including the first one. A name present only in the CN produces a
    certificate that modern clients reject outright.
    """
    domains = ["api.example.com", "www.example.com", "cdn.example.com"]
    csr = build_csr(generate_domain_key(), domains)

    sans = csr.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    assert sans == domains


def test_empty_domain_list_is_rejected():
    with pytest.raises(ValueError, match="at least one domain"):
        build_csr(generate_domain_key(), [])


def test_der_encoding_is_not_pem():
    """ACME finalize takes base64url(DER). PEM is the classic wrong answer."""
    der = csr_der(build_csr(generate_domain_key(), ["a.example.com"]))

    assert not der.startswith(b"-----BEGIN")
    assert x509.load_der_x509_csr(der).is_signature_valid


def test_private_key_is_written_atomically(tmp_path):
    path = tmp_path / "deep" / "nested" / "privkey.pem"
    save_private_key(generate_domain_key(), path)

    assert path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY")
    assert not path.with_suffix(".pem.tmp").exists()


def test_certificate_is_written_without_restrictive_permissions(tmp_path):
    """
    The certificate is public -- it is sent to every client in the handshake.
    Locking it down breaks web servers running as another user for no gain.
    """
    path = tmp_path / "fullchain.pem"
    save_certificate(b"-----BEGIN CERTIFICATE-----\n", path)

    assert path.exists()
