"""X.509 parsing tests, all against real generated certificates."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization

from app.core.x509_utils import (
    days_until_expiry,
    describe_bytes,
    fingerprint,
    load_certificate,
)
from tests.conftest import make_certificate, make_sha1_signed_certificate


def test_reads_identity_and_validity(certificate_pem):
    facts = describe_bytes(certificate_pem)

    assert facts.common_name == "api.example.com"
    assert facts.sans == ["api.example.com", "www.example.com"]
    assert facts.issuer_organization == "Certward Test"
    assert facts.key_type == "RSA"
    assert facts.key_bits == 2048
    assert facts.is_self_signed is True
    assert facts.is_ca is False
    assert len(facts.fingerprint_sha256) == 64


def test_accepts_der_as_well_as_pem(certificate_pem):
    der = load_certificate(certificate_pem).public_bytes(serialization.Encoding.DER)

    assert describe_bytes(der).common_name == describe_bytes(certificate_pem).common_name
    assert fingerprint(der) == fingerprint(certificate_pem)


def test_ec_key_size_is_the_curve_size():
    facts = describe_bytes(make_certificate(use_ec=True, sans=["ec.example.com"]))

    assert facts.key_type == "EC (secp256r1)"
    assert facts.key_bits == 256


def test_missing_san_extension_is_empty_not_an_error():
    """A certificate with no SAN parses fine and is broken for TLS. Both true."""
    facts = describe_bytes(make_certificate(sans=None))

    assert facts.sans == []
    assert facts.common_name == "api.example.com"


def test_ca_certificate_is_flagged():
    assert describe_bytes(make_certificate(is_ca=True, sans=["ca.example.com"])).is_ca


def test_rejects_data_that_is_not_a_certificate():
    with pytest.raises(ValueError):
        describe_bytes(b"this is not a certificate")


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (timedelta(days=45), 45),
        (timedelta(days=44, hours=21), 44),   # truncates down: renew early
        (timedelta(hours=3), 0),
        (timedelta(days=-30), -30),           # not -31: see the docstring
        (timedelta(days=-1, hours=-2), -1),
    ],
)
def test_days_until_expiry_truncates_toward_zero(offset, expected):
    now = datetime.now(UTC)
    assert days_until_expiry(now + offset, now=now) == expected


def test_naive_datetimes_are_treated_as_utc():
    now = datetime.now(UTC)
    naive = (now + timedelta(days=10)).replace(tzinfo=None)

    assert days_until_expiry(naive, now=now) == 10


def test_sha1_signature_is_reported_verbatim():
    """
    The parser reports, it does not judge. Deciding that sha1 is unacceptable
    is the risk engine's job, and keeping that split means the parser stays
    correct as policy changes.
    """
    facts = describe_bytes(make_sha1_signed_certificate(sans=["old.example.com"]))

    assert "sha1" in (facts.signature_algorithm or "").lower()
