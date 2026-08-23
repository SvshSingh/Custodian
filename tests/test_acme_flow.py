"""
Full ACME issuance against the in-process fake CA.

This is the test that matters most in the suite. It drives every step of RFC
8555 -- directory, nonce, account, order, authorization, challenge, finalize,
poll, download -- and asserts on both sides: the client gets a usable
certificate, and the CA saw a protocol-correct conversation.
"""

from __future__ import annotations

import httpx
import pytest

from app.acme.challenge import WebrootPublisher
from app.acme.client import AcmeClient, AcmeError
from app.acme.issuance import issue_certificate, load_or_create_account_key
from app.acme.jws import generate_account_key, jwk_thumbprint
from app.core.x509_utils import describe_bytes
from tests.conftest import CA_BASE

DOMAINS = ["api.test.local", "www.test.local"]


@pytest.fixture
def account_key():
    return generate_account_key()


async def _issue(ca_transport, account_key, tmp_path, **kwargs):
    async with httpx.AsyncClient(transport=ca_transport) as http:
        return await issue_certificate(
            domains=kwargs.pop("domains", DOMAINS),
            directory_url=f"{CA_BASE}/dir",
            account_key=account_key,
            publisher=WebrootPublisher(tmp_path / "webroot"),
            cert_dir=tmp_path / "certs",
            contact_email="ops@test.local",
            http=http,
            **kwargs,
        )


async def test_issues_a_usable_certificate(fake_ca, ca_transport, account_key, tmp_path):
    issued = await _issue(ca_transport, account_key, tmp_path)

    facts = describe_bytes(issued.certificate_pem)
    assert facts.common_name == "api.test.local"
    assert facts.sans == DOMAINS
    assert facts.issuer == "Fake Test CA"
    assert issued.account_url == f"{CA_BASE}/acct/1"


async def test_writes_key_and_certificate_to_disk(fake_ca, ca_transport, account_key, tmp_path):
    from pathlib import Path

    issued = await _issue(ca_transport, account_key, tmp_path)

    assert Path(issued.private_key_path).read_bytes().startswith(b"-----BEGIN PRIVATE KEY")
    assert Path(issued.certificate_path).read_bytes().startswith(b"-----BEGIN CERTIFICATE")
    # No temp files left over from the atomic writes.
    assert not list(Path(tmp_path / "certs").rglob("*.tmp"))


async def test_recovers_from_a_stale_nonce(fake_ca, ca_transport, account_key, tmp_path):
    """The CA rejects one request with badNonce; issuance must still complete."""
    await _issue(ca_transport, account_key, tmp_path)

    assert fake_ca.bad_nonce_sent is True


async def test_csr_requests_exactly_the_ordered_names(fake_ca, ca_transport, account_key, tmp_path):
    from cryptography import x509

    await _issue(ca_transport, account_key, tmp_path)

    csr = x509.load_der_x509_csr(fake_ca.csr_der)
    requested = csr.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)

    assert requested == DOMAINS == fake_ca.identifiers


async def test_challenge_files_are_cleaned_up(fake_ca, ca_transport, account_key, tmp_path):
    await _issue(ca_transport, account_key, tmp_path)

    challenge_dir = tmp_path / "webroot" / ".well-known" / "acme-challenge"
    assert list(challenge_dir.glob("*")) == []


async def test_key_authorization_served_matches_the_account_key(
    fake_ca, ca_transport, account_key, tmp_path, monkeypatch
):
    """
    Capture what actually gets written to the webroot and check it against the
    thumbprint. This is the property the whole HTTP-01 challenge rests on.
    """
    published: dict[str, str] = {}
    original = WebrootPublisher.publish

    async def capture(self, token, key_authorization):
        published[token] = key_authorization
        await original(self, token, key_authorization)

    monkeypatch.setattr(WebrootPublisher, "publish", capture)
    await _issue(ca_transport, account_key, tmp_path)

    thumbprint = jwk_thumbprint(account_key)
    assert published, "no challenge was published"
    for token, value in published.items():
        assert value == f"{token}.{thumbprint}"


async def test_failed_validation_reports_the_ca_reason_and_cleans_up(
    fake_ca, ca_transport, account_key, tmp_path
):
    fake_ca.fail_validation = True

    with pytest.raises(AcmeError) as caught:
        await _issue(ca_transport, account_key, tmp_path)

    # The useful detail lives on the challenge, not the authorization.
    assert "did not get a 200" in caught.value.detail
    assert "acme-challenge" in caught.value.detail  # actionable hint included

    challenge_dir = tmp_path / "webroot" / ".well-known" / "acme-challenge"
    assert not challenge_dir.exists() or list(challenge_dir.glob("*")) == []


async def test_newaccount_uses_jwk_and_everything_after_uses_kid(
    fake_ca, ca_transport, account_key, tmp_path
):
    """
    The fake CA asserts this from the server side as requests arrive; this
    test just confirms the conversation actually happened.
    """
    await _issue(ca_transport, account_key, tmp_path)

    urls = [url for url, _ in fake_ca.requests]
    assert any(u.endswith("/new-acct") for u in urls)
    assert any(u.endswith("/finalize") for u in urls)


async def test_account_key_is_reused_across_runs(tmp_path):
    """
    Regenerating the account key each run would restart CA rate limits and
    discard cached authorizations.
    """
    path = tmp_path / "account.key"
    first = load_or_create_account_key(path)
    second = load_or_create_account_key(path)

    assert jwk_thumbprint(first) == jwk_thumbprint(second)


async def test_revocation_is_signed_and_accepted(fake_ca, ca_transport, account_key, tmp_path):
    issued = await _issue(ca_transport, account_key, tmp_path)

    from cryptography.hazmat.primitives import serialization

    from app.core.x509_utils import load_certificate

    der = load_certificate(issued.certificate_pem).public_bytes(serialization.Encoding.DER)

    async with httpx.AsyncClient(transport=ca_transport) as http:
        client = AcmeClient(f"{CA_BASE}/dir", account_key, http, account_url=f"{CA_BASE}/acct/1")
        await client.revoke(der, reason=4)  # 4 = superseded

    assert any(url.endswith("/revoke") for url, _ in fake_ca.requests)
