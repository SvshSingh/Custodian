"""
Shared fixtures.

The interesting one is `fake_ca` -- an in-process ACME server built on
httpx.MockTransport. It implements enough of RFC 8555 to drive a real
issuance: directory, nonces, account creation, orders, authorizations,
challenges, finalize, and certificate download, and it signs the result with
a CA key generated for the test.

That is what makes the ACME client testable without network access, without
Docker, and in about a second. It also asserts protocol invariants from the
server's side -- that newAccount uses a `jwk` header and everything after it
uses `kid`, that the CSR signature is valid -- so a client-side regression
fails loudly here rather than surfacing as a rejection from a real CA.

The fake CA also injects one `badNonce` response, because the retry path is
easy to get wrong and impossible to trigger reliably against a real server.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.acme.jws import b64url_decode

CA_BASE = "https://ca.test"


# --------------------------------------------------------------------------
# certificate factory
# --------------------------------------------------------------------------

def make_certificate(
    common_name: str = "api.example.com",
    sans: list[str] | None = None,
    days_valid: int = 90,
    days_ago_issued: int = 1,
    key_size: int = 2048,
    use_ec: bool = False,
    is_ca: bool = False,
) -> bytes:
    """Build a self-signed certificate as PEM. Used across the test suite."""
    key = ec.generate_private_key(ec.SECP256R1()) if use_ec else rsa.generate_private_key(
        public_exponent=65537, key_size=key_size
    )
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Certward Test"),
        ]
    )
    now = datetime.now(UTC)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=days_ago_issued))
        .not_valid_after(now - timedelta(days=days_ago_issued) + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )

    if sans is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )

    certificate = builder.sign(key, hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.PEM)


# DER encodings of the AlgorithmIdentifier OIDs. Both are 9 content bytes, so
# substituting one for the other leaves every enclosing length valid.
_OID_SHA256_RSA = bytes.fromhex("2a864886f70d01010b")  # 1.2.840.113549.1.1.11
_OID_SHA1_RSA = bytes.fromhex("2a864886f70d010105")   # 1.2.840.113549.1.1.5


def make_sha1_signed_certificate(**kwargs) -> bytes:
    """
    A certificate whose signatureAlgorithm reads sha1WithRSAEncryption.

    cryptography >= 50 refuses to *produce* a SHA-1 signature, which is
    correct of it -- but a discovery tool still has to *read* the ones already
    deployed, and refusing to parse them would blind the inventory to exactly
    the certificates most worth reporting. So the OID is rewritten in the DER
    after signing. The signature itself no longer matches the algorithm it
    claims, which is fine here: nothing in the parse path verifies it, and the
    field under test is the one being rewritten.
    """
    certificate = x509.load_pem_x509_certificate(make_certificate(**kwargs))
    der = certificate.public_bytes(serialization.Encoding.DER)

    patched = der.replace(_OID_SHA256_RSA, _OID_SHA1_RSA)
    assert patched != der, "expected a sha256WithRSAEncryption OID to rewrite"
    return patched


@pytest.fixture
def certificate_pem() -> bytes:
    return make_certificate(sans=["api.example.com", "www.example.com"])


# --------------------------------------------------------------------------
# the fake CA
# --------------------------------------------------------------------------

class FakeCA:
    """A minimal RFC 8555 server for tests. Records what it was sent."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Test CA")])
        self.nonce_counter = 0
        self.answered: set[str] = set()
        self.finalized = False
        self.csr_der: bytes | None = None
        self.requests: list[tuple[str, dict]] = []
        self.bad_nonce_sent = False
        self.identifiers: list[str] = []
        self.fail_validation = False

    # -- helpers -----------------------------------------------------------

    def _nonce(self) -> str:
        self.nonce_counter += 1
        return f"nonce-{self.nonce_counter}"

    def _issue(self, csr_der: bytes) -> bytes:
        csr = x509.load_der_x509_csr(csr_der)
        assert csr.is_signature_valid, "client sent a CSR with an invalid signature"
        sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        now = datetime.now(UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.name)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(sans, critical=False)
            .sign(self.key, hashes.SHA256())
        )
        return certificate.public_bytes(serialization.Encoding.PEM)

    # -- the handler -------------------------------------------------------

    def handle(self, request):
        import httpx

        url = str(request.url)
        headers = {"Replay-Nonce": self._nonce()}

        if url.endswith("/dir"):
            return httpx.Response(
                200,
                json={
                    "newNonce": f"{CA_BASE}/nonce",
                    "newAccount": f"{CA_BASE}/new-acct",
                    "newOrder": f"{CA_BASE}/new-order",
                    "revokeCert": f"{CA_BASE}/revoke",
                },
                headers=headers,
            )

        if url.endswith("/nonce"):
            return httpx.Response(200, headers=headers)

        body = json.loads(request.content)
        protected = json.loads(b64url_decode(body["protected"]))
        payload = json.loads(b64url_decode(body["payload"])) if body["payload"] else None
        self.requests.append((url, protected))

        # Force the client through its stale-nonce retry exactly once.
        if url.endswith("/new-order") and not self.bad_nonce_sent:
            self.bad_nonce_sent = True
            return httpx.Response(
                400,
                json={"type": "urn:ietf:params:acme:error:badNonce", "detail": "stale nonce"},
                headers=headers,
            )

        if url.endswith("/new-acct"):
            assert "jwk" in protected, "newAccount must carry the full jwk"
            assert "kid" not in protected, "newAccount must not use kid"
            return httpx.Response(
                201, json={"status": "valid"},
                headers={**headers, "Location": f"{CA_BASE}/acct/1"},
            )

        assert protected.get("kid") == f"{CA_BASE}/acct/1", (
            f"request to {url} must be signed with kid, not jwk"
        )

        if url.endswith("/new-order"):
            self.identifiers = [i["value"] for i in payload["identifiers"]]
            return httpx.Response(
                201,
                json={
                    "status": "pending",
                    "identifiers": payload["identifiers"],
                    "authorizations": [
                        f"{CA_BASE}/authz/{n}" for n in range(len(self.identifiers))
                    ],
                    "finalize": f"{CA_BASE}/finalize",
                },
                headers={**headers, "Location": f"{CA_BASE}/order/1"},
            )

        if "/authz/" in url:
            index = url.rsplit("/", 1)[-1]
            answered = f"chal-{index}" in self.answered
            if answered and self.fail_validation:
                return httpx.Response(
                    200,
                    json={
                        "status": "invalid",
                        "identifier": {"type": "dns", "value": self.identifiers[int(index)]},
                        "challenges": [
                            {
                                "type": "http-01",
                                "url": f"{CA_BASE}/chal/{index}",
                                "token": f"tok{index}",
                                "status": "invalid",
                                "error": {
                                    "type": "urn:ietf:params:acme:error:unauthorized",
                                    "detail": "did not get a 200 for the challenge file",
                                },
                            }
                        ],
                    },
                    headers=headers,
                )
            return httpx.Response(
                200,
                json={
                    "status": "valid" if answered else "pending",
                    "identifier": {"type": "dns", "value": self.identifiers[int(index)]},
                    "challenges": [
                        {
                            "type": "http-01",
                            "url": f"{CA_BASE}/chal/{index}",
                            "token": f"tok{index}",
                            "status": "valid" if answered else "pending",
                        }
                    ],
                },
                headers=headers,
            )

        if "/chal/" in url:
            self.answered.add(f"chal-{url.rsplit('/', 1)[-1]}")
            return httpx.Response(200, json={"status": "processing"}, headers=headers)

        if url.endswith("/finalize"):
            self.csr_der = b64url_decode(payload["csr"])
            self.finalized = True
            return httpx.Response(200, json={"status": "processing"}, headers=headers)

        if url.endswith("/order/1"):
            if not self.finalized:
                return httpx.Response(200, json={"status": "pending"}, headers=headers)
            return httpx.Response(
                200,
                json={"status": "valid", "certificate": f"{CA_BASE}/cert/1"},
                headers=headers,
            )

        if "/cert/" in url:
            assert self.csr_der is not None
            return httpx.Response(200, content=self._issue(self.csr_der), headers=headers)

        if url.endswith("/revoke"):
            return httpx.Response(200, json={}, headers=headers)

        return httpx.Response(404, json={"type": "about:blank", "detail": url}, headers=headers)


@pytest.fixture
def fake_ca() -> FakeCA:
    return FakeCA()


@pytest.fixture
def ca_transport(fake_ca: FakeCA):
    import httpx

    return httpx.MockTransport(fake_ca.handle)


# --------------------------------------------------------------------------
# database and app
# --------------------------------------------------------------------------

@pytest_asyncio.fixture
async def db_session(tmp_path, monkeypatch):
    """
    A fresh SQLite database per test, on disk in tmp_path.

    On disk rather than in memory because an async in-memory SQLite database
    is per-connection, so the schema created on one connection is invisible
    to the next -- a confusing failure that looks like a missing table.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app import models  # noqa: F401 -- registers tables
    from app.db import Base

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session

    await engine.dispose()
