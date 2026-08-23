"""
JWS and JWK tests.

The thumbprint test is the important one: it checks the implementation
against the example published in RFC 7638 section 3.1 rather than against
itself. A test that only round-trips your own code proves the code is
self-consistent, which is exactly what a wrong canonicalisation also is.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.acme import jws

# RFC 7638 section 3.1 -- the published worked example.
RFC7638_N = (
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxu"
    "hDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN"
    "5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5"
    "hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBni"
    "Iqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
)
RFC7638_E = "AQAB"
RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


@pytest.fixture(scope="module")
def account_key() -> rsa.RSAPrivateKey:
    return jws.generate_account_key()


def test_thumbprint_matches_rfc7638_vector():
    n = int.from_bytes(jws.b64url_decode(RFC7638_N), "big")
    e = int.from_bytes(jws.b64url_decode(RFC7638_E), "big")
    public_key = rsa.RSAPublicNumbers(e, n).public_key()

    assert jws.jwk_thumbprint(public_key) == RFC7638_THUMBPRINT


def test_public_jwk_round_trips_rfc_values():
    n = int.from_bytes(jws.b64url_decode(RFC7638_N), "big")
    e = int.from_bytes(jws.b64url_decode(RFC7638_E), "big")
    jwk = jws.public_jwk(rsa.RSAPublicNumbers(e, n).public_key())

    assert jwk == {"e": RFC7638_E, "kty": "RSA", "n": RFC7638_N}


def test_b64url_has_no_padding():
    assert "=" not in jws.b64url(b"any length of bytes at all!")
    assert jws.b64url_decode(jws.b64url(b"round trip")) == b"round trip"


def test_jwk_mode_carries_the_public_key(account_key):
    """newAccount identifies by jwk, because the server has no kid for us yet."""
    signed = jws.sign_jws(account_key, url="https://ca/new-acct", nonce="n1", payload={"a": 1})
    header = json.loads(jws.b64url_decode(signed["protected"]))

    assert header["alg"] == "RS256"
    assert header["url"] == "https://ca/new-acct"
    assert header["nonce"] == "n1"
    assert "jwk" in header and "kid" not in header


def test_kid_mode_replaces_the_jwk(account_key):
    signed = jws.sign_jws(
        account_key, url="https://ca/order", nonce="n2", payload={}, kid="https://ca/acct/1"
    )
    header = json.loads(jws.b64url_decode(signed["protected"]))

    assert header["kid"] == "https://ca/acct/1"
    assert "jwk" not in header


def test_post_as_get_sends_an_empty_payload(account_key):
    """
    RFC 8555 section 6.3: the payload is the empty string, not an encoded
    empty object. Sending b64url(b"{}") produces a malformed-request error
    from real CAs with no hint as to why.
    """
    signed = jws.sign_jws(account_key, url="https://ca/authz/1", nonce="n3", payload=None)

    assert signed["payload"] == ""
    assert signed["payload"] != jws.b64url(b"{}")


def test_signature_verifies_over_the_signing_input(account_key):
    signed = jws.sign_jws(account_key, url="https://ca/x", nonce="n4", payload={"hello": "world"})
    signing_input = f"{signed['protected']}.{signed['payload']}".encode("ascii")

    # Raises InvalidSignature if wrong; no assertion needed.
    account_key.public_key().verify(
        jws.b64url_decode(signed["signature"]),
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_key_authorization_is_token_dot_thumbprint(account_key):
    token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
    authorization = jws.key_authorization(token, account_key)

    prefix, _, thumbprint = authorization.partition(".")
    assert prefix == token
    assert thumbprint == jws.jwk_thumbprint(account_key)


def test_dns_value_is_hashed_but_http_value_is_not(account_key):
    """
    DNS-01 publishes base64url(SHA256(key_authorization)); HTTP-01 publishes
    the key authorization itself. Mixing them up is a silent validation
    failure, so it is worth pinning.
    """
    token = "tok"
    http_value = jws.key_authorization(token, account_key)
    dns_value = jws.dns_challenge_value(token, account_key)

    assert dns_value != http_value
    assert len(dns_value) == 43  # base64url of 32 bytes, unpadded


def test_account_key_round_trips_through_disk(tmp_path, account_key):
    path = tmp_path / "nested" / "account.key"
    jws.save_account_key(account_key, path)
    loaded = jws.load_account_key(path)

    assert jws.jwk_thumbprint(loaded) == jws.jwk_thumbprint(account_key)
    assert not path.with_suffix(path.suffix + ".tmp").exists(), "temp file left behind"


def test_external_account_binding_is_signed_with_the_hmac_key(account_key):
    import hashlib
    import hmac

    secret = b"a shared secret from the CA"
    eab = jws.external_account_binding(
        account_key, kid="kid-1", hmac_key_b64=jws.b64url(secret),
        directory_url_new_account="https://ca/new-acct",
    )

    expected = hmac.new(
        secret, f"{eab['protected']}.{eab['payload']}".encode("ascii"), hashlib.sha256
    ).digest()
    assert jws.b64url_decode(eab["signature"]) == expected

    # The payload is our account public key -- that is what is being bound.
    assert json.loads(jws.b64url_decode(eab["payload"])) == jws.public_jwk(account_key)
