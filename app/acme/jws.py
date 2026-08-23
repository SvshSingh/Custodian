"""
JWK / JWS primitives for ACME (RFC 8555).

Every ACME request except the directory fetch is a POST whose body is a
*flattened JSON JWS* signed with the client's account key. This module owns
that construction, plus the JWK thumbprint that HTTP-01 key authorizations
are built from.

Why hand-rolled instead of using josepy?
  Two reasons. It is about 120 lines of well-specified work, and the RFC
  publishes a test vector for the thumbprint (RFC 7638 section 3.1) so the
  implementation is verifiable rather than trusted. See tests/test_jws.py.

Boundary: this module deals with the *account* key only. Domain keys and
CSRs live in app/acme/csr.py -- they are a different keypair with a
different lifetime, and conflating them is the classic PKI mistake.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --------------------------------------------------------------------------
# base64url, the encoding used everywhere in JOSE
# --------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    """base64url with padding stripped (RFC 7515 appendix C)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Inverse of b64url -- re-adds the padding base64 needs."""
    padding_needed = -len(text) % 4
    return base64.urlsafe_b64decode(text + ("=" * padding_needed))


def _int_to_bytes(value: int) -> bytes:
    """Big-endian minimal-length encoding, as JOSE requires for RSA n and e."""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


# --------------------------------------------------------------------------
# Account key lifecycle
# --------------------------------------------------------------------------

def generate_account_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def save_account_key(key: rsa.RSAPrivateKey, path: str | Path) -> None:
    """
    Write the account key as unencrypted PKCS#8 PEM, mode 0600.

    Written to a temp file in the same directory then renamed, so a crash
    mid-write can never leave a truncated private key on disk. os.replace
    is atomic on POSIX; on Windows it is atomic for same-volume renames.
    """
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
        # Windows does not honour POSIX modes; NTFS ACLs govern instead.
        pass


def load_account_key(path: str | Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("account key must be RSA")
    return key


# --------------------------------------------------------------------------
# JWK and thumbprint
# --------------------------------------------------------------------------

def public_jwk(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> dict[str, str]:
    """
    The public JWK for an RSA key. Accepts a private or public key so the
    thumbprint can be checked against RFC test vectors, which publish only
    the public half.

    Key order matters here: RFC 7638 requires the *lexicographic* order
    e, kty, n for the thumbprint input, and Python dicts preserve insertion
    order, so building it in that order lets the same dict serve both as the
    protected-header "jwk" and as the thumbprint input.
    """
    public = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    numbers = public.public_numbers()
    return {
        "e": b64url(_int_to_bytes(numbers.e)),
        "kty": "RSA",
        "n": b64url(_int_to_bytes(numbers.n)),
    }


def jwk_thumbprint(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> str:
    """
    base64url(SHA-256(canonical JWK)) -- RFC 7638 section 3.

    "Canonical" means: only the required members for the key type, sorted
    by name, serialised with no whitespace. Any extra member or stray space
    changes the digest and the CA will reject your key authorization with a
    completely unhelpful error, which is exactly why this has a test vector.
    """
    canonical = json.dumps(
        public_jwk(key), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return b64url(hashlib.sha256(canonical).digest())


def key_authorization(token: str, key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> str:
    """
    The value served at /.well-known/acme-challenge/<token> for HTTP-01.

    token + "." + thumbprint. The CA hands out the token publicly, so on its
    own it proves nothing -- anyone watching the wire has it. Joining it to a
    fingerprint of *your account public key* is what makes serving the file
    proof of both domain control and account identity at once.
    """
    return f"{token}.{jwk_thumbprint(key)}"


def dns_challenge_value(token: str, key: rsa.RSAPrivateKey) -> str:
    """
    The TXT value for _acme-challenge.<domain> in a DNS-01 challenge.

    Note the extra hash compared to HTTP-01: DNS-01 publishes
    base64url(SHA256(key_authorization)), not the key authorization itself,
    because TXT records are size-constrained and publicly enumerable.
    """
    digest = hashlib.sha256(key_authorization(token, key).encode("utf-8")).digest()
    return b64url(digest)


# --------------------------------------------------------------------------
# JWS signing
# --------------------------------------------------------------------------

def sign_jws(
    key: rsa.RSAPrivateKey,
    url: str,
    nonce: str,
    payload: Any = None,
    kid: str | None = None,
) -> dict[str, str]:
    """
    Build a flattened JSON JWS for one ACME request.

    Two identification modes, and using the wrong one is a common first bug:
      - kid=None  -> the full public "jwk" goes in the header. Used *only*
                     for newAccount and revokeCert-by-key, where the server
                     does not yet know you.
      - kid=<url> -> the account URL goes in the header instead. Used for
                     everything after registration.

    payload=None means POST-as-GET (RFC 8555 section 6.3): the payload is the
    *empty string*, not an encoded empty object. Encoding {} instead makes
    the server return a confusing malformed-request error.
    """
    protected: dict[str, Any] = {"alg": "RS256", "nonce": nonce, "url": url}
    if kid is None:
        protected["jwk"] = public_jwk(key)
    else:
        protected["kid"] = kid

    protected_b64 = b64url(json.dumps(protected, separators=(",", ":")).encode())
    payload_b64 = (
        "" if payload is None
        else b64url(json.dumps(payload, separators=(",", ":")).encode())
    )

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url(signature),
    }


def external_account_binding(
    account_key: rsa.RSAPrivateKey,
    kid: str,
    hmac_key_b64: str,
    directory_url_new_account: str,
) -> dict[str, str]:
    """
    Build the EAB object for CAs that require one (RFC 8555 section 7.3.4).

    Let's Encrypt lets anyone create an account anonymously. A commercial CA
    -- DigiCert, ZeroSSL, Sectigo -- needs the ACME account tied to a paying
    contract, so it issues a key ID and an HMAC secret out of band. The
    newAccount request then carries this inner JWS, signed with the *HMAC*
    key over your *account public key*, proving the new account belongs to
    an existing customer.

    Not exercised against a live commercial CA in this project -- Pebble and
    Let's Encrypt staging do not require EAB -- so treat it as reference
    code. It is here because the structure is the interesting part.
    """
    protected = {"alg": "HS256", "kid": kid, "url": directory_url_new_account}
    protected_b64 = b64url(json.dumps(protected, separators=(",", ":")).encode())
    payload_b64 = b64url(
        json.dumps(public_jwk(account_key), separators=(",", ":")).encode()
    )

    secret = b64url_decode(hmac_key_b64)
    signature = hmac.new(
        secret, f"{protected_b64}.{payload_b64}".encode("ascii"), hashlib.sha256
    ).digest()

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url(signature),
    }
