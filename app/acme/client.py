"""
A minimal ACME client (RFC 8555).

Scope: account registration, order placement, HTTP-01 validation,
finalization, download, and revocation -- against any compliant CA. That is
the whole issuance path and it is deliberately the whole file, so the
protocol can be read top to bottom rather than assembled from a package.

What it does not do: DNS-01 (the value computation is in jws.py, the
provider plumbing is not here), certificate renewal-info (ARI), or account
key rollover. Those are noted in the README rather than stubbed, because a
stub that returns None is worse than an honest absence.

The shape of the protocol, in one paragraph:
every request except the directory fetch is a POST whose body is a JWS
signed with your account key, and every response hands back a fresh nonce in
a header that the *next* request must carry. That nonce chain is the replay
defence, and it is the thing that makes ACME feel unusual to write -- you
cannot fire requests in parallel with one account, and you must be ready for
the server to reject a nonce it considers stale.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa

from app.acme.jws import b64url, key_authorization, sign_jws

log = logging.getLogger("custodian.acme")

JOSE_CONTENT_TYPE = "application/jose+json"

# Terminal ACME error codes -- retrying these changes nothing, they need a
# human. Anything else is treated as transient and retried with backoff.
FATAL_ERROR_TYPES = {
    "urn:ietf:params:acme:error:accountDoesNotExist",
    "urn:ietf:params:acme:error:badCSR",
    "urn:ietf:params:acme:error:badPublicKey",
    "urn:ietf:params:acme:error:badRevocationReason",
    "urn:ietf:params:acme:error:externalAccountRequired",
    "urn:ietf:params:acme:error:invalidContact",
    "urn:ietf:params:acme:error:rejectedIdentifier",
    "urn:ietf:params:acme:error:unauthorized",
    "urn:ietf:params:acme:error:unsupportedIdentifier",
}


class AcmeError(RuntimeError):
    """An error document returned by the CA (RFC 7807 problem+json)."""

    def __init__(self, status: int, problem: dict[str, Any]):
        self.status = status
        self.type = problem.get("type", "about:blank")
        self.detail = problem.get("detail", "")
        self.subproblems = problem.get("subproblems", [])
        super().__init__(f"{self.type}: {self.detail}")

    @property
    def is_fatal(self) -> bool:
        return self.type in FATAL_ERROR_TYPES


@dataclass
class Order:
    url: str
    status: str
    identifiers: list[str]
    authorization_urls: list[str]
    finalize_url: str
    certificate_url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Http01Challenge:
    """One HTTP-01 challenge, with everything needed to satisfy it."""

    authorization_url: str
    challenge_url: str
    token: str
    key_authorization: str
    domain: str


class AcmeClient:
    """
    One account's conversation with one CA.

    Not safe for concurrent use by design, not by accident: the nonce chain
    is stateful, so two coroutines sharing a client will steal each other's
    nonces. Use one client per issuance, or serialise access.
    """

    def __init__(
        self,
        directory_url: str,
        account_key: rsa.RSAPrivateKey,
        http: httpx.AsyncClient,
        account_url: str | None = None,
    ):
        self.directory_url = directory_url
        self.account_key = account_key
        self.http = http
        self.account_url = account_url
        self._directory: dict[str, Any] | None = None
        self._nonce: str | None = None

    # -- plumbing ----------------------------------------------------------

    async def directory(self) -> dict[str, Any]:
        """Fetch and cache the CA's endpoint map. The only unsigned GET."""
        if self._directory is None:
            response = await self.http.get(self.directory_url)
            response.raise_for_status()
            self._directory = response.json()
            log.debug("acme directory loaded: %s", sorted(self._directory))
        return self._directory

    def _store_nonce(self, response: httpx.Response) -> None:
        nonce = response.headers.get("Replay-Nonce")
        if nonce:
            self._nonce = nonce

    async def _get_nonce(self) -> str:
        """
        Return a usable nonce, fetching one if we have none banked.

        Every response carries a replacement, so in the steady state this
        never hits the network -- it only does so before the first request
        and after a nonce is consumed by a failure.
        """
        if self._nonce is None:
            directory = await self.directory()
            response = await self.http.head(directory["newNonce"])
            response.raise_for_status()
            self._store_nonce(response)
        nonce, self._nonce = self._nonce, None
        if nonce is None:
            raise RuntimeError("CA did not return a Replay-Nonce")
        return nonce

    async def _post(
        self,
        url: str,
        payload: Any = None,
        use_jwk: bool = False,
        retries: int = 1,
    ) -> httpx.Response:
        """
        Signed POST, with one automatic retry on a stale nonce.

        badNonce is not really an error -- it is the server telling you to use
        the value it just handed back. RFC 8555 section 6.5 requires clients
        to retry it, and not doing so produces intermittent failures under
        clock skew or load balancing that are miserable to reproduce.
        """
        nonce = await self._get_nonce()
        kid = None if use_jwk else self.account_url
        body = sign_jws(self.account_key, url=url, nonce=nonce, payload=payload, kid=kid)

        response = await self.http.post(
            url, content=json.dumps(body), headers={"Content-Type": JOSE_CONTENT_TYPE}
        )
        self._store_nonce(response)

        if response.status_code >= 400:
            problem = _problem(response)
            error = AcmeError(response.status_code, problem)
            if error.type.endswith("badNonce") and retries > 0:
                log.warning("stale nonce, retrying %s", url)
                return await self._post(url, payload, use_jwk, retries - 1)
            raise error

        return response

    # -- account -----------------------------------------------------------

    async def register_account(
        self,
        contact_email: str | None = None,
        external_account_binding: dict[str, str] | None = None,
    ) -> str:
        """
        Create the account, or recover the URL of an existing one.

        onlyReturnExisting is not used here: newAccount is idempotent for a
        given key, so a repeat call returns 200 with the same Location rather
        than creating a duplicate. That makes this safe to call on every run,
        which is what you want in a service that may restart at any time.
        """
        directory = await self.directory()
        payload: dict[str, Any] = {"termsOfServiceAgreed": True}
        if contact_email:
            payload["contact"] = [f"mailto:{contact_email}"]
        if external_account_binding:
            payload["externalAccountBinding"] = external_account_binding

        response = await self._post(directory["newAccount"], payload, use_jwk=True)
        account_url = response.headers.get("Location")
        if not account_url:
            raise RuntimeError("newAccount response had no Location header")

        self.account_url = account_url
        log.info("acme account ready: %s", account_url)
        return account_url

    # -- orders ------------------------------------------------------------

    async def new_order(self, domains: list[str]) -> Order:
        directory = await self.directory()
        payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        response = await self._post(directory["newOrder"], payload)
        data = response.json()
        return Order(
            url=response.headers["Location"],
            status=data["status"],
            identifiers=[i["value"] for i in data["identifiers"]],
            authorization_urls=data["authorizations"],
            finalize_url=data["finalize"],
            certificate_url=data.get("certificate"),
            raw=data,
        )

    async def fetch(self, url: str) -> dict[str, Any]:
        """
        POST-as-GET (RFC 8555 section 6.3).

        ACME deliberately has almost no plain GETs: fetching an order or an
        authorization is a POST with an empty payload, signed, so the server
        can tell who is asking. jws.sign_jws encodes payload=None as the empty
        string, which is what makes this a POST-as-GET rather than a POST of
        an empty object.
        """
        response = await self._post(url, payload=None)
        return response.json()

    async def http01_challenges(self, order: Order) -> list[Http01Challenge]:
        """
        Collect the pending HTTP-01 challenge for every unvalidated identifier.

        Authorizations already marked valid are skipped -- CAs cache them for
        a period, so a re-issue for the same name often needs no challenge at
        all, and re-answering one that is already valid is an error.
        """
        challenges: list[Http01Challenge] = []

        for auth_url in order.authorization_urls:
            authorization = await self.fetch(auth_url)
            if authorization["status"] == "valid":
                log.info(
                    "authorization already valid for %s, skipping challenge",
                    authorization["identifier"]["value"],
                )
                continue

            http01 = next(
                (c for c in authorization["challenges"] if c["type"] == "http-01"), None
            )
            if http01 is None:
                raise RuntimeError(
                    f"CA offered no http-01 challenge for "
                    f"{authorization['identifier']['value']}; "
                    "a wildcard name requires dns-01"
                )

            challenges.append(
                Http01Challenge(
                    authorization_url=auth_url,
                    challenge_url=http01["url"],
                    token=http01["token"],
                    key_authorization=key_authorization(http01["token"], self.account_key),
                    domain=authorization["identifier"]["value"],
                )
            )

        return challenges

    async def answer_challenge(self, challenge: Http01Challenge) -> None:
        """
        Tell the CA the token is published and it may validate.

        The empty object is required and meaningful: it is the client saying
        "go ahead". The CA then makes its own HTTP request to your domain,
        from its own network, which is why this cannot be faked locally
        without a test CA like Pebble.
        """
        await self._post(challenge.challenge_url, payload={})

    async def poll_authorization(
        self, url: str, attempts: int = 30, delay: float = 2.0
    ) -> dict[str, Any]:
        """
        Wait for validation to finish.

        Fixed interval rather than exponential backoff: validation normally
        completes in seconds, and backing off aggressively just adds latency
        to the common case. The attempt cap is the real safety net.
        """
        for _ in range(attempts):
            authorization = await self.fetch(url)
            status = authorization["status"]

            if status == "valid":
                return authorization
            if status in ("invalid", "revoked", "deactivated", "expired"):
                raise AcmeError(400, _challenge_problem(authorization))

            await asyncio.sleep(delay)

        raise TimeoutError(
            f"authorization {url} still pending after {attempts * delay:g}s"
        )

    async def finalize(self, order: Order, csr_der_bytes: bytes) -> Order:
        """Submit the CSR. base64url of DER -- not PEM, and not raw base64."""
        response = await self._post(
            order.finalize_url, payload={"csr": b64url(csr_der_bytes)}
        )
        data = response.json()
        order.status = data["status"]
        order.certificate_url = data.get("certificate")
        order.raw = data
        return order

    async def poll_order(
        self, order: Order, attempts: int = 30, delay: float = 2.0
    ) -> Order:
        """
        Wait for the CA to sign.

        The 'processing' state is the one people forget to handle. A CA is
        allowed to accept the CSR and issue asynchronously, so a client that
        only looks for 'valid' will read certificate=None and conclude the
        order failed.
        """
        for _ in range(attempts):
            data = await self.fetch(order.url)
            order.status = data["status"]
            order.certificate_url = data.get("certificate")
            order.raw = data

            if order.status == "valid" and order.certificate_url:
                return order
            if order.status == "invalid":
                raise AcmeError(400, data.get("error", {"detail": "order became invalid"}))

            await asyncio.sleep(delay)

        raise TimeoutError(f"order {order.url} still {order.status} after polling")

    async def download_certificate(self, order: Order) -> bytes:
        """
        Fetch the issued chain as PEM.

        What comes back is leaf first, then intermediates -- the order a TLS
        server must send them in. The root is not included and should not be:
        clients already have it, and shipping it wastes handshake bytes.
        """
        if not order.certificate_url:
            raise RuntimeError("order has no certificate URL yet")
        response = await self._post(order.certificate_url, payload=None)
        return response.content

    async def revoke(self, certificate_der: bytes, reason: int = 0) -> None:
        """
        Revoke a certificate. Reason codes are RFC 5280 section 5.3.1;
        1 is keyCompromise, 4 is superseded, 5 is cessationOfOperation.

        Signed with the account key here, which works when the same account
        ordered the certificate. RFC 8555 also permits signing with the
        certificate's own key, which is the path you need when the ordering
        account is gone -- not implemented.
        """
        directory = await self.directory()
        await self._post(
            directory["revokeCert"],
            payload={"certificate": b64url(certificate_der), "reason": reason},
        )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _problem(response: httpx.Response) -> dict[str, Any]:
    try:
        return response.json()
    except ValueError:
        return {"type": "about:blank", "detail": response.text[:400]}


def _challenge_problem(authorization: dict[str, Any]) -> dict[str, Any]:
    """
    Dig the real reason out of a failed authorization.

    The authorization itself just says "invalid". The useful message -- wrong
    file contents, connection refused, DNS failure -- is on the individual
    challenge object, and surfacing it is the difference between a debuggable
    failure and a support ticket.
    """
    for challenge in authorization.get("challenges", []):
        if challenge.get("error"):
            return challenge["error"]
    return {
        "type": "urn:ietf:params:acme:error:unauthorized",
        "detail": f"authorization is {authorization.get('status')}",
    }
