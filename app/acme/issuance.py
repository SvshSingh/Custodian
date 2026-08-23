"""
The issuance flow, end to end.

client.py knows the protocol; this knows the order to do things in and what
to do when a step fails. Splitting them keeps the protocol code free of
policy, and means the retry and cleanup behaviour is readable in one place.

The sequence:

    account  ->  order  ->  challenge  ->  validate
                                             |
    certificate  <-  poll  <-  finalize  <---+

Everything in this module is deterministic. No model is consulted about
whether to issue, what to issue, or whether a failure is retryable -- those
are rules, and rules are auditable. The AI layer decides only which
certificates to put through this flow first; see app/ai/planner.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa

from app.acme.challenge import ChallengePublisher
from app.acme.client import AcmeClient, AcmeError, Http01Challenge
from app.acme.csr import build_csr, csr_der, generate_domain_key, save_certificate, save_private_key
from app.acme.jws import generate_account_key, load_account_key, save_account_key

log = logging.getLogger("certward.issuance")


@dataclass
class IssuedCertificate:
    domains: list[str]
    certificate_pem: bytes
    private_key_path: str
    certificate_path: str
    account_url: str


def load_or_create_account_key(path: str | Path) -> rsa.RSAPrivateKey:
    """
    Reuse the account key if one exists, otherwise make one.

    Reuse matters more than it looks. The account key is your identity to the
    CA, and CAs apply rate limits and cached authorizations per account, so
    generating a fresh key on every run means starting from zero each time
    and burning through registration limits.
    """
    path = Path(path)
    if path.exists():
        return load_account_key(path)

    log.info("no account key at %s, generating one", path)
    key = generate_account_key()
    save_account_key(key, path)
    return key


async def issue_certificate(
    domains: list[str],
    directory_url: str,
    account_key: rsa.RSAPrivateKey,
    publisher: ChallengePublisher,
    cert_dir: str | Path,
    contact_email: str | None = None,
    verify_tls: bool = True,
    key_type: str = "ec",
    account_url: str | None = None,
    timeout: float = 30.0,
    http: httpx.AsyncClient | None = None,
) -> IssuedCertificate:
    """
    Run one full ACME issuance and write the result to disk.

    `verify_tls=False` exists for Pebble, which serves the ACME API under its
    own untrusted test root. It must never be set against a real CA: it would
    let anyone who can intercept the connection impersonate the CA and hand
    you a certificate you would then deploy.

    Challenge cleanup runs in a finally block so a failure part-way through
    does not leave tokens published. The private key is written *before*
    finalize, because a key that exists without a certificate is recoverable
    -- you can re-order -- while a certificate whose key was lost is not.

    `http` lets a caller supply its own client. That is what makes the whole
    flow testable: the suite passes one wired to an in-process fake CA, so
    every step below is exercised for real without a network or a container.
    A caller-supplied client is not closed here, since the caller owns it.
    """
    cert_dir = Path(cert_dir)
    published_tokens: list[str] = []

    owned_client = http is None
    client_context = http or httpx.AsyncClient(verify=verify_tls, timeout=timeout)

    try:
        client = AcmeClient(directory_url, account_key, client_context, account_url=account_url)

        resolved_account = account_url or await client.register_account(contact_email)
        client.account_url = resolved_account

        order = await client.new_order(domains)
        log.info("order created for %s (%s)", ", ".join(domains), order.status)

        try:
            challenges = await client.http01_challenges(order)

            for challenge in challenges:
                await publisher.publish(challenge.token, challenge.key_authorization)
                published_tokens.append(challenge.token)

            for challenge in challenges:
                await _validate(client, challenge)

            key = generate_domain_key(key_type)
            primary = domains[0]
            key_path = cert_dir / primary / "privkey.pem"
            cert_path = cert_dir / primary / "fullchain.pem"

            save_private_key(key, key_path)

            order = await client.finalize(order, csr_der(build_csr(key, domains)))
            order = await client.poll_order(order)
            pem = await client.download_certificate(order)

            save_certificate(pem, cert_path)
            log.info("issued certificate for %s -> %s", primary, cert_path)

            return IssuedCertificate(
                domains=list(domains),
                certificate_pem=pem,
                private_key_path=str(key_path),
                certificate_path=str(cert_path),
                account_url=resolved_account,
            )

        finally:
            for token in published_tokens:
                await publisher.cleanup(token)

    finally:
        if owned_client:
            await client_context.aclose()


async def _validate(client: AcmeClient, challenge: Http01Challenge) -> None:
    """Answer one challenge and wait for the CA's verdict."""
    log.info("answering http-01 for %s", challenge.domain)
    await client.answer_challenge(challenge)
    try:
        await client.poll_authorization(challenge.authorization_url)
    except AcmeError as exc:
        raise AcmeError(
            exc.status,
            {
                "type": exc.type,
                "detail": (
                    f"validation failed for {challenge.domain}: {exc.detail}. "
                    f"Check that http://{challenge.domain}/.well-known/"
                    f"acme-challenge/{challenge.token} is reachable from the "
                    "public internet over port 80."
                ),
            },
        ) from exc
    log.info("authorization valid for %s", challenge.domain)
