"""
Live TLS probe -- open a real connection and read the certificate the server
actually serves.

This is the discovery half of certificate lifecycle management. An inventory
built only from what people remembered to register is an inventory of the
certificates that will not page you at 3am; the ones that will are the ones
nobody wrote down. So we go and look.

Design note on verification, because it is deliberately unusual:
we connect twice.

  Pass 1 runs with verification *disabled*. That is not laziness -- a
  monitoring tool whose whole job is finding broken certificates cannot
  refuse to look at broken certificates. An expired or self-signed cert
  would abort a verifying handshake before we could read it, which is
  precisely the case we most need to report on.

  Pass 2 runs with verification *enabled*, and we record only whether it
  succeeded and why not. That gives the inventory an honest
  `chain_trusted` field instead of us guessing from the parsed fields.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass

DEFAULT_TIMEOUT = 8.0


@dataclass
class ProbeResult:
    host: str
    port: int
    reachable: bool
    certificate_der: bytes | None = None
    tls_version: str | None = None
    cipher: str | None = None
    chain_trusted: bool = False
    chain_error: str | None = None
    error: str | None = None


def _permissive_context() -> ssl.SSLContext:
    """A context that completes a handshake with anything, so we can look."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _connect(
    host: str, port: int, context: ssl.SSLContext, timeout: float
) -> tuple[bytes | None, str | None, str | None]:
    """One handshake. Returns (peer cert DER, tls version, cipher name)."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=context, server_hostname=host),
        timeout=timeout,
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        version = ssl_object.version() if ssl_object else None
        cipher_info = ssl_object.cipher() if ssl_object else None
        return der, version, cipher_info[0] if cipher_info else None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ssl.SSLError, OSError):
            # Servers frequently drop the connection rather than completing a
            # clean TLS shutdown. We already have the certificate; a noisy
            # close is not a probe failure.
            pass


async def probe(
    host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT
) -> ProbeResult:
    """
    Fetch the certificate served by host:port, and report chain trust.

    `server_hostname` is passed on both passes so SNI is sent. Without it a
    host serving several sites returns its default certificate and the whole
    inventory quietly records the wrong one.
    """
    result = ProbeResult(host=host, port=port, reachable=False)

    try:
        der, version, cipher = await _connect(host, port, _permissive_context(), timeout)
    except TimeoutError:
        result.error = f"timed out after {timeout:g}s"
        return result
    except (OSError, ssl.SSLError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    result.reachable = True
    result.certificate_der = der
    result.tls_version = version
    result.cipher = cipher

    # Pass 2: does this chain actually validate against the system trust store?
    try:
        await _connect(host, port, ssl.create_default_context(), timeout)
        result.chain_trusted = True
    except ssl.SSLCertVerificationError as exc:
        result.chain_error = exc.verify_message or str(exc)
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        result.chain_error = f"{type(exc).__name__}: {exc}"

    return result


async def probe_many(
    targets: list[tuple[str, int]],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = 20,
) -> list[ProbeResult]:
    """
    Probe many hosts concurrently.

    This is the case that justifies async in this project: the work is almost
    entirely waiting on the network, so a semaphore-bounded gather scans a
    few hundred hosts in the time a sequential loop would take for a dozen.
    The bound matters -- unbounded gather over a large inventory will exhaust
    file descriptors and look like a network fault.
    """
    limit = asyncio.Semaphore(concurrency)

    async def one(host: str, port: int) -> ProbeResult:
        async with limit:
            return await probe(host, port, timeout)

    return await asyncio.gather(*(one(h, p) for h, p in targets))
