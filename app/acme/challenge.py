"""
HTTP-01 challenge publishing.

To satisfy an HTTP-01 challenge the key authorization must be served at

    http://<domain>/.well-known/acme-challenge/<token>

over plain HTTP on port 80, and the CA fetches it from its own network. Two
ways to arrange that, and the choice is usually made for you by whether
something is already listening on port 80.

  Webroot -- you already run a web server. Drop the file into its document
  root and let it serve it. No privileges needed, nothing to coordinate.
  This is the right default.

  Standalone -- nothing is listening, so we listen. Needs port 80, which on
  Linux means root or CAP_NET_BIND_SERVICE for ports below 1024, and it will
  collide with any existing server.

Note the challenge is plain HTTP, not HTTPS, deliberately: you are asking for
a certificate, so requiring a working one first would be circular. Redirects
to HTTPS are followed by the CA, so an http->https redirect does not break
validation.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Protocol

log = logging.getLogger("certward.challenge")

WELL_KNOWN = ".well-known/acme-challenge"


class ChallengePublisher(Protocol):
    """
    What the issuance flow needs from any challenge mechanism.

    Kept as a Protocol so a DNS-01 publisher can be added later without the
    issuance code knowing the difference -- it only ever publishes a value
    and cleans it up.
    """

    async def publish(self, token: str, key_authorization: str) -> None: ...

    async def cleanup(self, token: str) -> None: ...


class WebrootPublisher:
    """Write the token file into an existing web server's document root."""

    def __init__(self, webroot: str | Path):
        self.webroot = Path(webroot)

    def _path(self, token: str) -> Path:
        return self.webroot / WELL_KNOWN / token

    async def publish(self, token: str, key_authorization: str) -> None:
        path = self._path(token)
        path.parent.mkdir(parents=True, exist_ok=True)
        # No trailing newline. Some CAs tolerate one, some do not; the spec
        # says the body is the key authorization, so send exactly that.
        path.write_text(key_authorization, encoding="ascii")
        log.info("published challenge at %s", path)

    async def cleanup(self, token: str) -> None:
        """
        Best-effort removal.

        A leftover challenge file is not a security problem -- the key
        authorization is useless without the account private key -- so a
        failure to clean up must never fail the issuance that just succeeded.
        """
        try:
            self._path(token).unlink(missing_ok=True)
        except OSError as exc:
            log.warning("could not remove challenge file for %s: %s", token, exc)


class StandaloneServer:
    """
    A minimal HTTP server that answers only ACME challenges.

    Hand-written rather than pulled from a framework because it needs to do
    exactly one thing and the whole request handler is fifteen lines. It
    speaks just enough HTTP/1.1 to satisfy a CA validator: parse the request
    line, match the path, respond, close.
    """

    # Binds every interface by design: the CA validator connects from the
    # public internet, so listening only on loopback would fail every
    # challenge. Narrow it by passing an explicit host if the deployment
    # fronts this with a proxy.
    def __init__(self, host: str = "0.0.0.0", port: int = 80):  # noqa: S104
        self.host = host
        self.port = port
        self._tokens: dict[str, str] = {}
        self._server: asyncio.AbstractServer | None = None

    async def publish(self, token: str, key_authorization: str) -> None:
        self._tokens[token] = key_authorization

    async def cleanup(self, token: str) -> None:
        self._tokens.pop(token, None)

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            parts = request_line.decode("latin-1").split()
            path = parts[1] if len(parts) >= 2 else ""

            token = path.rsplit("/", 1)[-1]
            body = self._tokens.get(token) if f"/{WELL_KNOWN}/" in path else None

            if body is None:
                response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            else:
                payload = body.encode("ascii")
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/octet-stream\r\n"
                    b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + payload
                )

            writer.write(response)
            await writer.drain()
        except (TimeoutError, OSError, UnicodeDecodeError, IndexError):
            pass
        finally:
            writer.close()

    async def __aenter__(self) -> StandaloneServer:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        log.info("challenge server listening on %s:%s", self.host, self.port)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
