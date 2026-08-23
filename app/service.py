"""
The application service layer.

Sits between the HTTP routes and everything underneath. Routes stay thin --
parse, delegate, serialise -- and the interesting logic (probe, assess,
upsert, renew, record) lives here where it can be tested without spinning up
an ASGI app.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.acme.challenge import WebrootPublisher
from app.acme.client import AcmeError
from app.acme.issuance import issue_certificate, load_or_create_account_key
from app.config import Settings
from app.core import tls_probe
from app.core.risk import assess
from app.core.x509_utils import CertificateFacts, describe_bytes
from app.models import Certificate, RenewalAttempt

log = logging.getLogger("certward.service")

DEFAULT_PORT = 443


def parse_target(target: str) -> tuple[str, int]:
    """
    Split 'host' or 'host:port' into its parts.

    rsplit on the last colon so an IPv6 literal in brackets survives; a bare
    IPv6 address without brackets is genuinely ambiguous and is treated as a
    hostname, which will simply fail to resolve rather than silently probing
    the wrong port.
    """
    target = target.strip()
    if target.startswith("[") and "]" in target:
        host, _, rest = target.partition("]")
        host = host[1:]
        port = int(rest.lstrip(":")) if rest.lstrip(":") else DEFAULT_PORT
        return host, port

    if ":" in target:
        host, _, port_text = target.rpartition(":")
        if port_text.isdigit():
            return host, int(port_text)

    return target, DEFAULT_PORT


async def upsert_certificate(
    session: AsyncSession,
    facts: CertificateFacts,
    host: str | None = None,
    port: int | None = None,
    chain_trusted: bool | None = None,
    tls_version: str | None = None,
    auto_renew: bool | None = None,
    managed: bool | None = None,
) -> Certificate:
    """
    Insert or refresh one certificate, keyed on its fingerprint.

    Renewal produces a *different* certificate with a different fingerprint,
    so it lands as a new row rather than overwriting the old one. That is
    intentional: the history of what was deployed when is worth keeping, and
    an inventory that mutates rows in place cannot answer "what were we
    serving last Tuesday".
    """
    existing = await session.scalar(
        select(Certificate).where(Certificate.fingerprint_sha256 == facts.fingerprint_sha256)
    )

    assessment = assess(
        facts,
        chain_trusted=chain_trusted,
        auto_renew=bool(auto_renew if auto_renew is not None else (existing.auto_renew if existing else False)),
    )

    values = {
        "host": host,
        "port": port,
        "common_name": facts.common_name,
        "sans": ",".join(facts.sans),
        "issuer": facts.issuer,
        "issuer_organization": facts.issuer_organization,
        "serial_number": facts.serial_number,
        "fingerprint_sha256": facts.fingerprint_sha256,
        "not_before": facts.not_before,
        "not_after": facts.not_after,
        "signature_algorithm": facts.signature_algorithm,
        "key_type": facts.key_type,
        "key_bits": facts.key_bits,
        "is_self_signed": facts.is_self_signed,
        "is_ca": facts.is_ca,
        "chain_trusted": chain_trusted,
        "tls_version": tls_version,
        "days_remaining": assessment.days_remaining,
        "risk_score": assessment.score,
        "severity": assessment.severity.value,
        "recommended_action": assessment.action.value,
        "hygiene_score": assessment.hygiene_score,
        "compliant": assessment.compliant,
        "risk_reasons": "\n".join(assessment.reasons),
        "last_seen": datetime.now(UTC),
    }

    if existing is None:
        certificate = Certificate(**values)
        certificate.auto_renew = bool(auto_renew)
        certificate.managed = bool(managed)
        session.add(certificate)
        await session.flush()
        return certificate

    for key, value in values.items():
        # Never overwrite a recorded host with None: a certificate first seen
        # on the network and later re-imported from a file should keep the
        # place we found it.
        if value is None and key in ("host", "port", "chain_trusted", "tls_version"):
            continue
        setattr(existing, key, value)

    if auto_renew is not None:
        existing.auto_renew = auto_renew
    if managed is not None:
        existing.managed = managed

    await session.flush()
    return existing


async def scan_targets(
    session: AsyncSession, targets: list[str], settings: Settings, timeout: float | None = None
) -> list[tuple[str, int, tls_probe.ProbeResult, Certificate | None]]:
    """Probe every target concurrently and fold the results into the inventory."""
    parsed = [parse_target(t) for t in targets]
    results = await tls_probe.probe_many(
        parsed,
        timeout=timeout or settings.scan_timeout_seconds,
        concurrency=settings.scan_concurrency,
    )

    folded: list[tuple[str, int, tls_probe.ProbeResult, Certificate | None]] = []
    for (host, port), result in zip(parsed, results, strict=True):
        certificate = None
        if result.reachable and result.certificate_der:
            try:
                certificate = await upsert_certificate(
                    session,
                    describe_bytes(result.certificate_der),
                    host=host,
                    port=port,
                    chain_trusted=result.chain_trusted,
                    tls_version=result.tls_version,
                )
            except ValueError as exc:
                # A server can serve bytes that are not a parseable
                # certificate. That is a finding about the host, not a crash.
                result.error = f"unparseable certificate: {exc}"
                result.reachable = False
        folded.append((host, port, result, certificate))

    return folded


async def renew(
    session: AsyncSession,
    domains: list[str],
    settings: Settings,
    key_type: str | None = None,
) -> RenewalAttempt:
    """
    Run a real ACME issuance and record the attempt either way.

    The attempt row is written on both paths. A renewal system that only logs
    successes cannot tell you it has been failing for three weeks, which is
    the exact situation that produces an expiry incident.
    """
    attempt = RenewalAttempt(domains=",".join(domains), started_at=datetime.now(UTC))
    session.add(attempt)
    await session.flush()

    try:
        issued = await issue_certificate(
            domains=domains,
            directory_url=settings.directory_url,
            account_key=load_or_create_account_key(settings.account_key_path),
            publisher=WebrootPublisher(settings.webroot_path),
            cert_dir=settings.cert_dir,
            contact_email=settings.acme_contact_email,
            verify_tls=settings.verify_acme_tls,
            key_type=key_type or settings.domain_key_type,
        )
    except AcmeError as exc:
        attempt.succeeded = False
        attempt.error_type = exc.type
        attempt.error_detail = exc.detail
        attempt.finished_at = datetime.now(UTC)
        log.warning("renewal failed for %s: %s", domains, exc)
        return attempt
    except Exception as exc:  # noqa: BLE001 -- the attempt record must survive
        attempt.succeeded = False
        attempt.error_type = type(exc).__name__
        attempt.error_detail = str(exc)[:1000]
        attempt.finished_at = datetime.now(UTC)
        log.exception("renewal raised for %s", domains)
        return attempt

    certificate = await upsert_certificate(
        session,
        describe_bytes(issued.certificate_pem),
        managed=True,
        auto_renew=True,
    )

    attempt.succeeded = True
    attempt.certificate_id = certificate.id
    attempt.certificate_path = issued.certificate_path
    attempt.finished_at = datetime.now(UTC)
    return attempt


async def summary(session: AsyncSession) -> dict[str, int]:
    """Counts by severity, computed in the database rather than in Python."""
    rows = await session.execute(
        select(Certificate.severity, func.count()).group_by(Certificate.severity)
    )
    by_severity = dict(rows.all())

    total = sum(by_severity.values())
    non_compliant = await session.scalar(
        select(func.count()).select_from(Certificate).where(Certificate.compliant.is_(False))
    )
    expiring = await session.scalar(
        select(func.count())
        .select_from(Certificate)
        .where(Certificate.days_remaining <= 30, Certificate.days_remaining >= 0)
    )

    return {
        "total": total,
        "expired": by_severity.get("expired", 0),
        "critical": by_severity.get("critical", 0),
        "warning": by_severity.get("warning", 0),
        "watch": by_severity.get("watch", 0),
        "ok": by_severity.get("ok", 0),
        "non_compliant": non_compliant or 0,
        "expiring_within_30_days": expiring or 0,
    }
