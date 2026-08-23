"""
Certificate inventory and lifecycle routes.

Routes are deliberately thin. Everything with logic in it lives in
app/service.py, which keeps these readable and means the behaviour can be
tested without an HTTP client.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import service
from app.ai.planner import plan_renewals
from app.config import Settings, get_settings
from app.core.x509_utils import describe_bytes
from app.db import get_db
from app.models import Certificate
from app.schemas import (
    CertificateOut,
    ImportRequest,
    PlanItem,
    PlanResponse,
    RenewRequest,
    RenewResponse,
    ScanRequest,
    ScanResponse,
    ScanResultOut,
    SummaryResponse,
)

router = APIRouter(prefix="/certificates", tags=["certificates"])

# FastAPI resolves these once per request and caches within it. Declaring
# them as named aliases keeps the signatures below readable.
Db = Annotated[AsyncSession, Depends(get_db)]
Config = Annotated[Settings, Depends(get_settings)]


@router.get("", response_model=list[CertificateOut], summary="List the inventory")
async def list_certificates(
    db: Db,
    severity: str | None = Query(None, description="Filter by severity."),
    expiring_within: int | None = Query(
        None, ge=0, le=3650, description="Only certificates expiring within N days."
    ),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[CertificateOut]:
    """
    Ordered by soonest expiry, because that is what anyone opening this wants
    first. Pagination is capped so one request cannot pull an entire fleet.
    """
    query = select(Certificate).order_by(Certificate.days_remaining.asc())

    if severity:
        query = query.where(Certificate.severity == severity)
    if expiring_within is not None:
        query = query.where(Certificate.days_remaining <= expiring_within)

    rows = await db.scalars(query.limit(limit).offset(offset))
    return [CertificateOut.from_model(row) for row in rows]


@router.get("/summary", response_model=SummaryResponse, summary="Counts by severity")
async def get_summary(db: Db) -> SummaryResponse:
    return SummaryResponse(**await service.summary(db))


@router.get("/plan", response_model=PlanResponse, summary="What to renew, in order")
async def get_plan(db: Db, settings: Config) -> PlanResponse:
    """
    The renewal queue.

    `source` in the response says how it was ordered: "rules" for the
    deterministic path, "llm" when a model ranked it. Always check that field
    rather than assuming -- the service silently falls back to rules whenever
    the model is unavailable, and the whole point is that both are valid.
    """
    rows = list(await db.scalars(select(Certificate)))
    plan = plan_renewals(rows, settings)

    return PlanResponse(
        source=plan.source,
        generated_at=plan.generated_at,
        total_candidates=plan.total_candidates,
        items=[PlanItem(**vars(item)) for item in plan.items],
        notes=plan.notes,
    )


@router.get("/{certificate_id}", response_model=CertificateOut)
async def get_certificate(certificate_id: int, db: Db) -> CertificateOut:
    row = await db.get(Certificate, certificate_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "certificate not found")
    return CertificateOut.from_model(row)


@router.post("/scan", response_model=ScanResponse, summary="Probe live hosts")
async def scan(request: ScanRequest, db: Db, settings: Config) -> ScanResponse:
    """
    Open a real TLS connection to each target and record what it serves.

    Unreachable hosts are reported, not raised. A scan of two hundred hosts
    where three are down is a successful scan with three findings, and a 500
    would throw away the other hundred and ninety-seven results.
    """
    folded = await service.scan_targets(db, request.targets, settings, request.timeout)

    results = [
        ScanResultOut(
            host=host,
            port=port,
            reachable=probe.reachable,
            error=probe.error,
            certificate=CertificateOut.from_model(certificate) if certificate else None,
        )
        for host, port, probe, certificate in folded
    ]

    return ScanResponse(
        scanned=len(results),
        reachable=sum(1 for r in results if r.reachable),
        results=results,
    )


@router.post(
    "/import",
    response_model=CertificateOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a certificate from PEM",
)
async def import_certificate(request: ImportRequest, db: Db) -> CertificateOut:
    try:
        facts = describe_bytes(request.pem.encode())
    except ValueError as exc:
        # Literal 422 rather than the named constant: Starlette renamed
        # HTTP_422_UNPROCESSABLE_ENTITY to HTTP_422_UNPROCESSABLE_CONTENT, so
        # either name breaks on half the supported version range.
        raise HTTPException(422, f"could not parse certificate: {exc}") from exc

    row = await service.upsert_certificate(
        db, facts, host=request.host, auto_renew=request.auto_renew
    )
    return CertificateOut.from_model(row)


@router.post("/renew", response_model=RenewResponse, summary="Issue via ACME")
async def renew_certificate(
    request: RenewRequest, db: Db, settings: Config
) -> RenewResponse:
    """
    Run a full ACME issuance for the given domains.

    Returns 200 with `succeeded: false` on a CA rejection rather than a 5xx.
    The request was handled correctly; the CA declined, and the error type and
    detail in the body are what the caller needs to act on. A 500 here would
    imply custodian malfunctioned, which is a different and misleading thing
    to page someone about.

    This runs the issuance inline, which can take tens of seconds. A
    production deployment would hand it to a worker and return a job id --
    see the README.
    """
    attempt = await service.renew(db, request.domains, settings, request.key_type)

    return RenewResponse(
        succeeded=attempt.succeeded,
        domains=request.domains,
        certificate_path=attempt.certificate_path,
        error_type=attempt.error_type,
        error_detail=attempt.error_detail,
    )
