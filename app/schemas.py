"""
Pydantic request and response models.

These are the API's contract, kept separate from the ORM models on purpose.
Returning SQLAlchemy objects directly couples the wire format to the schema,
so a column rename becomes a breaking API change and any column added for
internal bookkeeping leaks to clients by default.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScanRequest(BaseModel):
    """Probe live hosts and record what they serve."""

    targets: list[str] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Hosts to probe, as 'example.com' or 'example.com:8443'.",
        examples=[["github.com", "expired.badssl.com", "localhost:8443"]],
    )
    timeout: float | None = Field(None, gt=0, le=60)

    @field_validator("targets")
    @classmethod
    def _strip(cls, targets: list[str]) -> list[str]:
        cleaned = [t.strip() for t in targets if t.strip()]
        if not cleaned:
            raise ValueError("no usable targets")
        return cleaned


class ImportRequest(BaseModel):
    """Add a certificate from PEM text rather than from the network."""

    pem: str = Field(..., description="PEM-encoded certificate.")
    host: str | None = None
    auto_renew: bool = False


class RiskOut(BaseModel):
    severity: str
    score: float
    action: str
    days_remaining: int
    hygiene_score: float
    compliant: bool
    reasons: list[str]


class CertificateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host: str | None
    port: int | None
    common_name: str | None
    sans: list[str]
    issuer: str | None
    issuer_organization: str | None
    serial_number: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str | None
    key_type: str
    key_bits: int | None
    is_self_signed: bool
    chain_trusted: bool | None
    tls_version: str | None
    auto_renew: bool
    managed: bool
    days_remaining: int
    risk_score: float
    severity: str
    recommended_action: str
    hygiene_score: float
    compliant: bool
    risk_reasons: list[str]
    first_seen: datetime
    last_seen: datetime

    @classmethod
    def from_model(cls, row) -> CertificateOut:
        """
        Build from an ORM row, splitting the comma-joined text columns.

        SANs and reasons are stored as delimited text because SQLite has no
        array type and a join table for a list that is always read whole
        would be ceremony without benefit. The split happens here so nothing
        outside this boundary has to know that.
        """
        data = {
            column.name: getattr(row, column.name)
            for column in row.__table__.columns
        }
        data["sans"] = row.san_list
        data["risk_reasons"] = [r for r in (row.risk_reasons or "").split("\n") if r]
        return cls(**data)


class ScanResultOut(BaseModel):
    host: str
    port: int
    reachable: bool
    error: str | None = None
    certificate: CertificateOut | None = None


class ScanResponse(BaseModel):
    scanned: int
    reachable: int
    results: list[ScanResultOut]


class RenewRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=100)
    # Null rather than "ec" so that omitting it defers to DOMAIN_KEY_TYPE. A
    # non-null default here silently overrides the setting for every caller
    # that does not name a key type, which makes the setting do nothing.
    key_type: str | None = Field(None, pattern="^(ec|rsa)$")


class RenewResponse(BaseModel):
    succeeded: bool
    domains: list[str]
    certificate_path: str | None = None
    error_type: str | None = None
    error_detail: str | None = None


class PlanItem(BaseModel):
    certificate_id: int
    common_name: str | None
    days_remaining: int
    severity: str
    action: str
    rationale: str


class PlanResponse(BaseModel):
    source: str = Field(
        ...,
        description="'rules' when produced deterministically, 'llm' when a "
        "model ordered the queue.",
    )
    generated_at: datetime
    total_candidates: int
    items: list[PlanItem]
    notes: list[str] = []


class SummaryResponse(BaseModel):
    total: int
    expired: int
    critical: int
    warning: int
    watch: int
    ok: int
    non_compliant: int
    expiring_within_30_days: int
