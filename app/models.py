"""
Database models.

Two tables. `certificates` is the inventory -- one row per distinct
certificate, keyed by fingerprint. `renewal_attempts` is the audit trail --
one row per issuance attempt, successful or not.

The audit table exists because "did we try, and what happened" is the first
question asked after an expiry incident, and an inventory that only holds
current state cannot answer it. It is append-only by convention: rows are
never updated, only inserted.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Certificate(Base):
    __tablename__ = "certificates"
    __table_args__ = (
        # The fingerprint is the natural key: the same certificate served by
        # three load balancers is one certificate, and deduping on hostname
        # instead would either lose that or create phantom rows on rotation.
        UniqueConstraint("fingerprint_sha256", name="uq_certificate_fingerprint"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Where we found it. Null for certificates imported from a file.
    host: Mapped[str | None] = mapped_column(String(253), index=True)
    port: Mapped[int | None] = mapped_column(Integer)

    common_name: Mapped[str | None] = mapped_column(String(253), index=True)
    sans: Mapped[str] = mapped_column(Text, default="")
    issuer: Mapped[str | None] = mapped_column(String(253))
    issuer_organization: Mapped[str | None] = mapped_column(String(253))
    serial_number: Mapped[str] = mapped_column(String(64))
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), index=True)

    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    signature_algorithm: Mapped[str | None] = mapped_column(String(64))
    key_type: Mapped[str] = mapped_column(String(32))
    key_bits: Mapped[int | None] = mapped_column(Integer)

    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_ca: Mapped[bool] = mapped_column(Boolean, default=False)
    chain_trusted: Mapped[bool | None] = mapped_column(Boolean)
    tls_version: Mapped[str | None] = mapped_column(String(16))

    auto_renew: Mapped[bool] = mapped_column(Boolean, default=False)
    managed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Denormalised assessment, refreshed on every scan. Stored rather than
    # computed on read so the inventory can be sorted and filtered by risk in
    # the database instead of in Python.
    days_remaining: Mapped[int] = mapped_column(Integer, default=0, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="ok", index=True)
    recommended_action: Mapped[str] = mapped_column(String(32), default="monitor")
    hygiene_score: Mapped[float] = mapped_column(Float, default=0.0)
    compliant: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_reasons: Mapped[str] = mapped_column(Text, default="")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    attempts: Mapped[list[RenewalAttempt]] = relationship(
        back_populates="certificate", cascade="all, delete-orphan"
    )

    @property
    def san_list(self) -> list[str]:
        return [s for s in self.sans.split(",") if s]


class RenewalAttempt(Base):
    """One issuance attempt. Append-only: never updated, only inserted."""

    __tablename__ = "renewal_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    certificate_id: Mapped[int | None] = mapped_column(
        ForeignKey("certificates.id", ondelete="CASCADE"), index=True
    )

    domains: Mapped[str] = mapped_column(Text)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=False)

    # The ACME error type, e.g. urn:ietf:params:acme:error:unauthorized.
    # Stored separately from the message so failures can be grouped and
    # counted without parsing prose.
    error_type: Mapped[str | None] = mapped_column(String(128))
    error_detail: Mapped[str | None] = mapped_column(Text)

    certificate_path: Mapped[str | None] = mapped_column(String(512))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    certificate: Mapped[Certificate | None] = relationship(back_populates="attempts")
