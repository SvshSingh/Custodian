"""
Certificate risk assessment.

Deterministic, explainable, and entirely separate from the AI layer. Given
the facts read off a certificate this produces a severity, a 0-100 score, a
recommended action, and -- importantly -- the list of reasons that produced
them.

The reasons list is the point. A number on its own ("risk: 73") tells an
operator nothing they can act on, and a score they cannot interrogate is a
score they will learn to ignore. Every contribution to the score appends the
sentence that justifies it, so the output can always be read back as an
argument rather than an oracle.

Nothing in this module calls a model. When the AI layer is switched off with
LLM_DISABLED, this is what still runs, and the alerting behaviour is
identical -- which is what makes the LLM genuinely optional rather than
load-bearing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from app.core.x509_utils import CertificateFacts, days_until_expiry


class Severity(StrEnum):
    OK = "ok"
    WATCH = "watch"
    WARNING = "warning"
    CRITICAL = "critical"
    EXPIRED = "expired"


class Action(StrEnum):
    MONITOR = "monitor"
    SCHEDULE_RENEWAL = "schedule_renewal"
    RENEW_NOW = "renew_now"
    EMERGENCY_RENEW = "emergency_renew"
    REISSUE_EXPIRED = "reissue_expired"


# Thresholds in days. The 30/14/7 shape is the industry-standard alerting
# ladder and it maps onto a 90-day certificate sensibly: renewal is expected
# at 30 days, so anything inside 14 means automation has already failed once.
WATCH_DAYS = 30
WARNING_DAYS = 14
CRITICAL_DAYS = 7

# Below this an RSA key is considered too weak to keep in service. 2048 is
# the current CA/Browser Forum floor for RSA.
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256

WEAK_SIGNATURE_ALGORITHMS = ("md5", "sha1")


@dataclass
class RiskAssessment:
    """
    Two dimensions, deliberately kept apart.

    `severity` and `action` describe *expiry urgency* -- how soon this breaks
    and what to do about it today. `hygiene_score` and `compliant` describe
    whether the certificate meets policy at all.

    They are separate because they drive different work. A 1024-bit key that
    is valid for another 60 days is a compliance ticket for the next issuance,
    not a page; a compliant certificate expiring in three days is a page, not
    a ticket. Tools that collapse both into one number end up either paging
    people about key sizes or hiding an imminent outage behind a mid-range
    score. `score` is the combined figure for ranking a queue -- useful for
    sorting, never for deciding.
    """

    severity: Severity
    score: float
    action: Action
    days_remaining: int
    hygiene_score: float = 0.0
    compliant: bool = True
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "score": self.score,
            "action": self.action.value,
            "days_remaining": self.days_remaining,
            "hygiene_score": self.hygiene_score,
            "compliant": self.compliant,
            "reasons": list(self.reasons),
        }


def _expiry_component(days: int, reasons: list[str]) -> tuple[float, Severity, Action]:
    """
    Expiry is the dominant term, and it is deliberately not linear.

    The difference between 90 and 60 days remaining barely matters -- both are
    fine, automation has ample room. The difference between 10 and 3 days is
    the difference between a ticket and an outage. So the curve is flat out
    at the long end and climbs steeply near zero.
    """
    if days < 0:
        reasons.append(f"Certificate expired {abs(days)} day(s) ago.")
        return 100.0, Severity.EXPIRED, Action.REISSUE_EXPIRED

    if days <= CRITICAL_DAYS:
        reasons.append(
            f"Expires in {days} day(s) -- inside the {CRITICAL_DAYS}-day "
            "emergency window; renewal should already have happened."
        )
        return 85.0 + (CRITICAL_DAYS - days) * 2.0, Severity.CRITICAL, Action.EMERGENCY_RENEW

    if days <= WARNING_DAYS:
        reasons.append(
            f"Expires in {days} day(s) -- past the {WARNING_DAYS}-day warning "
            "threshold, so automated renewal has not succeeded yet."
        )
        return 60.0 + (WARNING_DAYS - days) * 3.0, Severity.WARNING, Action.RENEW_NOW

    if days <= WATCH_DAYS:
        reasons.append(
            f"Expires in {days} day(s) -- within the {WATCH_DAYS}-day renewal "
            "window where ACME clients normally act."
        )
        return 30.0 + (WATCH_DAYS - days) * 1.5, Severity.WATCH, Action.SCHEDULE_RENEWAL

    reasons.append(f"Expires in {days} day(s) -- outside all alert thresholds.")
    return max(0.0, 30.0 - (days - WATCH_DAYS) * 0.3), Severity.OK, Action.MONITOR


def _hygiene_penalties(
    facts: CertificateFacts,
    chain_trusted: bool | None,
    reasons: list[str],
) -> float:
    """
    Everything that is wrong with a certificate other than its expiry date.

    These add to the score but never set the action -- a weak key is a
    problem you fix at the next issuance, not a reason to renew at 2am.
    """
    penalty = 0.0

    if facts.key_type == "RSA" and facts.key_bits and facts.key_bits < MIN_RSA_BITS:
        penalty += 25.0
        reasons.append(
            f"RSA key is {facts.key_bits} bits, below the {MIN_RSA_BITS}-bit minimum."
        )

    if facts.key_type.startswith("EC") and facts.key_bits and facts.key_bits < MIN_EC_BITS:
        penalty += 25.0
        reasons.append(
            f"EC key is {facts.key_bits} bits, below the {MIN_EC_BITS}-bit minimum."
        )

    algorithm = (facts.signature_algorithm or "").lower()
    if any(weak in algorithm for weak in WEAK_SIGNATURE_ALGORITHMS):
        penalty += 30.0
        reasons.append(
            f"Signed with {facts.signature_algorithm}, which is no longer "
            "collision-resistant and is rejected by modern clients."
        )

    if facts.is_self_signed and not facts.is_ca:
        penalty += 15.0
        reasons.append(
            "Self-signed leaf certificate -- no CA vouches for this identity."
        )

    if not facts.sans:
        penalty += 20.0
        reasons.append(
            "No subjectAltName extension. Hostname verification uses SAN, not "
            "CN, so browsers will reject this regardless of expiry."
        )

    if chain_trusted is False and not facts.is_self_signed:
        penalty += 20.0
        reasons.append(
            "Chain did not validate against the system trust store -- likely "
            "a missing or misordered intermediate."
        )

    return penalty


def assess(
    facts: CertificateFacts,
    now: datetime | None = None,
    chain_trusted: bool | None = None,
    auto_renew: bool = False,
) -> RiskAssessment:
    """
    Score one certificate.

    `auto_renew` discounts the expiry term but deliberately cannot rescue a
    certificate inside the critical window: if automation were working, it
    would already have renewed, so trusting it at day five is exactly the
    assumption that produces outages.
    """
    now = now or datetime.now(UTC)
    reasons: list[str] = []

    days = days_until_expiry(facts.not_after, now)
    # Day-granularity rounds a cert that expired hours ago to 0, so settle
    # the expired question against the real timestamp, not the day count.
    not_after = facts.not_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    if not_after <= now and days >= 0:
        days = -1 if days == 0 else days

    expiry_score, severity, action = _expiry_component(days, reasons)

    if auto_renew and severity in (Severity.OK, Severity.WATCH):
        expiry_score *= 0.7
        reasons.append("Auto-renew is enabled, reducing expiry urgency.")

    hygiene = _hygiene_penalties(facts, chain_trusted, reasons)
    score = min(100.0, expiry_score + hygiene)

    return RiskAssessment(
        severity=severity,
        score=round(score, 1),
        action=action,
        days_remaining=days,
        hygiene_score=round(min(100.0, hygiene), 1),
        compliant=hygiene == 0.0,
        reasons=reasons,
    )
