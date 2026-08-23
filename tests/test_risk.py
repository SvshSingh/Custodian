"""Risk engine tests. Pure functions, no fixtures needed beyond a clock."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.risk import Action, Severity, assess
from app.core.x509_utils import CertificateFacts

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def facts(days: int, **overrides) -> CertificateFacts:
    base = dict(
        common_name="api.example.com",
        sans=["api.example.com"],
        issuer="Test CA",
        issuer_organization="Test",
        serial_number="01",
        not_before=NOW - timedelta(days=1),
        not_after=NOW + timedelta(days=days),
        signature_algorithm="sha256WithRSAEncryption",
        key_type="RSA",
        key_bits=2048,
        fingerprint_sha256="ab" * 32,
        is_self_signed=False,
        is_ca=False,
        key_usage=[],
    )
    base.update(overrides)
    return CertificateFacts(**base)


@pytest.mark.parametrize(
    ("days", "severity", "action"),
    [
        (89, Severity.OK, Action.MONITOR),
        (31, Severity.OK, Action.MONITOR),
        (30, Severity.WATCH, Action.SCHEDULE_RENEWAL),
        (15, Severity.WATCH, Action.SCHEDULE_RENEWAL),
        (14, Severity.WARNING, Action.RENEW_NOW),
        (8, Severity.WARNING, Action.RENEW_NOW),
        (7, Severity.CRITICAL, Action.EMERGENCY_RENEW),
        (1, Severity.CRITICAL, Action.EMERGENCY_RENEW),
        (-1, Severity.EXPIRED, Action.REISSUE_EXPIRED),
    ],
)
def test_threshold_ladder(days, severity, action):
    result = assess(facts(days), now=NOW)

    assert result.severity is severity
    assert result.action is action


def test_score_rises_as_expiry_approaches():
    scores = [assess(facts(d), now=NOW).score for d in (89, 30, 14, 7, 1)]

    assert scores == sorted(scores), f"scores should increase monotonically: {scores}"


def test_expired_hours_ago_is_expired_not_zero_days():
    """
    Day granularity rounds a certificate that died three hours ago to 0,
    which would otherwise read as 'critical, expires today'.
    """
    result = assess(facts(0, not_after=NOW - timedelta(hours=3)), now=NOW)

    assert result.severity is Severity.EXPIRED
    assert result.action is Action.REISSUE_EXPIRED


def test_auto_renew_discounts_urgency_but_not_inside_the_critical_window():
    relaxed = assess(facts(25), now=NOW, auto_renew=True)
    strict = assess(facts(25), now=NOW, auto_renew=False)
    assert relaxed.score < strict.score

    # At 3 days, automation has demonstrably not worked. No discount.
    assert assess(facts(3), now=NOW, auto_renew=True).score == pytest.approx(
        assess(facts(3), now=NOW, auto_renew=False).score
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"key_bits": 1024},
        {"signature_algorithm": "sha1WithRSAEncryption"},
        {"sans": []},
        {"is_self_signed": True},
    ],
)
def test_hygiene_problems_make_a_certificate_non_compliant(overrides):
    result = assess(facts(60, **overrides), now=NOW)

    assert result.compliant is False
    assert result.hygiene_score > 0
    # ...but urgency is unchanged. A weak key is a ticket, not a page.
    assert result.severity is Severity.OK
    assert result.action is Action.MONITOR


def test_untrusted_chain_is_a_hygiene_finding():
    result = assess(facts(60), now=NOW, chain_trusted=False)

    assert result.compliant is False
    assert any("trust store" in reason for reason in result.reasons)


def test_self_signed_certificate_is_not_also_penalised_for_the_chain():
    """
    A self-signed certificate obviously fails chain validation. Charging it
    for both would double-count one problem.
    """
    result = assess(facts(60, is_self_signed=True), now=NOW, chain_trusted=False)

    assert not any("trust store" in reason for reason in result.reasons)


def test_healthy_certificate_is_compliant_with_no_reasons_beyond_expiry():
    result = assess(facts(89), now=NOW)

    assert result.compliant is True
    assert result.hygiene_score == 0
    assert len(result.reasons) == 1


def test_every_score_contribution_is_explained():
    result = assess(facts(3, key_bits=1024, sans=[]), now=NOW)

    assert result.score == 100.0
    assert len(result.reasons) == 3  # expiry, weak key, missing SAN
