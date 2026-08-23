"""Service-layer tests that do not need HTTP."""

from __future__ import annotations

import pytest

from app import service
from app.core.x509_utils import describe_bytes
from tests.conftest import make_certificate


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("example.com", ("example.com", 443)),
        ("example.com:8443", ("example.com", 8443)),
        ("  example.com  ", ("example.com", 443)),
        ("[2606:4700::1111]:8443", ("2606:4700::1111", 8443)),
        ("[2606:4700::1111]", ("2606:4700::1111", 443)),
        # A trailing colon with no digits is not a port.
        ("example.com:", ("example.com:", 443)),
    ],
)
def test_parse_target(target, expected):
    assert service.parse_target(target) == expected


async def test_upsert_creates_then_refreshes_in_place(db_session):
    pem = make_certificate(common_name="u.example.com", sans=["u.example.com"])
    facts = describe_bytes(pem)

    first = await service.upsert_certificate(db_session, facts, host="u.example.com", port=443)
    second = await service.upsert_certificate(db_session, facts, host="u.example.com", port=443)

    assert first.id == second.id
    assert second.severity == "ok"


async def test_upsert_does_not_erase_a_known_host_on_reimport(db_session):
    """
    Seen on the network first, imported from a file later. The file import
    has no host; it must not blank the one we discovered.
    """
    facts = describe_bytes(make_certificate(common_name="h.example.com", sans=["h.example.com"]))

    await service.upsert_certificate(db_session, facts, host="h.example.com", port=8443)
    row = await service.upsert_certificate(db_session, facts, host=None, port=None)

    assert row.host == "h.example.com"
    assert row.port == 8443


async def test_a_renewed_certificate_is_a_new_row(db_session):
    """
    Renewal produces a different certificate with a different fingerprint.
    Keeping both preserves the history of what was deployed when.
    """
    old = describe_bytes(make_certificate(common_name="r.example.com", sans=["r.example.com"], days_valid=5))
    new = describe_bytes(make_certificate(common_name="r.example.com", sans=["r.example.com"], days_valid=90))

    first = await service.upsert_certificate(db_session, old)
    second = await service.upsert_certificate(db_session, new)

    assert first.id != second.id
    assert first.fingerprint_sha256 != second.fingerprint_sha256


async def test_summary_counts_reflect_the_inventory(db_session):
    for days in (90, 20, 5, -3):
        await service.upsert_certificate(
            db_session,
            describe_bytes(make_certificate(
                common_name=f"c{days}.example.com",
                sans=[f"c{days}.example.com"],
                days_valid=abs(days) if days > 0 else 1,
                days_ago_issued=1 if days > 0 else abs(days) + 1,
            )),
        )

    counts = await service.summary(db_session)

    assert counts["total"] == 4
    assert counts["expired"] == 1
    assert counts["ok"] == 1
