"""
API tests, driven through the real ASGI app with an overridden database
dependency.

httpx's ASGITransport talks to the app in-process, so these exercise routing,
validation, dependency injection and serialisation without binding a port.
"""

from __future__ import annotations

import httpx
import pytest_asyncio

from app.db import get_db
from app.main import app
from tests.conftest import make_certificate


@pytest_asyncio.fixture
async def client(db_session):
    """
    An HTTP client wired to the app, with the DB dependency pointed at the
    per-test SQLite file. Overrides are cleared afterwards so tests cannot
    leak state into each other through the app object, which is module-level.
    """
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http
    app.dependency_overrides.clear()


async def test_health_does_not_touch_dependencies(client):
    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_config_exposes_no_secrets(client):
    body = (await client.get("/config")).json()

    assert "ca_directory" in body
    for forbidden in ("api_key", "anthropic", "openai", "account_key_path", "password"):
        assert not any(forbidden in key.lower() for key in body)


async def test_import_stores_and_assesses_a_certificate(client):
    pem = make_certificate(common_name="imported.example.com", sans=["imported.example.com"], days_valid=10)

    response = await client.post("/certificates/import", json={"pem": pem.decode()})

    assert response.status_code == 201
    body = response.json()
    assert body["common_name"] == "imported.example.com"
    assert body["severity"] == "warning"       # ~9 days remaining
    assert body["recommended_action"] == "renew_now"
    assert body["risk_reasons"], "assessment must explain itself"


async def test_import_rejects_junk_with_422_not_500(client):
    response = await client.post("/certificates/import", json={"pem": "not a certificate"})

    assert response.status_code == 422


async def test_reimporting_the_same_certificate_does_not_duplicate_it(client):
    pem = make_certificate(common_name="same.example.com", sans=["same.example.com"]).decode()

    first = await client.post("/certificates/import", json={"pem": pem})
    second = await client.post("/certificates/import", json={"pem": pem})

    assert first.json()["id"] == second.json()["id"]
    assert len((await client.get("/certificates")).json()) == 1


async def test_listing_is_ordered_by_soonest_expiry(client):
    for days in (90, 5, 40):
        await client.post(
            "/certificates/import",
            json={"pem": make_certificate(
                common_name=f"d{days}.example.com", sans=[f"d{days}.example.com"], days_valid=days
            ).decode()},
        )

    rows = (await client.get("/certificates")).json()

    assert [r["days_remaining"] for r in rows] == sorted(r["days_remaining"] for r in rows)


async def test_filters_by_severity_and_window(client):
    for days in (90, 5):
        await client.post(
            "/certificates/import",
            json={"pem": make_certificate(
                common_name=f"f{days}.example.com", sans=[f"f{days}.example.com"], days_valid=days
            ).decode()},
        )

    critical = (await client.get("/certificates", params={"severity": "critical"})).json()
    soon = (await client.get("/certificates", params={"expiring_within": 30})).json()

    assert len(critical) == 1
    assert len(soon) == 1


async def test_summary_counts_by_severity(client):
    for days in (90, 20, 5):
        await client.post(
            "/certificates/import",
            json={"pem": make_certificate(
                common_name=f"s{days}.example.com", sans=[f"s{days}.example.com"], days_valid=days
            ).decode()},
        )

    body = (await client.get("/certificates/summary")).json()

    assert body["total"] == 3
    assert body["critical"] == 1
    assert body["watch"] == 1
    assert body["expiring_within_30_days"] == 2


async def test_plan_is_rule_sourced_by_default(client):
    await client.post(
        "/certificates/import",
        json={"pem": make_certificate(
            common_name="p.example.com", sans=["p.example.com"], days_valid=5
        ).decode()},
    )

    body = (await client.get("/certificates/plan")).json()

    assert body["source"] == "rules"
    assert body["total_candidates"] == 1
    assert body["items"][0]["rationale"]


async def test_unknown_certificate_is_404(client):
    assert (await client.get("/certificates/9999")).status_code == 404


async def test_named_routes_are_not_swallowed_by_the_id_route(client):
    """
    /certificates/summary and /certificates/plan must be declared before
    /certificates/{id}, or FastAPI matches the id route first and returns a
    422 trying to parse "summary" as an int.
    """
    for path in ("/certificates/summary", "/certificates/plan"):
        assert (await client.get(path)).status_code == 200


async def test_scan_reports_unreachable_hosts_without_failing(client):
    """One dead host must not discard the rest of the scan."""
    response = await client.post(
        "/certificates/scan",
        json={"targets": ["127.0.0.1:1", "127.0.0.1:2"], "timeout": 2},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["scanned"] == 2
    assert body["reachable"] == 0
    assert all(result["error"] for result in body["results"])


async def test_scan_rejects_an_empty_target_list(client):
    assert (await client.post("/certificates/scan", json={"targets": []})).status_code == 422
