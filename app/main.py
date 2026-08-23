"""
Custodian -- TLS certificate lifecycle service.

Discovers certificates by probing live hosts, keeps an inventory, assesses
expiry and hygiene risk, and renews via ACME.

Run it:  uvicorn app.main:app --reload
Docs:    http://localhost:8000/docs
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.certificates import router as certificates_router
from app.config import get_settings
from app.db import init_models

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)

log = logging.getLogger("custodian")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Startup and shutdown.

    Creating tables here rather than at import time means importing the app
    -- which every test does -- has no side effects on the filesystem.
    """
    settings = get_settings()
    await init_models()

    log.info("custodian ready | CA: %s", settings.directory_url)
    if settings.llm_disabled:
        log.info("LLM disabled; renewal planning is rule-based")
    else:
        log.info("LLM planning enabled via %s", settings.llm_provider)
    if not settings.verify_acme_tls:
        log.warning(
            "ACME TLS verification is OFF -- only valid against a local test CA"
        )

    yield

    log.info("custodian shutting down")


app = FastAPI(
    title="Custodian",
    version="0.1.0",
    summary="TLS certificate discovery, risk assessment and ACME renewal.",
    description=__doc__,
    lifespan=lifespan,
)

app.include_router(certificates_router)


@app.get("/health", tags=["meta"], summary="Liveness probe")
async def health() -> dict[str, str]:
    """
    Deliberately does not touch the database or the CA.

    A liveness probe answers "is this process running"; mixing in dependency
    checks means a slow database restarts a perfectly healthy container. What
    the dependencies are doing belongs in a separate readiness endpoint.
    """
    return {"status": "ok"}


@app.get("/config", tags=["meta"], summary="Effective configuration")
async def config() -> dict[str, object]:
    """
    Non-secret settings, for confirming what the service actually loaded.

    Only fields that are safe to expose. No API keys, no key paths -- an
    endpoint like this is a standing temptation to add "just one" useful
    secret to, and the answer is always no.
    """
    settings = get_settings()
    return {
        "ca_directory": settings.directory_url,
        "acme_tls_verification": settings.verify_acme_tls,
        "renewal_threshold_days": settings.renewal_threshold_days,
        "llm_disabled": settings.llm_disabled,
        "llm_provider": None if settings.llm_disabled else settings.llm_provider,
        "domain_key_type": settings.domain_key_type,
    }
