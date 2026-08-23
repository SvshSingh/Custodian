"""
Configuration, read from the environment.

pydantic-settings gives type coercion and validation at startup rather than
an AttributeError three hours into a run. Everything has a default that
works locally, so `uvicorn app.main:app` runs with no .env at all -- but
nothing that touches a real CA defaults to anything dangerous.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Pebble is Let's Encrypt's test CA. It is the default because it makes the
# safe path the easy path: a misconfigured run hits a local test server
# rather than burning Let's Encrypt rate limits with a broken client.
PEBBLE_DIRECTORY = "https://localhost:14000/dir"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"

CA_DIRECTORIES = {
    "pebble": PEBBLE_DIRECTORY,
    "letsencrypt_staging": LETSENCRYPT_STAGING,
    "letsencrypt": LETSENCRYPT_PRODUCTION,
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "certward"
    debug: bool = False

    database_url: str = "sqlite+aiosqlite:///./certward.db"

    # -- ACME --------------------------------------------------------------
    ca_provider: str = "pebble"
    acme_directory_url: str | None = None
    acme_contact_email: str | None = None
    account_key_path: str = "./data/account.key"
    cert_dir: str = "./data/certs"
    webroot_path: str = "./data/webroot"
    domain_key_type: str = "ec"

    # Disables TLS verification when talking to the ACME server. Required for
    # Pebble, which uses its own test root. Guarded below so it cannot be
    # combined with a production CA.
    acme_insecure: bool = False

    # -- lifecycle ---------------------------------------------------------
    renewal_threshold_days: int = 30
    scan_timeout_seconds: float = 8.0
    scan_concurrency: int = 20

    # -- AI ----------------------------------------------------------------
    # Default is off. The service is fully functional without a model, and
    # anything that requires an API key to work at all is a liability.
    llm_disabled: bool = True
    llm_provider: str = "anthropic"
    llm_model: str = "claude-sonnet-5"
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    llm_max_planned: int = 25

    @field_validator("ca_provider")
    @classmethod
    def _known_provider(cls, value: str) -> str:
        if value not in CA_DIRECTORIES:
            raise ValueError(
                f"ca_provider must be one of {', '.join(CA_DIRECTORIES)}, or set "
                "acme_directory_url explicitly for a custom CA"
            )
        return value

    @property
    def directory_url(self) -> str:
        """An explicit URL always wins; otherwise map the named provider."""
        return self.acme_directory_url or CA_DIRECTORIES[self.ca_provider]

    @property
    def verify_acme_tls(self) -> bool:
        """
        Never skip verification against a public CA.

        acme_insecure exists for Pebble's self-signed test root. If it is set
        while pointing at a real CA that is a configuration mistake, and
        honouring it would mean any network attacker could impersonate the CA
        and hand us a certificate we would then deploy. So it is ignored
        rather than trusted.
        """
        production = self.directory_url in (LETSENCRYPT_PRODUCTION, LETSENCRYPT_STAGING)
        return not (self.acme_insecure and not production)


@lru_cache
def get_settings() -> Settings:
    """Cached so the .env file is read once, and so tests can clear it."""
    return Settings()
