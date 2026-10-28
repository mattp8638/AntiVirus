"""Production readiness checks (CORE-14).

With FENRIR_ENV=production (the Docker Compose default) the server refuses to start on settings that are unsafe
rather than merely suboptimal, and says exactly what to change. Softer risks are reported to platform
administrators instead of blocking.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

from .config import Settings

PLACEHOLDERS = ("change-me", "changeme", "replace-me", "replaceme", "your-")  # markers used by templates and docs
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(p in lowered for p in PLACEHOLDERS)


def check(settings: Settings, existing_users: int) -> tuple[list[str], list[str]]:
    """(errors, warnings). Errors only apply in production."""
    errors: list[str] = []
    warnings: list[str] = []
    key = settings.secret_key
    if not os.getenv("FENRIR_SECRET_KEY"):
        errors.append("FENRIR_SECRET_KEY is not set: sessions would end on every restart and differ between workers. "
                      "Set it in deploy/.env to the output of: openssl rand -hex 32")
    elif len(key) < 32 or _placeholder(key):
        errors.append("FENRIR_SECRET_KEY is a placeholder or shorter than 32 characters, so session tokens could be forged. "
                      "Set it to the output of: openssl rand -hex 32")
    if settings.database_url.startswith("sqlite"):
        errors.append("FENRIR_DATABASE_URL points at SQLite. Production needs PostgreSQL (the Docker Compose file provides it).")
    password = settings.bootstrap_admin_password or ""
    if existing_users == 0 and (len(password) < 12 or _placeholder(password)):
        errors.append("FENRIR_ADMIN_PASSWORD is missing, a placeholder or shorter than 12 characters, and it would become the "
                      "first administrator's password. Set a long random value in deploy/.env.")
    url = urlparse(settings.public_base_url)
    if url.scheme != "https" and (url.hostname or "") not in LOCAL_HOSTS:
        warnings.append(f"FENRIR_PUBLIC_URL ({settings.public_base_url}) is not HTTPS: agents and browsers would send credentials "
                        "unencrypted. Put the server behind TLS (deploy/docker-compose.https.yml) and use an https:// URL.")
    if settings.open_enrollment:
        warnings.append("FENRIR_OPEN_ENROLLMENT is on: any machine that can reach the server can enrol into the Unassigned "
                        "customer and wait for approval. Turn it off once enrolment tokens are in use.")
    if os.getenv("FENRIR_VAULT_ALLOW_DERIVED_LEGACY", "true").lower() in {"1", "true", "yes"}:
        warnings.append("FENRIR_VAULT_ALLOW_DERIVED_LEGACY is on: vault values encrypted with the old derived key are still "
                        "readable. Rotate the vault key, then set it to false.")
    if settings.environment != "production":
        warnings.insert(0, f"FENRIR_ENV is '{settings.environment}': production safety checks are not enforced.")
        return [], warnings
    return errors, warnings
