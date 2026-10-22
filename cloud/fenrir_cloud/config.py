"""Runtime configuration for Fenrir Cloud.

Everything is read from environment variables so the same image runs in
docker-compose, Kubernetes, or a developer laptop.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv("FENRIR_DATABASE_URL", "sqlite:///./fenrir.db"))
    # Signs console session tokens. Generated per process when unset, which logs
    # everyone out on restart: set it in any real deployment.
    secret_key: str = field(default_factory=lambda: os.getenv("FENRIR_SECRET_KEY") or secrets.token_hex(32))
    token_ttl_minutes: int = field(default_factory=lambda: int(os.getenv("FENRIR_TOKEN_TTL_MINUTES", "720")))
    public_base_url: str = field(default_factory=lambda: os.getenv("FENRIR_PUBLIC_URL", "http://localhost:8080"))

    bootstrap_admin_email: str = field(default_factory=lambda: os.getenv("FENRIR_ADMIN_EMAIL", "admin@fenrir.local"))
    bootstrap_admin_password: str | None = field(default_factory=lambda: os.getenv("FENRIR_ADMIN_PASSWORD"))

    # Devices that enroll without a token land in the "Unassigned" tenant and
    # wait for approval. Turn off to require an enrollment token.
    open_enrollment: bool = field(default_factory=lambda: _bool("FENRIR_OPEN_ENROLLMENT", True))

    # Upstream signature feed (the signaturedb-fenrir Cloudflare worker).
    feed_url: str = field(default_factory=lambda: os.getenv("FENRIR_FEED_URL", "https://api.fenrir-security.co.uk"))
    feed_token: str = field(default_factory=lambda: os.getenv("FENRIR_FEED_TOKEN", ""))
    feed_sync_enabled: bool = field(default_factory=lambda: _bool("FENRIR_FEED_SYNC", False))

    dns_upstream: str = field(default_factory=lambda: os.getenv("FENRIR_DNS_UPSTREAM", "https://cloudflare-dns.com/dns-query"))
    dns_sinkhole_ipv4: str = field(default_factory=lambda: os.getenv("FENRIR_DNS_SINKHOLE", "0.0.0.0"))

    cors_origins: list[str] = field(default_factory=lambda: _list("FENRIR_CORS_ORIGINS", "http://localhost:5173"))
    console_dir: Path = field(
        default_factory=lambda: Path(os.getenv("FENRIR_CONSOLE_DIR", str(Path(__file__).resolve().parents[2] / "console" / "dist")))
    )
    model_dir: Path = field(
        default_factory=lambda: Path(os.getenv("FENRIR_MODEL_DIR", str(Path(__file__).resolve().parents[2] / "ml" / "models")))
    )
    rules_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "rules" / "sigma")

    # Mount the vendored Sentinel investigation API under /legacy/sentinel.
    enable_legacy: bool = field(default_factory=lambda: _bool("FENRIR_ENABLE_LEGACY", False))
    telemetry_retention_days: int = field(default_factory=lambda: int(os.getenv("FENRIR_TELEMETRY_RETENTION_DAYS", "90")))
    max_telemetry_batch: int = field(default_factory=lambda: int(os.getenv("FENRIR_MAX_TELEMETRY_BATCH", "2000")))


@lru_cache
def get_settings() -> Settings:
    return Settings()
