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
    # production (the Docker Compose default) refuses to start on unsafe settings; see production.py.
    environment: str = field(default_factory=lambda: os.getenv("FENRIR_ENV", "development").strip().lower())
    database_url: str = field(default_factory=lambda: os.getenv("FENRIR_DATABASE_URL", "sqlite:///./fenrir.db"))
    # Signs console session tokens. Generated per process when unset, which logs
    # everyone out on restart: set it in any real deployment.
    secret_key: str = field(default_factory=lambda: os.getenv("FENRIR_SECRET_KEY") or secrets.token_hex(32))
    token_ttl_minutes: int = field(default_factory=lambda: int(os.getenv("FENRIR_TOKEN_TTL_MINUTES", "720")))
    # Staff must use MFA unless the platform settings say otherwise (Settings > Platform > Security).
    require_mfa: bool = field(default_factory=lambda: _bool("FENRIR_REQUIRE_MFA", True))
    # Default for Settings > Platform > Security > "Require script review" until it is saved there.
    script_review: bool = field(default_factory=lambda: _bool("FENRIR_SCRIPT_REVIEW", False))
    # Break glass: ignore the console network allow-list (when a wrong list has locked every administrator out).
    ignore_console_allowlist: bool = field(default_factory=lambda: _bool("FENRIR_IGNORE_CONSOLE_ALLOWLIST", False))
    public_base_url: str = field(default_factory=lambda: os.getenv("FENRIR_PUBLIC_URL", "http://localhost:8080"))
    # Microsoft 365 sign-in. The MSP's own multi-tenant Entra app ("Sign in with Microsoft"); leave empty to use only
    # "Sign in with a code", which creates a Fenrir app registration inside each customer tenant instead.
    m365_client_id: str = field(default_factory=lambda: os.getenv("FENRIR_M365_CLIENT_ID", ""))
    m365_client_secret: str = field(default_factory=lambda: os.getenv("FENRIR_M365_CLIENT_SECRET", ""))
    # Public client used for the device-code sign-in (default: Microsoft Graph Command Line Tools).
    m365_public_client_id: str = field(default_factory=lambda: os.getenv("FENRIR_M365_PUBLIC_CLIENT_ID", "14d82eec-204b-4c2f-b7e8-296a70dab67e"))

    bootstrap_admin_email: str = field(default_factory=lambda: os.getenv("FENRIR_ADMIN_EMAIL", "admin@fenrir.local"))
    bootstrap_admin_password: str | None = field(default_factory=lambda: os.getenv("FENRIR_ADMIN_PASSWORD"))

    # Devices that enroll without a token land in the "Unassigned" tenant and
    # wait for approval. Turn off to require an enrollment token.
    open_enrollment: bool = field(default_factory=lambda: _bool("FENRIR_OPEN_ENROLLMENT", True))

    # Upstream signature feed (the signaturedb-fenrir Cloudflare worker).
    feed_url: str = field(default_factory=lambda: os.getenv("FENRIR_FEED_URL", "https://api.fenrir-security.co.uk"))
    feed_token: str = field(default_factory=lambda: os.getenv("FENRIR_FEED_TOKEN", ""))
    feed_sync_enabled: bool = field(default_factory=lambda: _bool("FENRIR_FEED_SYNC", False))

    # Have I Been Pwned subscription key for dark-web credential exposure monitoring (darkweb.py).
    hibp_api_key: str = field(default_factory=lambda: os.getenv("FENRIR_HIBP_API_KEY", ""))
    # External DNS blocklists (HaGeZi and others; see blocklists.py), refreshed by the hourly maintenance loop.
    dns_blocklists_enabled: bool = field(default_factory=lambda: _bool("FENRIR_DNS_BLOCKLISTS", True))
    dns_upstream: str = field(default_factory=lambda: os.getenv("FENRIR_DNS_UPSTREAM", "https://cloudflare-dns.com/dns-query"))
    dns_sinkhole_ipv4: str = field(default_factory=lambda: os.getenv("FENRIR_DNS_SINKHOLE", "0.0.0.0"))

    cors_origins: list[str] = field(default_factory=lambda: _list("FENRIR_CORS_ORIGINS", "http://localhost:5173"))
    console_dir: Path = field(
        default_factory=lambda: Path(os.getenv("FENRIR_CONSOLE_DIR", str(Path(__file__).resolve().parents[2] / "console" / "dist")))
    )
    model_dir: Path = field(
        default_factory=lambda: Path(os.getenv("FENRIR_MODEL_DIR", str(Path(__file__).resolve().parents[2] / "ml" / "models")))
    )
    # Forensic and support bundles uploaded by agents (mount a volume here in production).
    artifact_dir: Path = field(
        default_factory=lambda: Path(os.getenv("FENRIR_ARTIFACT_DIR", str(Path(__file__).resolve().parents[1] / "data" / "artifacts")))
    )
    artifact_max_bytes: int = field(default_factory=lambda: int(os.getenv("FENRIR_ARTIFACT_MAX_BYTES", str(200 * 1024 * 1024))))
    artifact_retention_days: int = field(default_factory=lambda: int(os.getenv("FENRIR_ARTIFACT_RETENTION_DAYS", "30")))
    # The 30-second RMM/PSA scheduler (scheduled tasks, monitors, patch windows, workflows).
    scheduler_enabled: bool = field(default_factory=lambda: _bool("FENRIR_SCHEDULER", True))
    # Background CVE intelligence: NVD (CVSS, descriptions, app version matching), FIRST EPSS and CISA KEV.
    # An NVD API key (free, https://nvd.nist.gov/developers/request-an-api-key) raises NVD's limit tenfold.
    vuln_intel_enabled: bool = field(default_factory=lambda: _bool("FENRIR_VULN_INTEL", True))
    nvd_api_key: str = field(default_factory=lambda: os.getenv("FENRIR_NVD_API_KEY", ""))
    rules_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "rules" / "sigma")

    # Mount the vendored Sentinel investigation API under /legacy/sentinel.
    enable_legacy: bool = field(default_factory=lambda: _bool("FENRIR_ENABLE_LEGACY", False))
    telemetry_retention_days: int = field(default_factory=lambda: int(os.getenv("FENRIR_TELEMETRY_RETENTION_DAYS", "90")))
    max_telemetry_batch: int = field(default_factory=lambda: int(os.getenv("FENRIR_MAX_TELEMETRY_BATCH", "2000")))
    # Routine activity (process, image-load, network, DNS, file, registry, script-scan events at "info") is kept for less time
    # than detections, scan results and agent state, and each device may store only so much of it per minute: past
    # the cap, routine events are still checked against every detection rule but stored only if one matches.
    routine_retention_days: int = field(default_factory=lambda: int(os.getenv("FENRIR_ROUTINE_RETENTION_DAYS", "30")))
    routine_events_per_device_minute: int = field(
        default_factory=lambda: int(os.getenv("FENRIR_ROUTINE_EVENTS_PER_DEVICE_MINUTE", "600")))
    # all: one process serves the API and runs background jobs. web / worker: split them (python -m fenrir_cloud.worker).
    role: str = field(default_factory=lambda: os.getenv("FENRIR_ROLE", "all").strip().lower())


_active: Settings | None = None


@lru_cache
def _from_environment() -> Settings:
    return Settings()


def get_settings() -> Settings:
    """Settings passed to ``create_app`` win; otherwise read once from the environment."""
    return _active or _from_environment()


def set_settings(settings: Settings | None) -> None:
    global _active
    _active = settings
