"""Fenrir Cloud application factory."""

from __future__ import annotations

import logging
import mimetypes
import secrets
import sys
import threading
from contextlib import asynccontextmanager, contextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from sqlalchemy import delete, select

from . import __version__, crypto, audit, db as database, events, policy_schema, psa, ratelimit, remote, rmm, rmm_library
from . import vulnmgmt  # noqa: F401 - registers its event handlers
from .config import Settings, get_settings, set_settings
from .detection import sync_builtin_rules
from .models import DnsQueryLog, Event, RateLimitBucket, Policy, RuleMatch, Tenant, User, utcnow
from .routers import m365_admin as m365_admin_router
from .routers import m365 as m365_router, network as network_router, grc as grc_router, backup as backup_router, soc_workflows
from .routers import documentation as documentation_router
from .routers import active_directory as ad_router
from .routers import grc_programme as grc_programme_router
from .routers import rollouts as rollouts_router
from .routers import apikeys as apikeys_router
from .routers import admin, agent_api, artifacts as artifacts_router, business, crm as crm_router, fleet, portal, protection, service_mgmt, soc
from .routers import psa as psa_router, remote as remote_router, rmm as rmm_router
from .security import hash_password
from .services import GLOBAL_POLICY_ID

# The console is installable as an app; browsers expect this type for its manifest.
mimetypes.add_type("application/manifest+json", ".webmanifest")

log = logging.getLogger("fenrir")


def bootstrap(settings: Settings) -> None:
    crypto.key_status()  # Validate configured keys before changing the database.
    applied = database.migrate(database.engine())
    if applied:
        log.info("applied database migrations: %s", applied)
    db = database.session_factory()()
    try:
        msp = db.execute(select(Tenant).where(Tenant.kind == "msp")).scalars().first()
        if msp is None:
            msp = Tenant(name="Palmertech", slug="palmertech", kind="msp", plan="mdr")
            db.add(msp)
            db.flush()
        if db.get(Policy, GLOBAL_POLICY_ID) is None:
            db.add(Policy(id=GLOBAL_POLICY_ID, tenant_id=None, name="Global baseline", template="balanced", settings={},
                          description="Platform-wide defaults. Lock settings here to enforce them on every customer."))
        if db.execute(select(User).limit(1)).scalar_one_or_none() is None:
            password = settings.bootstrap_admin_password or secrets.token_urlsafe(14)
            db.add(User(tenant_id=msp.id, email=settings.bootstrap_admin_email.lower(), name="Platform admin", role="platform_admin",
                        password_hash=hash_password(password)))
            audit.record(db, "system", "bootstrap.admin_created", settings.bootstrap_admin_email, msp.id)
            if not settings.bootstrap_admin_password:
                # Printed once so the first operator can sign in; change it straight away.
                print(f"\n[fenrir] Created admin {settings.bootstrap_admin_email} with password: {password}\n", file=sys.stderr)
        rmm_library.seed(db)
        psa.ensure_default_boards(db, msp.id)
        db.commit()
        sync_builtin_rules(db, settings.rules_dir)
        # Once, after the antimalware precision update: close open alerts the tuned rules no longer raise.
        from sqlalchemy import text

        if 17 not in set(db.execute(text("SELECT version FROM schema_migrations")).scalars()):
            from .detection import retune_open_alerts

            log.info("detection tuning: %s", retune_open_alerts(db))
            db.execute(text("INSERT INTO schema_migrations (version) VALUES (17)"))
            db.commit()
    finally:
        db.close()


def _maintenance_loop(settings: Settings, stop: threading.Event) -> None:
    """Hourly: purge telemetry past retention, refresh the upstream feed if enabled."""
    delay = 30.0
    while not stop.wait(delay):
        delay = 3600.0
        db = database.session_factory()()
        try:
            cutoff = utcnow() - timedelta(days=settings.telemetry_retention_days)
            db.execute(delete(Event).where(Event.occurred_at < cutoff))
            db.execute(delete(RuleMatch).where(RuleMatch.at < cutoff))
            db.execute(delete(DnsQueryLog).where(DnsQueryLog.at < cutoff))
            db.execute(delete(RateLimitBucket).where(RateLimitBucket.expires_at < utcnow()))
            db.commit()
            if settings.feed_sync_enabled:
                from .intel import sync_feed

                result = sync_feed(db, settings.feed_url, settings.feed_token)
                log.info("feed sync: %s", result)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            log.warning("maintenance cycle failed: %s", exc)
            db.rollback()
        finally:
            db.close()


@contextmanager
def _scheduler_lease():
    """Only one cloud worker may run scheduled MSP operations at a time.

    PostgreSQL session advisory locks survive the intermediate commits used by
    the existing scheduler. Hold a *dedicated connection* throughout the pass
    and release the lock on that same connection on every exit.
    """
    engine = database.engine()
    if engine.dialect.name != "postgresql":
        # SQLite remains supported for single-process local development only.
        yield True
        return
    lock_key = 726191904221
    with engine.connect() as lock_connection:
        acquired = bool(lock_connection.exec_driver_sql(
            f"SELECT pg_try_advisory_lock({lock_key})").scalar())
        try:
            yield acquired
        finally:
            if acquired:
                lock_connection.exec_driver_sql(
                    f"SELECT pg_advisory_unlock({lock_key})")
            lock_connection.rollback()


def _scheduler_loop(stop: threading.Event, interval: float = 30.0) -> None:
    """Periodic MSP jobs are single-owner across PostgreSQL API workers."""
    passes = 0
    while not stop.wait(interval):
        try:
            with _scheduler_lease() as acquired:
                if not acquired:
                    continue
                passes += 1
                db = database.session_factory()()
                try:
                    rmm.tick(db)
                    psa.timed_workflows(db)
                    remote.expire_sessions(db)
                    db.commit()
                    events.process(db)
                    db.commit()
                    from . import network
                    network.tick(db)
                    if passes % 10 == 0:
                        from .routers import backup as backup_health
                        backup_health.health_tick(db)
                    if passes % 120 == 0:
                        from .routers import artifacts as artifact_store
                        artifact_store.purge_expired(db)
                        audit.daily_checkpoint(db)  # CORE-06: daily chain-head checkpoint (published to webhooks)
                        audit.apply_retention(db)
                    if passes % 4 == 0:
                        msp = db.execute(select(Tenant).where(Tenant.kind == "msp")).scalars().first()
                        if msp is not None:
                            psa.poll_imap(db, msp.id)
                    db.commit()
                except Exception as exc:
                    log.warning("scheduler pass failed: %s", exc)
                    db.rollback()
                finally:
                    db.close()
        except Exception as exc:
            log.warning("scheduler lease could not be acquired/released: %s", exc)


LINUX_INSTALLER = r"""#!/bin/sh
# Fenrir Linux agent installer. Usage:
#   curl -fsSL {base}/install/linux.sh | sudo FENRIR_SERVER={base} FENRIR_TOKEN=<token> sh
set -eu
: "${{FENRIR_SERVER:?set FENRIR_SERVER}}"
: "${{FENRIR_TOKEN:?set FENRIR_TOKEN}}"
ARCH=$(uname -m); case "$ARCH" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; esac
TMP=$(mktemp -d)
curl -fsSL "$FENRIR_SERVER/downloads/fenrir-agent-linux-$ARCH" -o "$TMP/fenrir-agent"
install -m 0755 "$TMP/fenrir-agent" /usr/local/bin/fenrir-agent
mkdir -p /etc/fenrir /var/lib/fenrir
umask 077
cat > /etc/fenrir/agent.env <<EOF
FENRIR_SERVER=$FENRIR_SERVER
FENRIR_ENROLLMENT_TOKEN=$FENRIR_TOKEN
FENRIR_STATE_DIR=/var/lib/fenrir
EOF
cat > /etc/systemd/system/fenrir-agent.service <<'EOF'
[Unit]
Description=Fenrir endpoint protection agent
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/fenrir/agent.env
ExecStart=/usr/local/bin/fenrir-agent
Restart=always
RestartSec=5
ProtectSystem=full
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now fenrir-agent
echo "Fenrir agent installed and enrolling with $FENRIR_SERVER"
"""


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    set_settings(settings)
    database.init_engine(settings.database_url)
    stop = threading.Event()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        bootstrap(settings)
        worker = threading.Thread(target=_maintenance_loop, args=(settings, stop), daemon=True)
        worker.start()
        if settings.scheduler_enabled:
            threading.Thread(target=_scheduler_loop, args=(stop,), daemon=True).start()
        if settings.scheduler_enabled and settings.vuln_intel_enabled:
            from . import cveintel

            threading.Thread(target=cveintel.loop, args=(stop,), daemon=True, name="vuln-intel").start()
        yield
        stop.set()

    app = FastAPI(title="Fenrir Cloud", version=__version__, lifespan=lifespan,
                  description="Unified control plane: antivirus/EDR fleet, SIEM, DNS protection, exposure management, CRM/PSA.")
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        # The remote viewer needs the clipboard and fullscreen; nothing else may use powerful features.
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    remote.install_wake_hook()
    for module in (agent_api, admin, fleet, soc, crm_router, business, rmm_router, service_mgmt, psa_router, remote_router, portal):
        app.include_router(module.router)
    for module in (m365_admin_router, m365_router, network_router, grc_router, backup_router, soc_workflows, ad_router, grc_programme_router,
                   rollouts_router, apikeys_router):
        app.include_router(module.router)
    app.include_router(documentation_router.router)
    app.include_router(m365_router.oauth)
    app.include_router(psa_router.inbound)
    app.include_router(backup_router.ingest)
    from .routers import local_admin as local_admin_router
    app.include_router(local_admin_router.agent)
    app.include_router(local_admin_router.console)
    from .routers import device_profile as device_profile_router
    app.include_router(device_profile_router.agent)
    app.include_router(device_profile_router.console)
    from .routers import mobile as mobile_router
    app.include_router(mobile_router.agent)
    app.include_router(mobile_router.console)
    from .routers import elevation as elevation_router
    app.include_router(elevation_router.agent)
    app.include_router(elevation_router.console)
    app.include_router(artifacts_router.agent)
    app.include_router(artifacts_router.console)
    app.include_router(remote_router.sockets)
    app.include_router(protection.router)
    app.include_router(protection.console)

    @app.get("/health", tags=["System"])
    def health():
        return {"status": "ok", "version": __version__, "policySettings": len(policy_schema.FIELDS)}

    @app.get("/install/linux.sh", response_class=PlainTextResponse, include_in_schema=False)
    def linux_installer():
        return LINUX_INSTALLER.format(base=settings.public_base_url.rstrip("/"))

    downloads = Path(__file__).resolve().parents[1] / "downloads"

    @app.get("/downloads/fenrir-codesign.cer", include_in_schema=False)
    def codesign_certificate():
        # The public half of the Windows code-signing certificate, for Group Policy / Intune trust deployment.
        target = downloads / "windows" / "fenrir-codesign.cer"
        if not target.is_file():
            return JSONResponse({"detail": "The Windows build is not code-signed"}, status_code=404)
        return FileResponse(target, media_type="application/pkix-cert", filename="fenrir-codesign.cer")

    @app.get("/downloads/fenrir-android.apk", include_in_schema=False)
    def android_app():
        # Built by agent/android (./gradlew assembleRelease) and copied here by the deploy script.
        target = downloads / "fenrir-android.apk"
        if not target.is_file():
            return JSONResponse({"detail": "The Android app has not been published on this server yet"}, status_code=404)
        return FileResponse(target, media_type="application/vnd.android.package-archive", filename="fenrir-android.apk",
                            headers={"Cache-Control": "no-cache"})

    @app.get("/downloads/{name}", include_in_schema=False)
    def download(name: str):
        target = (downloads / name).resolve()
        if downloads.resolve() not in target.parents or not target.is_file():
            return JSONResponse({"detail": "Not found"}, status_code=404)
        return FileResponse(target)

    if settings.enable_legacy:
        _mount_legacy(app)

    console_dir = settings.console_dir
    if console_dir.is_dir() and (console_dir / "index.html").is_file():
        from fastapi.staticfiles import StaticFiles

        app.mount("/assets", StaticFiles(directory=console_dir / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            candidate = (console_dir / path).resolve()
            if path and console_dir.resolve() in candidate.parents and candidate.is_file():
                # The service worker and manifest must always be re-checked, or installed apps never update.
                fresh = {"Cache-Control": "no-cache"} if path in {"sw.js", "manifest.webmanifest"} else None
                return FileResponse(candidate, headers=fresh)
            return FileResponse(console_dir / "index.html", headers={"Cache-Control": "no-cache"})

    return app


def _mount_legacy(app: FastAPI) -> None:
    """Mount the vendored Sentinel investigation API at /legacy/sentinel."""
    sentinel = Path(__file__).resolve().parents[2] / "components" / "sentinel"
    if not sentinel.is_dir():
        log.warning("legacy Sentinel not found at %s", sentinel)
        return
    sys.path.insert(0, str(sentinel))
    try:
        import importlib

        legacy = importlib.import_module("main")
        app.mount("/legacy/sentinel", legacy.app)
        log.info("mounted legacy Sentinel API at /legacy/sentinel")
    except Exception as exc:  # noqa: BLE001 - legacy code is optional
        log.warning("could not mount legacy Sentinel: %s", exc)
    finally:
        sys.path.remove(str(sentinel))


def run() -> None:  # pragma: no cover - CLI entry
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    uvicorn.run(create_app(), host="0.0.0.0", port=8080)
