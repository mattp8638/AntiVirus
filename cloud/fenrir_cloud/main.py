"""Fenrir Cloud application factory."""

from __future__ import annotations

import logging
import mimetypes
import secrets
import sys
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from sqlalchemy import delete, func, select, text

from . import __version__, crypto, audit, db as database, events, policy_schema, psa, ratelimit, remote, rmm, rmm_library
from . import vulnmgmt  # noqa: F401 - registers its event handlers
from . import ai_helpdesk  # noqa: F401 - registers its event handlers
from .config import Settings, get_settings, set_settings
from .detection import sync_builtin_rules
from .models import Device, DnsQueryLog, Event, RateLimitBucket, Policy, RuleMatch, Tenant, User, utcnow
from .routers import m365_admin as m365_admin_router
from .routers import m365 as m365_router, network as network_router, grc as grc_router, backup as backup_router, soc_workflows
from .routers import documentation as documentation_router
from .routers import active_directory as ad_router
from .routers import grc_programme as grc_programme_router
from .routers import rollouts as rollouts_router
from .routers import apikeys as apikeys_router
from .routers import roles as roles_router
from .routers import approvals as approvals_router
from .routers import exclusions as exclusions_router
from .routers import exposure_intel as exposure_intel_router
from .routers import m365_partner as m365_partner_router
from .routers import condition_packages as condition_packages_router
from .routers import oob as oob_router
from .routers import customization as customization_router
from .routers import grc_assurance as grc_assurance_router
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
        from . import condition_remediation

        condition_remediation.seed(db)
        from . import blocklists

        blocklists.ensure_builtin(db)
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


SCHEDULER_LOCK = 726191904221
MAINTENANCE_LOCK = 726191904222


def _run_job(db, name: str, job) -> bool:
    """Runs one background job in its own transaction and records how it went. One failing job never stops the others."""
    from .models import BackgroundJob

    started = time.monotonic()
    error = ""
    _mark_running(db, name)
    try:
        job(db)
        db.commit()
    except Exception as exc:  # noqa: BLE001 - the next job still runs
        db.rollback()
        error = f"{type(exc).__name__}: {exc}"[:1000]
        log.warning("background job %s failed: %s", name, error)
    try:
        now = utcnow()
        row = db.get(BackgroundJob, name) or BackgroundJob(name=name, failures=0)
        row.last_run_at, row.ok, row.error, row.running_since = now, not error, error, None
        row.duration_ms = int((time.monotonic() - started) * 1000)
        row.failures = (row.failures or 0) + 1 if error else 0
        if not error:
            row.last_ok_at = now
        db.merge(row)
        db.commit()
    except Exception as exc:  # noqa: BLE001 - recording the outcome must not break the loop
        db.rollback()
        log.warning("could not record background job %s: %s", name, exc)
    return not error


def _mark_running(db, name: str) -> None:
    """Record that a job has started, so one that never finishes shows up as stuck rather than as nothing."""
    from .models import BackgroundJob

    try:
        row = db.get(BackgroundJob, name) or BackgroundJob(name=name, failures=0)
        row.running_since = utcnow()
        db.merge(row)
        db.commit()
    except Exception as exc:  # noqa: BLE001 - never stop the job over its bookkeeping
        db.rollback()
        log.warning("could not mark background job %s as running: %s", name, exc)


def _heartbeat(name: str, started: float) -> None:
    """A completed scheduler or maintenance pass: what /health/background checks for freshness."""
    from .models import BackgroundJob

    with database.session_factory()() as db:
        try:
            now = utcnow()
            row = db.get(BackgroundJob, name) or BackgroundJob(name=name, failures=0)
            row.last_run_at = row.last_ok_at = now
            row.ok, row.error, row.failures, row.running_since = True, "", 0, None
            row.duration_ms = int((time.monotonic() - started) * 1000)
            db.merge(row)
            db.commit()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            log.warning("could not record %s: %s", name, exc)


PURGE_CHUNK = 5000


def _delete_in_chunks(db, model, *conditions) -> int:
    """Delete in short transactions, so an hourly purge of millions of rows never holds one long lock."""
    removed = 0
    while True:
        ids = db.execute(select(model.id).where(*conditions).limit(PURGE_CHUNK)).scalars().all()
        if not ids:
            return removed
        db.execute(delete(model).where(model.id.in_(ids)))
        db.commit()
        removed += len(ids)
        if len(ids) < PURGE_CHUNK:
            return removed


def _purge_telemetry(db, settings: Settings) -> dict:
    """Everything past FENRIR_TELEMETRY_RETENTION_DAYS; routine activity past FENRIR_ROUTINE_RETENTION_DAYS, unless a
    detection rule matched it (it is an alert's evidence then)."""
    from sqlalchemy import exists

    from .detection import ROUTINE_CATEGORIES

    now = utcnow()
    cutoff = now - timedelta(days=settings.telemetry_retention_days)
    removed = {"events": _delete_in_chunks(db, Event, Event.occurred_at < cutoff)}
    routine_cutoff = now - timedelta(days=min(settings.routine_retention_days, settings.telemetry_retention_days))
    if routine_cutoff > cutoff:
        removed["routine"] = _delete_in_chunks(
            db, Event, Event.occurred_at < routine_cutoff, Event.category.in_(ROUTINE_CATEGORIES), Event.severity == "info",
            ~exists().where(RuleMatch.event_pk == Event.id))
    removed["ruleMatches"] = _delete_in_chunks(db, RuleMatch, RuleMatch.at < cutoff)
    removed["dnsQueries"] = _delete_in_chunks(db, DnsQueryLog, DnsQueryLog.at < cutoff)
    db.execute(delete(RateLimitBucket).where(RateLimitBucket.expires_at < utcnow()))
    if any(removed.values()):
        log.info("telemetry retention removed %s", removed)
    return removed


def _maintenance_jobs(settings: Settings) -> list[tuple[str, object]]:
    """Hourly jobs, in order."""
    from . import autodoc, billing_sync, darkweb, grc_automation, m365_partner, m365_standards, tprm

    jobs: list[tuple[str, object]] = [("telemetry.retention", lambda db: _purge_telemetry(db, settings))]
    if settings.feed_sync_enabled:
        from .intel import sync_feed

        jobs.append(("intel.feed", lambda db: log.info("feed sync: %s", sync_feed(db, settings.feed_url, settings.feed_token))))
    jobs += [("m365.partner", m365_partner.tick), ("documentation.auto", autodoc.tick), ("tprm", tprm.tick),
             ("grc.automation", grc_automation.tick), ("darkweb", darkweb.tick), ("m365.standards", m365_standards.tick),
             ("billing.sync", billing_sync.tick)]
    if settings.dns_blocklists_enabled:
        from . import blocklists

        jobs.append(("dns.blocklists", lambda db: [log.info("dns blocklist sync: %s", r) for r in blocklists.sync_due(db)]))
    return jobs


def _maintenance_loop(settings: Settings, stop: threading.Event) -> None:
    """Hourly: purge telemetry past retention, refresh feeds, run the slow provider syncs. One worker at a time."""
    delay = 30.0
    while not stop.wait(delay):
        delay = 3600.0
        try:
            with _scheduler_lease(MAINTENANCE_LOCK) as acquired:
                if not acquired:
                    continue  # another worker is running them
                started = time.monotonic()
                db = database.session_factory()()
                try:
                    for name, job in _maintenance_jobs(settings):
                        if stop.is_set():
                            break
                        _run_job(db, name, job)
                finally:
                    db.close()
                _heartbeat("maintenance.pass", started)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            log.warning("maintenance lease could not be acquired/released: %s", exc)


@contextmanager
def _scheduler_lease(lock_key: int = SCHEDULER_LOCK):
    """Only one cloud worker may run a set of scheduled jobs at a time.

    PostgreSQL session advisory locks survive the intermediate commits used by
    the jobs. Hold a *dedicated connection* throughout the pass and release the
    lock on that same connection on every exit.
    """
    engine = database.engine()
    if engine.dialect.name != "postgresql":
        # SQLite remains supported for single-process local development only.
        yield True
        return
    with engine.connect() as lock_connection:
        acquired = bool(lock_connection.exec_driver_sql(
            f"SELECT pg_try_advisory_lock({int(lock_key)})").scalar())
        try:
            yield acquired
        finally:
            if acquired:
                lock_connection.exec_driver_sql(
                    f"SELECT pg_advisory_unlock({int(lock_key)})")
            lock_connection.rollback()


def _poll_msp_mailbox(db) -> None:
    msp = db.execute(select(Tenant).where(Tenant.kind == "msp")).scalars().first()
    if msp is not None:
        psa.poll_imap(db, msp.id)


def _scheduled_jobs() -> list[tuple[str, int, object]]:
    """(name, every N passes of 30 seconds, job), in the order they run within a pass."""
    from . import condition_remediation, network, remediation, topology
    from .routers import artifacts as artifact_store
    from .routers import backup as backup_health

    return [
        ("rmm", 1, rmm.tick),
        ("psa.timed-workflows", 1, psa.timed_workflows),
        ("remote.expire-sessions", 1, remote.expire_sessions),
        ("events.outbox", 1, events.process),  # after the jobs above, so their events go out in the same pass
        ("network", 1, network.tick),
        ("psa.mailbox", 4, _poll_msp_mailbox),  # every two minutes
        ("condition-remediation", 10, condition_remediation.tick),  # every five minutes
        ("backup.health", 10, backup_health.health_tick),
        ("remediation", 20, remediation.tick),  # every ten minutes
        ("topology", 120, topology.tick),  # hourly
        ("artifacts.purge", 120, artifact_store.purge_expired),
        ("audit.checkpoint", 120, audit.daily_checkpoint),  # CORE-06: daily chain-head checkpoint (published to webhooks)
        ("audit.retention", 120, audit.apply_retention),
    ]


def _scheduler_loop(stop: threading.Event, interval: float = 30.0) -> None:
    """Periodic MSP jobs are single-owner across PostgreSQL API workers."""
    passes = 0
    while not stop.wait(interval):
        try:
            with _scheduler_lease() as acquired:
                if not acquired:
                    continue
                passes += 1
                started = time.monotonic()
                db = database.session_factory()()
                try:
                    for name, every, job in _scheduled_jobs():
                        if passes % every == 0 and not stop.is_set():
                            _run_job(db, name, job)
                finally:
                    db.close()
                _heartbeat("scheduler.pass", started)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            log.warning("scheduler lease could not be acquired/released: %s", exc)


def start_background(settings: Settings, stop: threading.Event) -> list[threading.Thread]:
    """Starts the background loops: hourly maintenance, the 30-second scheduler and vulnerability intel. The web
    process runs them itself (FENRIR_ROLE=all) or leaves them to ``python -m fenrir_cloud.worker`` (web/worker)."""
    threads = [threading.Thread(target=_maintenance_loop, args=(settings, stop), daemon=True, name="maintenance")]
    if settings.scheduler_enabled:
        threads.append(threading.Thread(target=_scheduler_loop, args=(stop,), daemon=True, name="scheduler"))
    if settings.scheduler_enabled and settings.vuln_intel_enabled:
        from . import cveintel

        threads.append(threading.Thread(target=cveintel.loop, args=(stop,), daemon=True, name="vuln-intel"))
    for thread in threads:
        thread.start()
    return threads


def _wake_relay_loop(stop: threading.Event, interval: float = 2.0) -> None:
    """In a split deployment the worker queues commands (schedules, automations, remediation, playbooks) but agents
    keep their live connections to this process, so a commit in the worker cannot wake them. Every couple of
    seconds, wake connected agents that have a pending command not yet woken for."""
    woken: dict[str, float] = {}
    while not stop.wait(interval):
        try:
            _wake_pending(woken)
        except Exception as exc:  # noqa: BLE001 - try again next round
            log.warning("wake relay could not read pending commands: %s", exc)


def _wake_pending(woken: dict[str, float]) -> set[str]:
    """One relay round. ``woken`` maps command ids already woken for to when; returns the devices woken now."""
    from .models import Command
    from .remote import hub

    connected = list(hub.devices)
    if not connected:
        return set()
    with database.session_factory()() as db:
        rows = [row for start in range(0, len(connected), 500) for row in db.execute(
            select(Command.id, Command.device_id).where(Command.status == "pending",
                                                        Command.device_id.in_(connected[start:start + 500]))).all()]
    now = time.monotonic()
    due = {device_id for command_id, device_id in rows if command_id not in woken}
    woken.update({command_id: woken.get(command_id, now) for command_id, _ in rows})
    for command_id in [c for c, at in woken.items() if now - at > 600]:
        del woken[command_id]
    if due:
        hub.wake(due)
    return due


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


def _existing_users() -> int:
    try:
        with database.session_factory()() as db:
            return db.execute(select(func.count()).select_from(User)).scalar() or 0
    except Exception:  # noqa: BLE001 - a fresh database has no tables yet
        return 0


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    if settings.role not in ("all", "web", "worker"):
        raise RuntimeError(f"FENRIR_ROLE must be all, web or worker, not {settings.role!r}")
    set_settings(settings)
    database.init_engine(settings.database_url)
    from . import production

    errors, warnings = production.check(settings, _existing_users())
    if errors:  # CORE-14: never start an unsafe production server
        raise RuntimeError("Fenrir will not start in production with these settings:\n- " + "\n- ".join(errors))
    for warning in warnings:
        log.warning("%s", warning)
    stop = threading.Event()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        bootstrap(settings)
        if settings.role == "web":
            # The worker queues commands; this process holds the agents' live connections, so it wakes them.
            threading.Thread(target=_wake_relay_loop, args=(stop,), daemon=True, name="wake-relay").start()
        else:
            start_background(settings, stop)
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

    from . import approvals as approval_gate

    @app.exception_handler(approval_gate.ApprovalRequired)
    async def approval_required(_request: Request, exc: approval_gate.ApprovalRequired):
        return exc.response()

    remote.install_wake_hook()
    for module in (agent_api, admin, fleet, soc, crm_router, business, rmm_router, service_mgmt, psa_router, remote_router, portal):
        app.include_router(module.router)
    for module in (m365_admin_router, m365_router, network_router, grc_router, backup_router, soc_workflows, ad_router, grc_programme_router,
                   rollouts_router, apikeys_router, roles_router, approvals_router, exclusions_router,
                   exposure_intel_router, m365_partner_router, condition_packages_router):
        app.include_router(module.router)
    app.include_router(documentation_router.router)
    app.include_router(m365_router.oauth)
    app.include_router(psa_router.inbound)
    app.include_router(business.xero_callback)
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
    app.include_router(oob_router.router)
    app.include_router(oob_router.agent_router)
    app.include_router(grc_assurance_router.router)
    app.include_router(grc_assurance_router.public)
    app.include_router(protection.router)
    app.include_router(protection.console)
    app.include_router(customization_router.router)

    @app.get("/health", tags=["System"])
    def health():
        return {"status": "ok", "version": __version__, "policySettings": len(policy_schema.FIELDS)}

    @app.get("/health/background", tags=["System"])
    def background_health():
        """For uptime monitors: the scheduler and hourly maintenance are completing, no job is hung and the event
        outbox is keeping up. 503 names what is wrong. Job names and counts only, no errors or customer data."""
        from .health import background_health as report

        try:
            with database.session_factory()() as db:
                result = report(db, settings)
        except Exception:  # noqa: BLE001
            return JSONResponse({"ok": False, "problems": ["database unavailable"]}, status_code=503)
        return result if result["ok"] else JSONResponse(result, status_code=503)

    @app.get("/ready", tags=["System"])
    def ready():
        """For load balancers and orchestrators: the database answers and its schema is the one this build expects."""
        try:
            with database.session_factory()() as db:
                version = db.execute(text("SELECT MAX(version) FROM schema_migrations")).scalar()
                if version == database.LATEST_MIGRATION:
                    try:
                        # Resolve all mapped columns without returning device data.
                        # A current ledger alone did not catch the skipped build column.
                        db.execute(select(Device).limit(0))
                    except Exception:  # noqa: BLE001
                        return JSONResponse({"ready": False, "reason": "device schema is incompatible"}, status_code=503)
        except Exception:  # noqa: BLE001
            return JSONResponse({"ready": False, "reason": "database unavailable"}, status_code=503)
        if version != database.LATEST_MIGRATION:
            return JSONResponse({"ready": False, "reason": "database schema is not current"}, status_code=503)
        return {"ready": True}

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
