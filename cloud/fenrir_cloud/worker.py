"""Fenrir's background worker: the 30-second scheduler (RMM, automations, the event outbox, webhooks, the PSA
mailbox...), hourly maintenance (retention, Microsoft 365, GRC, billing sync...) and vulnerability intel, without
the web server.

    FENRIR_ROLE=worker python -m fenrir_cloud.worker    # the web process runs with FENRIR_ROLE=web
    python -m fenrir_cloud.worker --check               # exit 0 when background work is healthy (container healthcheck)

Splitting them means a slow provider sync never delays a console page or an agent check-in, and a crash in one
never takes down the other. The web process creates and upgrades the database; the worker waits until the schema
is current. More than one worker is safe: PostgreSQL advisory locks give each set of jobs one owner at a time and
the event outbox hands each event to one worker.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading

from sqlalchemy import text

from . import db as database
from .config import get_settings

log = logging.getLogger("fenrir.worker")


def _schema_current() -> bool:
    try:
        with database.session_factory()() as db:
            return db.execute(text("SELECT MAX(version) FROM schema_migrations")).scalar() == database.LATEST_MIGRATION
    except Exception:  # noqa: BLE001 - the web process has not created it yet
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fenrir background worker")
    parser.add_argument("--check", action="store_true", help="report background health and exit 0 (healthy) or 1")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from .main import create_app, start_background

    settings = get_settings()
    create_app(settings)  # the same configuration checks, and the same modules, jobs and event handlers, as the API

    if args.check:
        from .health import background_health

        try:
            with database.session_factory()() as db:
                report = background_health(db, settings)
        except Exception as exc:  # noqa: BLE001
            report = {"ok": False, "problems": [f"database unavailable: {exc}"]}
        print(json.dumps(report))
        return 0 if report["ok"] else 1

    if settings.role != "worker":
        log.warning("FENRIR_ROLE is %r: set the web process to FENRIR_ROLE=web, or both will run the jobs", settings.role)
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())

    waited = 0
    while not _schema_current():
        if waited % 60 == 0:
            log.info("waiting for the web process to bring the database to schema %s", database.LATEST_MIGRATION)
        if stop.wait(5):
            return 0
        waited += 5

    threads = start_background(settings, stop)
    log.info("Fenrir worker running: %s", ", ".join(thread.name for thread in threads))
    while not stop.wait(1):
        pass
    log.info("stopping; letting running jobs finish")
    for thread in threads:
        thread.join(timeout=60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
