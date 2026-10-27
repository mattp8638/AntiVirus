"""FIX-05 / AT-04: concurrent audit writers (with rollbacks and retries) leave exactly the committed events in one
verifiable chain. Before the fix, two interleaved transactions both chained onto the same previous hash.

Runs on PostgreSQL when FENRIR_TEST_DATABASE_URL is set (as in CI), otherwise on a file-backed SQLite database."""

import os
import threading

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from fenrir_cloud import audit
from fenrir_cloud.db import Base
from fenrir_cloud.models import AuditLog

WRITERS = 64
EVENTS_PER_WRITER = 3


@pytest.fixture()
def engine(tmp_path):
    url = os.getenv("FENRIR_TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'audit.db'}"
    if url.startswith("sqlite"):
        eng = create_engine(url, connect_args={"timeout": 60, "check_same_thread": False})

        @event.listens_for(eng, "connect")
        def _wal(dbapi_connection, _):
            dbapi_connection.execute("PRAGMA journal_mode=WAL")

        @event.listens_for(eng, "begin")
        def _immediate(conn):  # what the app's SQLite sessions do for writes
            conn.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        eng = create_engine(url, pool_size=WRITERS + 4, max_overflow=0)
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


def test_concurrent_writers_keep_one_valid_chain(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    barrier = threading.Barrier(WRITERS)
    errors = []
    committed = []
    lock = threading.Lock()

    def writer(n):
        try:
            barrier.wait()
            for i in range(EVENTS_PER_WRITER):
                with factory() as db:
                    audit.record(db, f"writer-{n}", "test.event", f"{n}-{i}")
                    if (n + i) % 7 == 0:  # some transactions roll back: their events must not appear
                        db.rollback()
                        continue
                    db.commit()
                    with lock:
                        committed.append(f"{n}-{i}")
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(WRITERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=300)
    assert not errors, errors[:3]
    with factory() as db:
        result = audit.verify_chain(db)
        targets = sorted(db.execute(select(AuditLog.target)).scalars())
    assert result == {"valid": True, "checked": len(committed)}, result
    assert targets == sorted(committed)


def test_rollback_of_first_event_then_new_writer(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        audit.record(db, "a", "first")
        db.rollback()
    with factory() as db:
        audit.record(db, "b", "second")
        audit.record(db, "b", "third")  # two in one transaction
        db.commit()
    with factory() as db:
        assert audit.verify_chain(db) == {"valid": True, "checked": 2}


def test_tampering_is_still_detected(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        for i in range(5):
            audit.record(db, "x", "event", str(i))
        db.commit()
    with factory() as db:
        row = db.execute(select(AuditLog).where(AuditLog.target == "2")).scalar_one()
        row.details = {"edited": True}
        db.commit()
        broken = audit.verify_chain(db)
    assert broken["valid"] is False and broken["checked"] == 2
    with factory() as db:
        db.delete(db.execute(select(AuditLog).where(AuditLog.target == "3")).scalar_one())
        db.commit()
        assert audit.verify_chain(db)["valid"] is False
