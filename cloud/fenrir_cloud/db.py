from __future__ import annotations

from collections.abc import Iterator
from contextlib import nullcontext

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def init_engine(url: str) -> Engine:
    global _engine, _session_factory
    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in {"sqlite://", "sqlite:///:memory:"}:
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    else:
        kwargs["pool_pre_ping"] = True
    _engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - driver hook
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Database engine not initialised")
    return _engine


def session_factory() -> sessionmaker[Session]:
    if _session_factory is None:
        raise RuntimeError("Database engine not initialised")
    return _session_factory


def get_db() -> Iterator[Session]:
    db = session_factory()()
    try:
        yield db
    finally:
        db.close()


def ensure_columns(base: type[DeclarativeBase], bind: Engine) -> list[str]:
    """Add columns that exist in the models but not yet in the database.

    ``create_all`` creates new tables but never alters existing ones. New
    columns on existing tables are declared nullable, so a plain
    ``ALTER TABLE ... ADD COLUMN`` is safe on SQLite and PostgreSQL.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(bind)
    existing_tables = set(inspector.get_table_names())
    added: list[str] = []
    with (bind.begin() if isinstance(bind, Engine) else nullcontext(bind)) as conn:
        for table in base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            present = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in present:
                    continue
                if not column.nullable:
                    # Never guess a backfill value for a required column.
                    continue
                ddl_type = column.type.compile(dialect=bind.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {ddl_type}'))
                added.append(f"{table.name}.{column.name}")
    return added


def migrate(bind: Engine) -> list[int]:
    """Apply ordered additive upgrades under one database-wide migration lock.

    Version 1 adopts the legacy schema without recreating tables or rows. Future
    upgrades must be appended here; applied versions are never rerun or edited.
    """
    from sqlalchemy import text

    applied = []
    with bind.connect() as conn:
        if bind.dialect.name == "sqlite":
            conn.exec_driver_sql("BEGIN IMMEDIATE")
        elif bind.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(721484616)"))
        else:
            raise RuntimeError("Migrations require SQLite or PostgreSQL")
        try:
            conn.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations "
                              "(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"))
            versions = set(conn.execute(text("SELECT version FROM schema_migrations")).scalars())
            if versions - {1, 2, 3, 4}:
                raise RuntimeError("Database schema is newer than this application")
            if 1 not in versions:
                Base.metadata.create_all(conn)
                ensure_columns(Base, conn)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (1)"))
                applied.append(1)
            if 2 not in versions:
                from .models import RateLimitBucket
                RateLimitBucket.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (2)"))
                applied.append(2)
            if 3 not in versions:
                from .models import DocumentRevision, VaultCredential
                for model in (DocumentRevision, VaultCredential):
                    model.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (3)"))
                applied.append(3)
            if 4 not in versions:
                from .models import (M365Connection, NetworkMonitor, GovernanceRecord, BackupPlan, BackupRun, RecoveryExercise, IncidentEvidence, AlertSuppression)
                for model in (M365Connection, NetworkMonitor, GovernanceRecord, BackupPlan, BackupRun, RecoveryExercise, IncidentEvidence, AlertSuppression):
                    model.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (4)"))
                applied.append(4)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return applied
