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


# The newest schema version this build creates. Bump it with every new migration below.
LATEST_MIGRATION = 46

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

    ``create_all`` creates new tables but never alters existing ones. This
    helper adds nullable columns only. Required columns need an explicit
    migration with a safe backfill; a Python ORM default does not add them.
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
            if versions - set(range(1, LATEST_MIGRATION + 1)):
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
            if 5 not in versions:
                from .models import M365Action
                M365Action.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (5)"))
                applied.append(5)
            if 6 not in versions:
                # Nullable columns added to existing tables (e.g. devices.patch_window_run).
                ensure_columns(Base, conn)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (6)"))
                applied.append(6)
            if 7 not in versions:
                from .models import Activity, Opportunity
                for model in (Opportunity, Activity):
                    model.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # tenants.account_owner
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (7)"))
                applied.append(7)
            if 8 not in versions:
                ensure_columns(Base, conn)  # problem/change management fields on psa tickets
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (8)"))
                applied.append(8)
            if 9 not in versions:
                ensure_columns(Base, conn)  # network_monitors.probe_device_id
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (9)"))
                applied.append(9)
            if 10 not in versions:
                ensure_columns(Base, conn)  # backup_plans.ingest_token_hash
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (10)"))
                applied.append(10)
            if 11 not in versions:
                from .models import DeviceArtifact
                DeviceArtifact.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (11)"))
                applied.append(11)
            if 12 not in versions:
                from .models import LocalAdminPassword
                LocalAdminPassword.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (12)"))
                applied.append(12)
            if 13 not in versions:
                from .models import ElevationRequest
                ElevationRequest.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (13)"))
                applied.append(13)
            if 14 not in versions:
                from .models import DeviceProfile, RecoveryKey
                for model in (DeviceProfile, RecoveryKey):
                    model.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (14)"))
                applied.append(14)
            if 15 not in versions:
                from .models import DeviceLocation
                DeviceLocation.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # devices.lost_mode
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (15)"))
                applied.append(15)
            if 16 not in versions:
                from .models import CpeMatchCache, CveRecord
                for model in (CveRecord, CpeMatchCache):
                    model.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # vulnerabilities evidence/fix/epss/cvss_vector, software_items install data
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (16)"))
                applied.append(16)
            # 17 is recorded by bootstrap (main.py) once the tuned detection rules have re-checked open alerts.
            if 18 not in versions:
                from .models import M365SignIn
                M365SignIn.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # m365_connections auth_mode, tenant_name, consent and secret expiry
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (18)"))
                applied.append(18)
            if 19 not in versions:
                from .models import GrcAdoption, GrcEvidence, GrcEvidenceLink, GrcFramework, GrcPolicy, GrcPolicyVersion, GrcRequirementState
                for model in (GrcFramework, GrcAdoption, GrcRequirementState, GrcPolicy, GrcPolicyVersion, GrcEvidence, GrcEvidenceLink):
                    model.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (19)"))
                applied.append(19)
            if 20 not in versions:
                from .models import VulnScan
                VulnScan.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (20)"))
                applied.append(20)
            if 21 not in versions:
                from .models import UserSession
                UserSession.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (21)"))
                applied.append(21)
            if 22 not in versions:
                # Audit chain head (FIX-05). Existing rows keep their order: seq = id, and the head points at the last.
                from .models import AuditChainHead
                AuditChainHead.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # audit_log.seq
                conn.execute(text("UPDATE audit_log SET seq = id WHERE seq IS NULL"))
                last = conn.execute(text("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")).first()
                conn.execute(text("DELETE FROM audit_chain_head"))
                conn.execute(text("INSERT INTO audit_chain_head (id, seq, last_hash) VALUES (1, :seq, :hash)"),
                             {"seq": last[0] if last else 0, "hash": last[1] if last else ""})
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (22)"))
                applied.append(22)
            if 23 not in versions:
                from .models import GrcAssessmentSnapshot
                GrcAssessmentSnapshot.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # grc_requirement_states.requirement_hash / requirement_text
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (23)"))
                applied.append(23)
            if 24 not in versions:
                from .models import AgentRollout, AgentRolloutDevice
                AgentRollout.__table__.create(conn, checkfirst=True)
                AgentRolloutDevice.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # devices.agent_build
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (24)"))
                applied.append(24)
            if 25 not in versions:
                from .models import ApiCredential
                ApiCredential.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (25)"))
                applied.append(25)
            if 26 not in versions:
                from .models import AuditCheckpoint, AuditPolicy
                AuditCheckpoint.__table__.create(conn, checkfirst=True)
                AuditPolicy.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (26)"))
                applied.append(26)
            if 27 not in versions:
                from .models import CustomRole
                CustomRole.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # users.assigned_tenant_ids
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (27)"))
                applied.append(27)
            if 28 not in versions:
                from .models import ApprovalRequest
                ApprovalRequest.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (28)"))
                applied.append(28)
            if 29 not in versions:
                # Migration 24 used ensure_columns, which deliberately skips
                # NOT NULL columns. A recorded 24 may still lack agent_build,
                # making every Device query fail on an upgraded database.
                # Empty means unknown until the next agent heartbeat.
                from sqlalchemy import inspect
                columns = {column["name"] for column in inspect(conn).get_columns("devices")}
                if "agent_build" not in columns:
                    conn.execute(text("ALTER TABLE devices ADD COLUMN agent_build VARCHAR(64) NOT NULL DEFAULT ''"))
                conn.execute(text("UPDATE devices SET agent_build = '' WHERE agent_build IS NULL"))
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (29)"))
                applied.append(29)
            if 30 not in versions:
                ensure_columns(Base, conn)  # nullable command cancellation fields; no history is changed
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (30)"))
                applied.append(30)
            if 31 not in versions:
                from .models import DiskTelemetryHistory, DiskExhaustionPrediction, ResourceBaseline, ResourceAnomaly
                DiskTelemetryHistory.__table__.create(conn, checkfirst=True)
                DiskExhaustionPrediction.__table__.create(conn, checkfirst=True)
                ResourceBaseline.__table__.create(conn, checkfirst=True)
                ResourceAnomaly.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (31)"))
                applied.append(31)
            if 32 not in versions:
                from .models import DnsBlocklist
                DnsBlocklist.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (32)"))
                applied.append(32)
            if 33 not in versions:
                from .models import EdrExclusion
                EdrExclusion.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (33)"))
                applied.append(33)
            if 34 not in versions:
                from .models import BreachExposure, DataDiscoveryScan
                DataDiscoveryScan.__table__.create(conn, checkfirst=True)
                BreachExposure.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # vulnerabilities.remediation, devices.exposure_flags
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (34)"))
                applied.append(34)
            if 35 not in versions:
                from .models import M365Partner, M365StandardRun
                M365Partner.__table__.create(conn, checkfirst=True)
                M365StandardRun.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (35)"))
                applied.append(35)
            if 36 not in versions:
                from .models import NetworkNode, NetworkSubnet
                NetworkSubnet.__table__.create(conn, checkfirst=True)
                NetworkNode.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (36)"))
                applied.append(36)
            if 37 not in versions:
                from .models import ConditionPackage, ConditionResult
                ConditionPackage.__table__.create(conn, checkfirst=True)
                ConditionResult.__table__.create(conn, checkfirst=True)
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (37)"))
                applied.append(37)
            if 38 not in versions:
                ensure_columns(Base, conn)  # psa_tickets.ai_triage
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (38)"))
                applied.append(38)
            if 39 not in versions:
                from .models import AccountingConnection
                AccountingConnection.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # billing_invoices.external_*
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (39)"))
                applied.append(39)
            if 40 not in versions:
                from .models import AmtEndpoint
                AmtEndpoint.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # remote_sessions.target_*
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (40)"))
                applied.append(40)
            if 41 not in versions:
                from .models import Vendor, VendorAssessment
                Vendor.__table__.create(conn, checkfirst=True)
                VendorAssessment.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # grc_evidence.data / control_id
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (41)"))
                applied.append(41)
            if 42 not in versions:
                ensure_columns(Base, conn)  # m365_partners.settings
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (42)"))
                applied.append(42)
            if 43 not in versions:
                ensure_columns(Base, conn)  # elevation_requests: temporary admin account, kind, target, timeline
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (43)"))
                applied.append(43)
            if 44 not in versions:
                from .models import BackgroundJob, CustomField, SavedView
                BackgroundJob.__table__.create(conn, checkfirst=True)
                SavedView.__table__.create(conn, checkfirst=True)
                CustomField.__table__.create(conn, checkfirst=True)
                ensure_columns(Base, conn)  # alerts: assignee/acknowledged/snoozed; devices, psa_tickets: custom_fields
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (44)"))
                applied.append(44)
            if 45 not in versions:
                # "awaiting_authorisation" did not fit VARCHAR(20): PostgreSQL refused every new Xero connection.
                if conn.dialect.name == "postgresql":
                    conn.execute(text("ALTER TABLE accounting_connections ALTER COLUMN status TYPE VARCHAR(40)"))
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (45)"))
                applied.append(45)
            if 46 not in versions:
                ensure_columns(Base, conn)  # background_jobs.running_since
                # Retention purges select events by age alone and keep events a detection rule matched.
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_time ON events (occurred_at)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_rule_matches_event ON rule_matches (event_pk)"))
                conn.execute(text("INSERT INTO schema_migrations (version) VALUES (46)"))
                applied.append(46)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return applied
