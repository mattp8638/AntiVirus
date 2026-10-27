from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.orm import Session

from fenrir_cloud import db as database, events, ratelimit
from fenrir_cloud.models import PlatformEvent, RateLimitBucket


def test_shared_rate_limit_concurrent_connections_and_restart(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'limits.db'}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    RateLimitBucket.__table__.create(engine)
    monkeypatch.setattr(ratelimit, "engine", lambda: engine)
    barrier = Barrier(12)

    def attempt(_):
        barrier.wait()
        try:
            ratelimit.check("same-account", 5, 300)
            return True
        except HTTPException as exc:
            assert exc.status_code == 429
            return False

    with ThreadPoolExecutor(max_workers=12) as pool:
        assert sum(pool.map(attempt, range(12))) == 5
    engine.dispose()
    engine = create_engine(url)
    with pytest.raises(HTTPException) as blocked:
        ratelimit.check("same-account", 5, 300)
    assert blocked.value.status_code == 429
    ratelimit.check("another-account", 5, 300)
    engine.dispose()


def test_event_claims_serialize_workers_and_rollback(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'events.db'}", connect_args={"check_same_thread": False})
    PlatformEvent.__table__.create(engine)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE effects (id INTEGER PRIMARY KEY, calls INTEGER NOT NULL)"))
        conn.execute(text("INSERT INTO effects VALUES (1, 0)"))
    kind = "test.concurrent.claim"

    @events.handler(kind, name=kind)
    def effect(db, row):
        db.execute(text("UPDATE effects SET calls = calls + 1 WHERE id = 1"))

    try:
        with Session(engine) as db:
            events.publish(db, kind, {}, key="concurrent-1")
            db.commit()
        barrier = Barrier(2)

        def process(_):
            barrier.wait(timeout=10)
            with Session(engine) as db:
                attempted = events.process(db)
                db.commit()
                return attempted

        with ThreadPoolExecutor(max_workers=2) as pool:
            assert sum(pool.map(process, range(2))) == 1
        with Session(engine) as db:
            assert db.scalar(text("SELECT calls FROM effects")) == 1
            events.publish(db, kind, {}, key="rollback-1")
            db.commit()
            assert events.process(db) == 1
            db.rollback()
            assert db.scalar(text("SELECT calls FROM effects")) == 1
            assert events.process(db) == 1
            db.commit()
            assert db.scalar(text("SELECT calls FROM effects")) == 2
            with pytest.raises(ValueError):
                events.publish(db, kind, {}, key="x" * 201)
    finally:
        events._handlers.pop(kind, None)
        engine.dispose()


def test_versioned_upgrade_preserves_legacy_rows_and_is_repeatable(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE psa_tickets (id VARCHAR(32) PRIMARY KEY, subject VARCHAR(300))"))
        conn.execute(text("INSERT INTO psa_tickets VALUES ('legacy', 'Keep me')"))
    assert database.migrate(engine) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    assert database.migrate(engine) == []
    with engine.connect() as conn:
        assert conn.scalar(text("SELECT subject FROM psa_tickets WHERE id = 'legacy'")) == "Keep me"
        assert list(conn.execute(text("SELECT version FROM schema_migrations ORDER BY version")).scalars()) == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    engine.dispose()


def test_vault_strict_key_configuration_and_legacy_retirement(client, monkeypatch, tmp_path):
    import base64
    import os
    from fenrir_cloud import crypto

    legacy = crypto.encrypt("legacy-secret", "tenant:record")
    monkeypatch.setenv("FENRIR_VAULT_REQUIRE_EXPLICIT_KEY", "true")
    monkeypatch.delenv("FENRIR_VAULT_KEY", raising=False)
    monkeypatch.delenv("FENRIR_VAULT_KEY_FILE", raising=False)
    with pytest.raises(ValueError, match="explicit"):
        crypto.key_status()
    key = base64.b64encode(os.urandom(32)).decode()
    key_file = tmp_path / "vault.key"
    key_file.write_text(key)
    monkeypatch.setenv("FENRIR_VAULT_KEY_FILE", str(key_file))
    assert crypto.key_status()["source"] == "file"
    rotated = crypto.rewrap(legacy, "tenant:record")
    monkeypatch.setenv("FENRIR_VAULT_ALLOW_DERIVED_LEGACY", "false")
    with pytest.raises(crypto.VaultError):
        crypto.decrypt(legacy, "tenant:record")
    assert crypto.decrypt(rotated, "tenant:record") == "legacy-secret"
    assert not crypto.key_status()["legacyDerivedKeyAccepted"]
    monkeypatch.setenv("FENRIR_VAULT_KEY", key + "!")
    with pytest.raises(ValueError):
        crypto.key_status()


def test_newer_schema_is_rejected_without_changing_data(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'future.db'}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMP)"))
        conn.execute(text("INSERT INTO schema_migrations (version) VALUES (999)"))
    with pytest.raises(RuntimeError, match="newer"):
        database.migrate(engine)
    with engine.connect() as conn:
        assert list(conn.execute(text("SELECT version FROM schema_migrations")).scalars()) == [999]
    engine.dispose()


def test_msp_admin_cannot_reset_platform_admin_mfa(client, admin):
    from conftest import ADMIN_PASSWORD, login
    target = client.get("/api/console/auth/me", headers=admin).json()["user"]
    created = client.post("/api/console/users", headers=admin,
                          json={"email": "msp-admin@example.com", "password": ADMIN_PASSWORD, "role": "msp_admin"})
    assert created.status_code == 200
    staff = login(client, "msp-admin@example.com")
    proof = client.post("/api/console/auth/reauth", headers=staff,
                        json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    denied = client.post(f"/api/console/users/{target['id']}/mfa/reset",
                         headers={**staff, "X-Fenrir-Reauth": proof})
    assert denied.status_code == 403
    assert "platform admins" in denied.json()["detail"]


def test_concurrent_migration_startup_applies_versions_once(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'startup.db'}", connect_args={"check_same_thread": False})
    barrier = Barrier(2)

    def upgrade(_):
        barrier.wait()
        return database.migrate(engine)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(upgrade, range(2)))
    assert sorted(results) == [[], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]]
    engine.dispose()

def test_version_two_upgrade_preserves_existing_documents_and_devices(tmp_path):
    from fenrir_cloud.models import (Tenant, KbArticle, Device, DocumentRevision, VaultCredential,
        M365Connection, NetworkMonitor, GovernanceRecord, BackupPlan, BackupRun,
        RecoveryExercise, IncidentEvidence, AlertSuppression)
    added = {model.__table__ for model in (DocumentRevision, VaultCredential, M365Connection,
        NetworkMonitor, GovernanceRecord, BackupPlan, BackupRun, RecoveryExercise, IncidentEvidence, AlertSuppression)}
    engine = create_engine(f"sqlite:///{tmp_path / 'version-two.db'}")
    database.Base.metadata.create_all(engine, tables=[table for table in database.Base.metadata.sorted_tables if table not in added and table.name not in {"schema_migrations", "m365_actions", "crm_opportunities", "crm_activities", "device_artifacts"}])
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO schema_migrations (version) VALUES (1), (2)"))
    with Session(engine) as db:
        tenant = Tenant(id="existing", name="Existing customer", slug="existing")
        db.add(tenant); db.flush()
        db.add(KbArticle(id="existing-doc", tenant_id=tenant.id, title="Preserve", body="Existing runbook"))
        db.add(Device(id="existing-device", tenant_id=tenant.id, hostname="Keep host", api_key_hash="keep-key-hash", dns_token="keep-token"))
        db.commit()
    assert database.migrate(engine) == [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    assert database.migrate(engine) == []
    from sqlalchemy import inspect
    assert {table.name for table in added}.issubset(inspect(engine).get_table_names())
    with Session(engine) as db:
        assert db.get(KbArticle, "existing-doc").body == "Existing runbook"
        assert db.get(Device, "existing-device").api_key_hash == "keep-key-hash"
        assert db.get(Device, "existing-device").dns_token == "keep-token"
    engine.dispose()


def test_upgrade_adds_columns_new_since_the_database_was_created(tmp_path):
    """A database migrated to version 5 before devices.patch_window_run existed must gain it."""
    engine = create_engine(f"sqlite:///{tmp_path / 'v5.db'}")
    database.migrate(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE devices DROP COLUMN patch_window_run"))
        conn.execute(text("DELETE FROM schema_migrations WHERE version >= 6"))
    assert database.migrate(engine) == [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    with engine.connect() as conn:
        columns = [row[1] for row in conn.execute(text("PRAGMA table_info(devices)"))]
    assert "patch_window_run" in columns
    engine.dispose()
