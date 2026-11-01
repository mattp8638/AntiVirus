from sqlalchemy import create_engine, inspect, text
import pytest

from fenrir_cloud import db as database
from fenrir_cloud import models  # noqa: F401 - registers every table


def test_ensure_columns_adds_new_nullable_columns(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        # A psa_tickets table as the previous release created it (a subset of today's columns).
        conn.execute(text("CREATE TABLE psa_tickets (id VARCHAR(32) PRIMARY KEY, number INTEGER, tenant_id VARCHAR(32), "
                          "subject VARCHAR(300), status VARCHAR(30))"))
        conn.execute(text("INSERT INTO psa_tickets (id, number, tenant_id, subject, status) VALUES ('tkt_1', 1001, 't', 'Old', 'Open')"))
    added = database.ensure_columns(database.Base, engine)
    columns = {c["name"] for c in inspect(engine).get_columns("psa_tickets")}
    assert {"board_id", "impact", "urgency", "respond_due_at", "workflow_fired"} <= columns
    assert "psa_tickets.board_id" in added
    with engine.connect() as conn:
        assert conn.execute(text("SELECT subject FROM psa_tickets")).scalar() == "Old"
    # Running again is a no-op.
    assert database.ensure_columns(database.Base, engine) == []


@pytest.mark.parametrize("before_phase1", [True, False])
def test_existing_device_database_recovers_missing_required_build_column(client, admin, tenant, device, before_phase1):
    """Exercise an upgrade with enrolled rows, not create_all on an empty DB."""
    with database.engine().begin() as conn:
        conn.execute(text("ALTER TABLE devices DROP COLUMN agent_build"))
        # Both a pre-Phase-1 schema and an already recorded broken migration 24
        # must be repaired, without rewriting or replaying applied migrations.
        conn.execute(text("DELETE FROM schema_migrations WHERE version >= :first"), {"first": 24 if before_phase1 else 29})
    applied = database.migrate(database.engine())
    assert 29 in applied
    columns = {c["name"]: c for c in inspect(database.engine()).get_columns("devices")}
    assert "agent_build" in columns and columns["agent_build"]["nullable"] is False
    with database.engine().connect() as conn:
        assert conn.execute(text("SELECT agent_build FROM devices WHERE id=:id"), {"id": device["deviceId"]}).scalar_one() == ""
    for path in ("devices", f"devices/{device['deviceId']}", "dashboard", "rmm/overview", "rmm/monitoring",
                 "rmm/patches", "rmm/patches/compliance", f"reports/executive?tenant_id={tenant['id']}"):
        response = client.get(f"/api/console/{path}", headers=admin)
        assert response.status_code == 200, (path, response.text)
    assert database.migrate(database.engine()) == []


def test_repair_migration_keeps_reported_builds(client, device):
    with database.engine().begin() as conn:
        conn.execute(text("UPDATE devices SET agent_build='known-build' WHERE id=:id"), {"id": device["deviceId"]})
        conn.execute(text("DELETE FROM schema_migrations WHERE version=29"))
    assert database.migrate(database.engine()) == [29]
    with database.engine().connect() as conn:
        assert conn.execute(text("SELECT agent_build FROM devices WHERE id=:id"), {"id": device["deviceId"]}).scalar_one() == "known-build"
