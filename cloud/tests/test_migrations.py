from sqlalchemy import create_engine, inspect, text

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
