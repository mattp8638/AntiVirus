"""CORE-06: audit checkpoints, protected export with an offline verifier, retention with legal hold, and telling a
modification or deletion apart from the old (pre-serialisation) software race."""

import importlib.util
import json
import pathlib
from datetime import timedelta

from conftest import login
from fenrir_cloud import audit
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import AuditChainHead, AuditLog, PlatformEvent, utcnow
from test_documentation_vault import stepup

ROOT = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("verify_audit_export", ROOT / "scripts" / "verify_audit_export.py")
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)


def export(client, headers):
    reply = client.get("/api/console/audit/export", headers=headers)
    assert reply.status_code == 200, reply.text
    return [json.loads(line) for line in reply.text.splitlines() if line.strip()]


def events(n, client, admin, tenant_id=None):
    for i in range(n):
        client.post("/api/console/groups", headers=admin, json={"tenantId": tenant_id, "name": f"group-{i}"} if tenant_id else {"name": f"g{i}"})


def db_session():
    return session_factory()()


def test_checkpoint_is_recorded_and_published(client, admin):
    cp = client.post("/api/console/audit/checkpoints", headers=admin, json={"reason": "quarter end"}).json()
    db = db_session()
    try:
        head = db.get(AuditChainHead, 1)
        assert cp["seq"] == head.seq and cp["hash"] == head.last_hash
        published = db.query(PlatformEvent).filter(PlatformEvent.type == "audit.checkpoint").all()
        assert published and published[-1].payload["hash"] == cp["hash"]
    finally:
        db.close()
    assert client.get("/api/console/audit/verify", headers=admin).json()["checkpoints"]["mismatched"] == []


def test_rewriting_the_whole_chain_is_caught_by_checkpoints(client, admin, tenant):
    events(3, client, admin, tenant["id"])
    cp = client.post("/api/console/audit/checkpoints", headers=admin).json()
    # An attacker with database access edits a row and recomputes every hash after it, so the links all look right.
    db = db_session()
    try:
        rows = db.query(AuditLog).order_by(AuditLog.seq).all()
        rows[1].actor = "covered-up"
        prev = rows[0].hash
        for row in rows[1:]:
            row.prev_hash, row.hash = prev, audit._row_digest(prev, row)
            prev = row.hash
        head = db.get(AuditChainHead, 1)
        head.last_hash = prev
        db.commit()
    finally:
        db.close()
    result = client.get("/api/console/audit/verify", headers=admin).json()
    assert result["valid"] is False and result["tampered"] is True
    assert any(b["kind"] == "checkpoint" for b in result["breaks"]) and result["checkpoints"]["mismatched"][0]["seq"] == cp["seq"]
    # A checkpoint kept outside Fenrir catches it even if the attacker also edited the checkpoint table.
    lines = export(client, admin)
    lines[0]["checkpoints"] = []
    assert verifier.verify(lines, {cp["seq"]: cp["hash"]})


def test_modified_deleted_and_legacy_race_are_told_apart(client, admin, tenant):
    events(4, client, admin, tenant["id"])
    db = db_session()
    try:
        rows = db.query(AuditLog).order_by(AuditLog.seq).all()
        # Simulate the pre-fix race on the two oldest rows: same content, both chained onto the same predecessor,
        # written before migration 22 was applied.
        boundary = audit._legacy_boundary(db)
        assert boundary is not None
        for row in rows[:3]:
            row.at = boundary - timedelta(days=30)
        rows[0].prev_hash = ""
        rows[0].hash = audit._row_digest("", rows[0])
        rows[1].prev_hash = rows[0].hash
        rows[1].hash = audit._row_digest(rows[1].prev_hash, rows[1])
        rows[2].prev_hash = rows[0].hash  # the race: also chained onto row 0
        rows[2].hash = audit._row_digest(rows[2].prev_hash, rows[2])
        prev = rows[2].hash
        for row in rows[3:]:
            row.prev_hash, row.hash = prev, audit._row_digest(prev, row)
            prev = row.hash
        db.get(AuditChainHead, 1).last_hash = prev
        db.commit()
    finally:
        db.close()
    raced = client.get("/api/console/audit/verify", headers=admin).json()
    assert raced["valid"] is False and raced["tampered"] is False and raced["legacyBreaks"] == 1
    db = db_session()
    try:
        rows = db.query(AuditLog).order_by(AuditLog.seq).all()
        rows[4].details = {"edited": True}
        db.delete(rows[5])
        db.commit()
    finally:
        db.close()
    kinds = {b["kind"] for b in client.get("/api/console/audit/verify", headers=admin).json()["breaks"]}
    assert {"legacy-race", "modified", "deleted"} <= kinds


def test_tenant_export_is_redacted_and_verifies_offline(client, admin, tenant):
    events(2, client, admin, tenant["id"])
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Secret Other Co", "template": "balanced"}).json()
    events(2, client, admin, other["id"])
    client.post("/api/console/audit/checkpoints", headers=admin)
    full = export(client, admin)
    assert verifier.verify(full, {}) == []
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ta@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    mine = export(client, login(client, "ta@acme.example", "acme-password-123"))
    assert verifier.verify(mine, {}) == []
    text = json.dumps(mine)
    assert "Secret Other Co" not in text and other["id"] not in text.replace(json.dumps(mine[0]), "")
    assert any(r.get("redacted") for r in mine[1:]) and any(r.get("tenant") == tenant["id"] for r in mine[1:])
    # Changing a row's content is reported by the offline verifier.
    full[2]["actor"] = "someone-else"
    assert any("changed" in p for p in verifier.verify(full, {}))
    assert client.get("/api/console/audit/export").status_code == 401  # signed-in users only


def test_retention_prunes_to_a_checkpoint_and_respects_legal_hold(client, admin, tenant):
    events(5, client, admin, tenant["id"])
    assert client.put("/api/console/audit/policy", headers=admin, json={"retentionDays": 400}).json()["detail"] == "reauth_required"
    assert client.put("/api/console/audit/policy", headers=stepup(client, admin), json={"retentionDays": 30}).status_code == 400
    assert client.put("/api/console/audit/policy", headers=stepup(client, admin), json={"retentionDays": 400, "legalHold": True}).status_code == 400
    held = client.put("/api/console/audit/policy", headers=stepup(client, admin),
                      json={"retentionDays": 400, "legalHold": True, "holdReason": "Litigation hold, matter 2026-17"})
    assert held.status_code == 200 and held.json()["legalHold"] is True
    cp = client.post("/api/console/audit/checkpoints", headers=admin).json()
    events(2, client, admin, tenant["id"])
    db = db_session()
    try:
        for row in db.query(AuditLog).filter(AuditLog.seq <= cp["seq"]):
            row.at = utcnow() - timedelta(days=500)
        db.commit()
    finally:
        db.close()
    assert client.post("/api/console/audit/retention/apply", headers=admin).json()["pruned"] == 0  # legal hold
    client.put("/api/console/audit/policy", headers=stepup(client, admin), json={"retentionDays": 400, "legalHold": False})
    pruned = client.post("/api/console/audit/retention/apply", headers=admin).json()["pruned"]
    assert pruned == cp["seq"]
    result = client.get("/api/console/audit/verify", headers=admin).json()
    assert result["valid"] is True and result["anchor"]["seq"] == cp["seq"]
    lines = export(client, admin)
    assert lines[0]["anchor"]["seq"] == cp["seq"] and verifier.verify(lines, {}) == []
    actions = [e["action"] for e in client.get("/api/console/audit", headers=admin).json()]
    assert "audit.pruned" in actions and "audit.policy_changed" in actions
    assert client.post("/api/console/audit/retention/apply", headers=admin).json()["pruned"] == 0  # nothing new to prune
