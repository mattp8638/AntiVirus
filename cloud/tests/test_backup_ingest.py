"""Backup tools push job results with a per-plan token; failures and overdue backups raise alerts."""
from datetime import datetime, timedelta, timezone

from conftest import ADMIN_PASSWORD

from fenrir_cloud import db as database
from fenrir_cloud.models import Alert, BackupPlan, utcnow
from fenrir_cloud.routers import backup


def _reauth(client, admin):
    proof = client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    return {**admin, "X-Fenrir-Reauth": proof}


def _alerts(plan_id):
    session = database.session_factory()()
    try:
        return [(a.title, a.status) for a in session.query(Alert).filter(Alert.rule_id == "backup:" + plan_id).order_by(Alert.created_at)]
    finally:
        session.close()


def test_backup_tool_pushes_runs_and_alerts_follow_results(client, admin, tenant):
    plan = client.post("/api/console/backup/plans", headers=admin, json={"tenantId": tenant["id"], "name": "File server",
                                                                         "provider": "Veeam", "rpoHours": 24}).json()
    assert client.post(f"/api/console/backup/plans/{plan['id']}/ingest-token", headers=admin).status_code == 403  # needs reauth
    issued = client.post(f"/api/console/backup/plans/{plan['id']}/ingest-token", headers=_reauth(client, admin)).json()
    token = issued["token"]
    assert token.startswith("fbk_") and "ingestTokenHash" not in client.get("/api/console/backup/plans", headers=admin).json()[0]

    def push(external_id, status, hours_ago, headers=None):
        when = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
        return client.post("/api/v1/backup/runs", headers=headers if headers is not None else {"X-Fenrir-Backup-Token": token},
                           json={"externalId": external_id, "status": status, "completedAt": when, "evidence": "job log"})

    assert push("job-1", "success", 1, headers={}).status_code == 401
    assert push("job-1", "success", 1, headers={"X-Fenrir-Backup-Token": "fbk_wrong"}).status_code == 401
    ok = push("job-1", "success", 3)
    assert ok.status_code == 200 and ok.json()["recordedBy"] == "backup-tool:Veeam"
    assert push("job-2", "failed", 2).status_code == 200
    assert _alerts(plan["id"]) == [("Backup failed: File server", "new")]
    assert push("job-0", "success", 30).status_code == 200  # an old run arriving late changes nothing
    assert _alerts(plan["id"]) == [("Backup failed: File server", "new")]
    push("job-3", "success", 0.5)
    assert _alerts(plan["id"]) == [("Backup failed: File server", "resolved")]
    assert client.get("/api/console/backup/plans", headers=admin).json()[0]["health"] == "protected"

    # Rotating the token retires the old one.
    client.post(f"/api/console/backup/plans/{plan['id']}/ingest-token", headers=_reauth(client, admin))
    assert push("job-4", "success", 0.1).status_code == 401


def test_overdue_backup_raises_one_alert(client, admin, tenant):
    plan = client.post("/api/console/backup/plans", headers=admin, json={"tenantId": tenant["id"], "name": "Laptops",
                                                                         "provider": "Datto", "rpoHours": 12}).json()
    session = database.session_factory()()
    try:
        session.get(BackupPlan, plan["id"]).created_at = utcnow() - timedelta(hours=13)
        session.commit()
        assert backup.health_tick(session) == 1
        assert backup.health_tick(session) == 0  # not repeated while the alert is open
        session.commit()
    finally:
        session.close()
    assert _alerts(plan["id"]) == [("Backup overdue: Laptops", "new")]
