"""Agent health: failures agents report are shown per device until the same component reports success again, and
failed commands are listed with their reason."""
import json
from datetime import timedelta

from conftest import enroll

from fenrir_cloud import db as database
from fenrir_cloud.models import AgentRollout, Command, utcnow


def report(client, admin, **params):
    response = client.get("/api/console/agent-health", headers=admin, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def event(event_type, minutes_ago, **payload):
    return {"eventId": f"{event_type}-{minutes_ago}", "eventType": event_type, "source": "rmm", "summary": event_type,
            "occurredAt": (utcnow() - timedelta(minutes=minutes_ago)).isoformat() + "Z", "payloadJson": json.dumps(payload)}


def test_reported_failures_show_until_the_component_recovers(client, admin, tenant):
    pc = enroll(client, admin, tenant, hostname="PM-HP", serial="HP-1")
    batch = [event("inventory.profile.failed", 30, error="the system profile collector timed out"),
             event("inventory.profile.failed", 20, error="the system profile collector timed out"),
             event("agent.update.failed", 10, error="signature check failed"),
             event("ransomware.shield.degraded", 15, error="VSS unavailable"),
             event("ransomware.shield.started", 5)]
    assert client.post(f"/api/v1/devices/{pc['deviceId']}/telemetry", headers=pc["headers"], json={"events": batch}).status_code == 200

    data = report(client, admin)
    [row] = [d for d in data["devices"] if d["deviceId"] == pc["deviceId"]]
    problems = {p["component"]: p for p in row["problems"]}
    assert problems["inventory.profile"]["count"] == 2 and not problems["inventory.profile"]["resolved"]
    assert problems["inventory.profile"]["error"] == "the system profile collector timed out"
    assert problems["agent.update"]["error"] == "signature check failed"
    assert problems["ransomware.shield"]["resolved"]  # it started again afterwards
    assert row["openProblems"] == 2 and data["totals"]["withProblems"] >= 1
    assert row["problems"][-1]["component"] == "ransomware.shield"  # resolved ones last

    # The profile arrives later: that problem clears.
    client.post(f"/api/v1/devices/{pc['deviceId']}/telemetry", headers=pc["headers"], json={"events": [event("inventory.profile.sent", 1)]})
    [row] = [d for d in report(client, admin)["devices"] if d["deviceId"] == pc["deviceId"]]
    assert {p["component"] for p in row["problems"] if not p["resolved"]} == {"agent.update"}


def test_failed_commands_and_stalled_rollouts_are_listed(client, admin, tenant):
    pc = enroll(client, admin, tenant, hostname="PM-DC", serial="DC-1")
    with database.session_factory()() as db:
        db.add(Command(tenant_id=tenant["id"], device_id=pc["deviceId"], type="script.run", status="failed", issued_by="admin",
                       result={"error": "Access is denied"}, updated_at=utcnow()))
        db.add(AgentRollout(platform="windows", build="abc12345", version="1.2.3", stage=1, state="paused", history=[],
                            reason="Paused automatically: PM-HP - stopped checking in after taking the update"))
        db.commit()
    data = report(client, admin)
    [row] = [d for d in data["devices"] if d["deviceId"] == pc["deviceId"]]
    assert row["failedCommands"][0]["type"] == "script.run" and row["failedCommands"][0]["error"] == "Access is denied"
    assert data["stalledRollouts"][0]["state"] == "paused" and "PM-HP" in data["stalledRollouts"][0]["reason"]


def test_scoped_to_the_customer(client, admin, tenant):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd"}).json()
    enroll(client, admin, tenant, hostname="MINE", serial="M-1")
    enroll(client, admin, other, hostname="THEIRS", serial="T-1")
    hosts = {d["hostname"] for d in report(client, admin, tenant_id=tenant["id"])["devices"]}
    assert "MINE" in hosts and "THEIRS" not in hosts


def test_defender_flagging_the_agent_raises_one_alert(client, admin, tenant):
    pc = enroll(client, admin, tenant, hostname="PM-NUC", serial="NUC-1")
    url = f"/api/v1/devices/{pc['deviceId']}/telemetry"
    flagged = event("agent.defender.flagged", 5, threat="Trojan:Win32/Wacatac.B!ml",
                    resources="file:_C:\\Program Files\\Fenrir Endpoint\\fenrir-agent-service.exe")
    assert client.post(url, headers=pc["headers"], json={"events": [flagged]}).status_code == 200
    again = dict(flagged, eventId="again")
    client.post(url, headers=pc["headers"], json={"events": [again, event("agent.defender.exclusions_refused", 4)]})
    alerts = client.get("/api/console/alerts", headers=admin, params={"device_id": pc["deviceId"]}).json()
    alerts = alerts.get("items", alerts) if isinstance(alerts, dict) else alerts
    titles = sorted(a["title"] for a in alerts if str(a.get("ruleId", a.get("rule_id", ""))).startswith("agent:defender"))
    assert titles == ["Defender ignores Fenrir's exclusions on PM-NUC", "Microsoft Defender flagged the Fenrir agent on PM-NUC"]
