"""AV-21: file integrity monitoring and container runtime posture, from agent command to cloud baseline and alerts."""
from conftest import enroll
from fenrir_cloud import db as database, workload
from fenrir_cloud.models import Alert, Command, Device, FimBaseline

URL = "/api/console/workload"
SHADOW = {"path": "/etc/shadow", "sha256": "a" * 64, "size": 900, "mode": "-rw-r-----", "uid": 0, "gid": 42, "mtime": 1}
HOSTS = {"path": "/etc/hosts", "sha256": "b" * 64, "size": 200, "mode": "-rw-r--r--", "uid": 0, "gid": 0, "mtime": 1}


def linux(client, admin, tenant, name="srv-01"):
    dev = enroll(client, admin, tenant, hostname=name, os_version="Ubuntu 24.04")
    with database.session_factory()() as db:
        db.get(Device, dev["deviceId"]).platform = "linux"
        db.commit()
    return dev


def complete(command_id, result):
    with database.session_factory()() as db:
        cmd = db.get(Command, command_id)
        cmd.status, cmd.result = "completed", result
        workload.on_command_complete(db, db.get(Device, cmd.device_id), cmd)
        db.commit()


def scan(client, admin, dev, kind):
    r = client.post(f"{URL}/devices/{dev['deviceId']}/scan", headers=admin, json={"kind": kind})
    assert r.status_code == 200, r.text
    return r.json()["commandId"]


def test_fim_baseline_changes_alert_and_accept(client, admin, tenant):
    dev = linux(client, admin, tenant)
    client.put(f"{URL}/settings/{tenant['id']}", headers=admin, json={"fim": True, "paths": ["/etc/shadow", "/etc/hosts"]})
    cmd = scan(client, admin, dev, "fim")
    with database.session_factory()() as db:
        assert db.get(Command, cmd).payload == {"paths": ["/etc/shadow", "/etc/hosts"]}
    complete(cmd, {"files": [SHADOW, HOSTS]})
    state = client.get(f"{URL}/devices/{dev['deviceId']}", headers=admin).json()
    assert state["baseline"]["files"] == 2 and state["reports"][0]["findings"] == [{"change": "baseline", "files": 2}]

    # /etc/shadow changes and a new file appears: one high-severity alert naming the changes.
    complete(scan(client, admin, dev, "fim"), {"files": [{**SHADOW, "sha256": "c" * 64, "size": 950}, HOSTS,
                                                         {"path": "/etc/ld.so.preload", "sha256": "d" * 64, "size": 20}]})
    state = client.get(f"{URL}/devices/{dev['deviceId']}", headers=admin).json()
    findings = state["reports"][0]["findings"]
    assert {(f["path"], f["change"]) for f in findings} == {("/etc/shadow", "changed"), ("/etc/ld.so.preload", "added")}
    shadow = next(f for f in findings if f["path"] == "/etc/shadow")
    assert {x["field"] for x in shadow["fields"]} == {"sha256", "size"}
    with database.session_factory()() as db:
        alert = db.query(Alert).filter_by(rule_id=workload.ALERT_FIM).one()
        assert alert.severity == "high" and alert.device_id == dev["deviceId"]
    # Accepting makes the latest scan the baseline and resolves the alert; the same files then raise nothing.
    assert client.post(f"{URL}/devices/{dev['deviceId']}/accept-baseline", headers=admin).json()["files"] == 3
    complete(scan(client, admin, dev, "fim"), {"files": [{**SHADOW, "sha256": "c" * 64, "size": 950}, HOSTS,
                                                         {"path": "/etc/ld.so.preload", "sha256": "d" * 64, "size": 20}]})
    with database.session_factory()() as db:
        assert db.query(Alert).filter_by(rule_id=workload.ALERT_FIM, status="new").count() == 0
        assert len(db.query(FimBaseline).one().manifest) == 3


def test_container_posture_alerts_on_privileged_and_host_mounts(client, admin, tenant):
    dev = linux(client, admin, tenant)
    cmd = scan(client, admin, dev, "containers")
    complete(cmd, {"runtime": "docker", "containers": [
        {"name": "web", "image": "nginx:1.25", "risks": []},
        {"name": "agent", "image": "tool:latest", "risks": ["privileged", "runs as root", "mounts host /var/run/docker.sock"]},
        {"name": "job", "image": "busybox", "risks": ["runs as root"]}]})
    state = client.get(f"{URL}/devices/{dev['deviceId']}", headers=admin).json()
    assert [f["container"] for f in state["reports"][0]["findings"]] == ["agent", "job"]
    with database.session_factory()() as db:
        alerts = db.query(Alert).filter_by(rule_id=workload.ALERT_CONTAINER).all()
        assert len(alerts) == 1 and "agent" in alerts[0].title and "privileged" in alerts[0].title


def test_windows_is_refused_and_scheduler_runs_when_enabled(client, admin, tenant):
    win = enroll(client, admin, tenant, hostname="win-01")
    r = client.post(f"{URL}/devices/{win['deviceId']}/scan", headers=admin, json={"kind": "fim"})
    assert r.status_code == 400 and "Linux and macOS" in r.json()["detail"]
    dev = linux(client, admin, tenant, "srv-02")
    with database.session_factory()() as db:
        assert workload.tick(db) == 0
    client.put(f"{URL}/settings/{tenant['id']}", headers=admin, json={"fim": True, "containers": True})
    with database.session_factory()() as db:
        assert workload.tick(db) == 2
        assert {c.type for c in db.query(Command).filter_by(device_id=dev["deviceId"]).all()} >= {"fim.scan", "container.inventory"}
