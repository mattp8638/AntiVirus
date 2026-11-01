from starlette.testclient import TestClient

from fenrir_cloud import db as database, platform_security
from fenrir_cloud.security import totp_code

from conftest import ADMIN_PASSWORD


def _stepup(client, headers):
    proof = client.post("/api/console/auth/reauth", headers=headers, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    return {**headers, "X-Fenrir-Reauth": proof}


def _require_mfa(on: bool) -> None:
    with database.session_factory()() as db:
        platform_security.save(db, {"requireMfa": on})
        db.commit()


def test_staff_without_mfa_can_only_enrol_until_they_do(client, admin):
    _require_mfa(True)
    blocked = client.get("/api/console/devices", headers=admin)
    assert blocked.status_code == 403 and blocked.headers["X-Fenrir-Mfa-Setup"] == "required"
    assert client.get("/api/console/auth/me", headers=admin).json()["mfaSetupRequired"] is True
    setup = client.post("/api/console/auth/mfa/setup", headers=admin).json()
    assert client.post("/api/console/auth/mfa/enable", headers=admin, json={"code": totp_code(setup["secret"])}).status_code == 200
    assert client.get("/api/console/devices", headers=admin).status_code == 200
    assert client.get("/api/console/auth/me", headers=admin).json()["mfaSetupRequired"] is False
    # While it is required, MFA cannot simply be switched off again.
    refused = client.post("/api/console/auth/mfa/disable", headers=admin,
                          json={"password": ADMIN_PASSWORD, "code": totp_code(setup["secret"])})
    assert refused.status_code == 409


def test_login_says_mfa_setup_is_needed_and_the_setting_needs_a_fresh_password(client, admin):
    assert client.put("/api/console/platform/security", headers=admin, json={"requireMfa": True}).status_code == 403
    saved = client.put("/api/console/platform/security", headers=_stepup(client, admin), json={"requireMfa": True}).json()
    assert saved["requireMfa"] is True and "admin@fenrir.local" in saved["staffWithoutMfa"]
    login = client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD}).json()
    assert login["mfaSetupRequired"] is True


def test_console_networks_limit_staff_but_not_agents(client, admin, device):
    office = TestClient(client.app, client=("203.0.113.7", 50000))
    token = office.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD}).json()["token"]
    office_admin = {"Authorization": f"Bearer {token}"}
    elsewhere = TestClient(client.app, client=("198.51.100.9", 50000))

    # Never a list that would lock out the administrator saving it.
    lockout = office.put("/api/console/platform/security", headers=_stepup(office, office_admin),
                         json={"consoleAllowedNetworks": ["192.0.2.0/24"]})
    assert lockout.status_code == 400 and "lock yourself out" in lockout.json()["detail"]
    assert office.put("/api/console/platform/security", headers=_stepup(office, office_admin),
                      json={"consoleAllowedNetworks": ["not-a-network"]}).status_code == 400
    saved = office.put("/api/console/platform/security", headers=_stepup(office, office_admin),
                       json={"consoleAllowedNetworks": ["203.0.113.0/24"]})
    assert saved.status_code == 200 and saved.json()["consoleAllowedNetworks"] == ["203.0.113.0/24"]

    assert office.get("/api/console/devices", headers=office_admin).status_code == 200
    assert elsewhere.get("/api/console/devices", headers=office_admin).status_code == 403  # a stolen token, used elsewhere
    denied = elsewhere.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD})
    assert denied.status_code == 403 and "not allowed from this network" in denied.json()["detail"]
    # Agents are not staff: they keep working from anywhere.
    beat = elsewhere.post(f"/api/v1/devices/{device['deviceId']}/heartbeat", headers=device["headers"], json={})
    assert beat.status_code == 200


def test_ip_allow_list_matching():
    assert platform_security.ip_allowed([], "anything")
    assert platform_security.ip_allowed(["10.0.0.0/8", "2001:db8::/32"], "10.20.30.40")
    assert platform_security.ip_allowed(["2001:db8::/32"], "2001:db8::1")
    assert not platform_security.ip_allowed(["10.0.0.0/8"], "11.0.0.1")
    assert not platform_security.ip_allowed(["10.0.0.0/8"], "testclient")
    assert platform_security.validate_networks(["10.1.2.3/8", "10.0.0.0/8", " 192.0.2.5 "]) == ["10.0.0.0/8", "192.0.2.5/32"]


def test_emergency_stop_cancels_queued_work_and_lets_only_containment_through(client, admin, device):
    queue = lambda kind, **extra: client.post(f"/api/console/devices/{device['deviceId']}/commands", headers=admin,
                                              json={"type": kind, "reason": "test", **extra})
    assert queue("inventory.refresh").status_code == 200
    assert client.post("/api/console/platform/emergency-stop", headers=admin, json={"active": True}).status_code == 400
    stop = client.post("/api/console/platform/emergency-stop", headers=admin,
                       json={"active": True, "reason": "Technician account phished"}).json()
    assert stop["active"] is True and stop["commandsCancelled"] == 1
    assert client.get("/api/console/auth/me", headers=admin).json()["emergencyStop"]["reason"] == "Technician account phished"

    refused = queue("inventory.refresh")
    assert refused.status_code >= 400 and "emergency stop is on" in refused.text
    assert queue("device.isolate").status_code == 200  # containment still goes out
    pending = client.get(f"/api/v1/devices/{device['deviceId']}/commands/pending", headers=device["headers"]).json()["items"]
    assert [c["type"] for c in pending] == ["device.isolate"]

    # Lifting it needs a fresh password check; afterwards, normal work resumes.
    assert client.post("/api/console/platform/emergency-stop", headers=admin, json={"active": False}).status_code == 403
    lifted = client.post("/api/console/platform/emergency-stop", headers=_stepup(client, admin), json={"active": False}).json()
    assert lifted["active"] is False
    assert queue("inventory.refresh").status_code == 200
    assert client.get("/api/console/auth/me", headers=admin).json()["emergencyStop"] is None
    actions = [e["action"] for e in client.get("/api/console/audit", headers=admin).json()]
    assert "platform.emergency_stop_on" in actions and "platform.emergency_stop_off" in actions
