"""Isolated real API for console render tests; JSON lines over stdin/stdout.

No production host, database, credentials or network services are used. Run
through the console tests, which start and stop this child process themselves.
"""
from __future__ import annotations

import dataclasses
import base64
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "cloud"), str(ROOT / "cloud/tests")]

from fastapi.testclient import TestClient
from fenrir_cloud import db, m365_admin as microsoft
from fenrir_cloud.config import Settings
from fenrir_cloud.main import create_app
from fenrir_cloud.models import DeviceArtifact, Incident, M365Connection
from test_device_profile import PROFILE


def reply(value):
    print(json.dumps(value), flush=True)


temporary = tempfile.TemporaryDirectory(prefix="fenrir-console-test-")
settings = dataclasses.replace(Settings(), database_url="sqlite://", bootstrap_admin_password="console-render-test-password",
                               secret_key="console-render-test-secret", scheduler_enabled=False,
                               feed_sync_enabled=False, vuln_intel_enabled=False, public_base_url="https://fenrir.test",
                               artifact_dir=Path(temporary.name))
# External Microsoft transport is a deterministic provider fixture. The actual
# authentication, routing, permissions and serialization still use the test API.
provider_rows = {
    "users": [{"id": "00000000-0000-0000-0000-000000000010", "displayName": "Test user", "userPrincipalName": "user@example.test", "accountEnabled": True}],
    "groups": [{"id": "00000000-0000-0000-0000-000000000020", "displayName": "Test group", "groupTypes": []}],
    "licenses": [{"skuId": "00000000-0000-0000-0000-000000000030", "skuPartNumber": "Test licence", "consumedUnits": 1, "prepaidUnits": {"enabled": 2}}],
}
microsoft.inventory = lambda connection, collection: provider_rows[collection]
from fenrir_cloud import m365_exchange as exchange  # noqa: E402  (Exchange Online, with rows shaped as Microsoft returns them)

exchange.mailboxes = lambda connection: [{"id": "mbx-1", "displayName": "Render User", "address": "render@example.test", "type": "user",
                                          "aliases": [], "forwardingTo": None, "forwardingKeepsCopy": False, "hiddenFromAddressBook": False,
                                          "litigationHold": False, "userPrincipalName": "render@example.test"}]
exchange.mailbox_detail = lambda connection, identity: {"mailbox": exchange.mailboxes(connection)[0], "fullAccess": [], "sendAs": [], "rules": []}
exchange.distribution_groups = lambda connection: []
exchange.group_members = lambda connection, group: []
exchange.quarantine = lambda connection: []
exchange.message_trace = lambda connection, sender="", recipient="", days=2: []
from fenrir_cloud import m365_intune as intune  # noqa: E402

intune.devices = lambda connection: []
intune.policies = lambda connection: {"compliance": [], "configuration": []}
intune.apps = lambda connection: []
intune.autopilot = lambda connection: []
from fenrir_cloud import m365_collaboration as collaboration  # noqa: E402

collaboration.teams = lambda connection: []
collaboration.sites = lambda connection: []
collaboration.sharing_settings = lambda connection: {"sharingCapability": "externalUserSharingOnly", "label": "Guests sign in",
                                                     "isResharingByExternalUsersEnabled": False, "sharingAllowedDomainList": [],
                                                     "sharingBlockedDomainList": []}
from fenrir_cloud import m365_reports as reports_module  # noqa: E402

reports_module.build = lambda connection, key: {"report": key, "title": key, "generatedAt": "2026-01-01T00:00:00Z",
                                                 "columns": ["name"], "rows": [{"name": "Render"}], "summary": "1 row."}
with TestClient(create_app(settings), raise_server_exceptions=False) as client:
    token = client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": settings.bootstrap_admin_password}).json()["token"]
    admin = {"Authorization": f"Bearer {token}"}

    def post(path, body, headers=None):
        response = client.post(path, headers=headers or admin, json=body)
        if response.status_code != 200:
            raise RuntimeError(f"Could not seed {path}: {response.status_code} {response.text}")
        return response.json()

    tenant = post("/api/console/tenants", {"name": "Console test customer", "template": "balanced"})
    enrollment = post("/api/console/enrollment-tokens", {"tenantId": tenant["id"], "label": "Render test"})["token"]
    device = post("/api/v1/enroll", {"hostname": "RENDER-SERVER", "osVersion": "Windows Server 2025", "serialNumber": "UI-SERVER"},
                  {"X-Fenrir-Token": enrollment})
    device_id = device["deviceId"]
    cancellation_device = post("/api/v1/enroll", {"hostname": "CANCEL-SERVER", "osVersion": "Windows Server 2025", "serialNumber": "UI-CANCEL"},
                               {"X-Fenrir-Token": enrollment})
    cancellation_job = post("/api/console/rmm/jobs", {"name": "Cancellable UI job", "commandType": "patch.scan",
                                                     "targets": {"deviceIds": [cancellation_device["deviceId"]]}})
    client.get(f"/api/v1/devices/{cancellation_device['deviceId']}/commands/pending", headers={"X-Device-Api-Key": cancellation_device["deviceApiKey"]})
    phone = post("/api/v1/enroll", {"hostname": "RENDER-PHONE", "osVersion": "Android 14", "platform": "android", "serialNumber": "UI-PHONE"},
                 {"X-Fenrir-Token": enrollment})
    post(f"/api/v1/devices/{device_id}/profile", {"profile": PROFILE}, {"X-Device-Api-Key": device["deviceApiKey"]})
    ticket = post("/api/console/tickets", {"accountTenantId": tenant["id"], "subject": "Console smoke ticket", "deviceId": device_id})
    remote = post("/api/console/remote/sessions", {"deviceId": device_id, "mode": "desktop"})
    project = post("/api/console/crm/projects", {"accountTenantId": tenant["id"], "name": "Console smoke project"})
    with db.session_factory()() as session:
        incident = Incident(tenant_id=tenant["id"], device_id=device_id, title="Console smoke incident")
        session.add(incident)
        m365_connection = M365Connection(tenant_id=tenant["id"], name="Test Microsoft tenant", directory_id="00000000-0000-0000-0000-000000000001",
                                         client_id="00000000-0000-0000-0000-000000000002", credentials_envelope={})
        session.add(m365_connection)
        content = b"FENREC1\n"
        (settings.artifact_dir / "test-recording").write_bytes(content)
        recording = DeviceArtifact(tenant_id=tenant["id"], device_id=device_id, command_id="test-command", kind="remote.recording",
                                   filename="test-session.fenrec", size=len(content), sha256=hashlib.sha256(content).hexdigest(), storage_name="test-recording")
        session.add(recording)
        session.commit()
        incident_id = incident.id
        m365_id = m365_connection.id
        recording_id = recording.id
    programme = post("/api/console/grc/programmes", {"tenantId": tenant["id"], "frameworkKey": "nist-csf-2"})
    policies = client.get("/api/console/grc/policies", headers=admin).json()
    me = client.get("/api/console/auth/me", headers=admin).json()
    if os.getenv("FENRIR_UI_TEST_LEGACY") == "true":
        # Recreate the deployed upgrade defect after seeding real records, then
        # run the repair before sweeping every console route and subpage.
        from sqlalchemy import text
        with db.engine().begin() as session:
            session.execute(text("ALTER TABLE devices DROP COLUMN agent_build"))
            session.execute(text("DELETE FROM schema_migrations WHERE version=29"))
        assert 29 in db.migrate(db.engine())
    reply({"ready": True, "me": me, "ids": {"device": device_id, "tenant": tenant["id"], "policy": tenant["defaultPolicyId"],
          "ticket": ticket["id"], "project": project["id"], "incident": incident_id,
          "grcPolicy": policies[0]["id"] if policies else "missing", "framework": "nist-csf-2", "remote": remote["id"],
          "phone": phone["deviceId"], "recording": recording_id, "m365": m365_id,
          "cancellationDevice": cancellation_device["deviceId"], "cancellationJob": cancellation_job["id"]}})
    for line in sys.stdin:
        request = json.loads(line)
        try:
            response = client.request(request.get("method", "GET"), request["path"], headers=admin,
                                      **({"json": request["body"]} if request.get("body") is not None else {}))
            reply({"id": request["id"], "status": response.status_code, "text": response.text, "headers": dict(response.headers),
                   "bytes": base64.b64encode(response.content).decode()})
        except Exception as error:
            reply({"id": request["id"], "status": 500, "text": str(error)})
temporary.cleanup()
