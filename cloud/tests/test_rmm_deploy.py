"""Deployment from an existing RMM, Group Policy or Intune: scripts, token-header downloads and the MSI."""

import hashlib
import json
import shutil
import subprocess
from datetime import timedelta

import pytest

from conftest import login
from fenrir_cloud import db as database, deployment_installers as installers, rmm_deploy
from fenrir_cloud.models import EnrollmentToken, utcnow


def _windows_build(tmp_path, monkeypatch):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    (tmp_path / "windows").mkdir()
    binary = b"MZ" + b"automatically-built-test-fixture"
    (tmp_path / "windows" / "FenrirSetup.exe").write_bytes(binary)
    (tmp_path / "windows" / "build.json").write_text(json.dumps({"sha256": hashlib.sha256(binary).hexdigest()}))
    return binary


def _deployment(client, admin, tenant, **extra):
    response = client.post("/api/console/deploy-scripts", headers=admin, json={"tenantId": tenant["id"], "label": "Itarian rollout", **extra})
    assert response.status_code == 200, response.text
    return response.json()


def test_scripts_are_idempotent_and_carry_the_token_in_a_header(client, admin, tenant):
    made = _deployment(client, admin, tenant)
    ps, sh = made["windowsPowerShell"], made["unixShell"]
    token = made["token"]
    assert token.startswith("fet_") and token in ps and token in sh
    # Already installed: nothing happens. Results are exit codes an RMM understands.
    assert "Get-Service -Name FenrirAgent" in ps and "exit 0" in ps and "exit 1" in ps and "--quiet" in ps
    assert "X-Fenrir-Token" in ps and "?token=" not in ps and "/api/v1/install/windows.exe" in ps
    assert "systemctl is-active --quiet fenrir-agent" in sh and "X-Fenrir-Token: $TOKEN" in sh
    assert "Itarian rollout (Acme Dental)" in ps and "Expires" in ps
    with database.session_factory()() as session:
        row = session.get(EnrollmentToken, made["id"])
        assert row.max_uses is None and row.expires_at > utcnow() + timedelta(days=89)  # one token, many devices
    if shutil.which("sh"):
        assert subprocess.run(["sh", "-n"], input=sh, text=True).returncode == 0  # the shell script parses


def test_powershell_quoting_survives_awkward_names(client, admin):
    odd = client.post("/api/console/tenants", headers=admin, json={"name": "O'Brien & Sons", "template": "balanced"}).json()
    ps = _deployment(client, admin, odd, label="Bob's rollout")["windowsPowerShell"]
    assert "$Server = 'https://fenrir.test'" in ps
    assert "Bob's rollout (O'Brien & Sons)" in ps.splitlines()[0]  # comment line only; values are single-quoted


def test_downloads_need_a_live_token_in_the_header(client, admin, tenant, monkeypatch, tmp_path):
    binary = _windows_build(tmp_path, monkeypatch)
    token = _deployment(client, admin, tenant)["token"]
    assert client.get("/api/v1/install/windows.exe").status_code == 401
    assert client.get("/api/v1/install/windows.exe", params={"token": token}).status_code == 401  # never in the URL
    assert client.get("/api/v1/install/windows.exe", headers={"X-Fenrir-Token": "fet_wrong"}).status_code == 403
    exe = client.get("/api/v1/install/windows.exe", headers={"X-Fenrir-Token": token})
    assert exe.status_code == 200 and exe.content.startswith(binary) and exe.content.endswith(installers.WINDOWS_CONFIG_MAGIC)
    assert token.encode() in exe.content
    # Downloading does not use up the token (enrolment does); revoking it stops downloads.
    with database.session_factory()() as session:
        row = session.query(EnrollmentToken).filter(EnrollmentToken.label == "Itarian rollout").one()
        assert row.uses == 0
        row.revoked = True
        session.commit()
    assert client.get("/api/v1/install/windows.exe", headers={"X-Fenrir-Token": token}).status_code == 403


def test_expired_tokens_cannot_download(client, admin, tenant, monkeypatch, tmp_path):
    _windows_build(tmp_path, monkeypatch)
    made = _deployment(client, admin, tenant)
    with database.session_factory()() as session:
        session.get(EnrollmentToken, made["id"]).expires_at = utcnow() - timedelta(minutes=1)
        session.commit()
    assert client.get("/api/v1/install/windows.exe", headers={"X-Fenrir-Token": made["token"]}).status_code == 403


def test_only_configurers_of_that_customer_create_deployments(client, admin, tenant):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ops@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    ops = login(client, "ops@acme.example", "acme-password-123")
    assert client.post("/api/console/deploy-scripts", headers=ops, json={"tenantId": other["id"]}).status_code == 404
    assert client.post("/api/console/deploy-scripts", headers=ops, json={"tenantId": tenant["id"]}).status_code == 200
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "view@acme.example",
                                                           "password": "acme-password-123", "role": "viewer"})
    viewer = login(client, "view@acme.example", "acme-password-123")
    assert client.post("/api/console/deploy-scripts", headers=viewer, json={"tenantId": tenant["id"]}).status_code == 403
    for days in (0, 400, "soon"):
        assert client.post("/api/console/deploy-scripts", headers=admin, json={"tenantId": tenant["id"], "expiresInDays": days}).status_code == 422


@pytest.mark.skipif(shutil.which("wixl") is None, reason="needs msitools (wixl)")
def test_msi_installs_the_customer_setup_and_runs_it_quietly(client, admin, tenant, monkeypatch, tmp_path):
    _windows_build(tmp_path, monkeypatch)
    made = _deployment(client, admin, tenant)
    msi = client.get("/api/v1/install/windows.msi", headers={"X-Fenrir-Token": made["token"]})
    assert msi.status_code == 200 and msi.content[:8] == bytes.fromhex("d0cf11e0a1b11ae1")  # an MSI (OLE compound file)
    path = tmp_path / "FenrirAgent.msi"
    path.write_bytes(msi.content)
    action = subprocess.run(["msiinfo", "export", str(path), "CustomAction"], capture_output=True, text=True).stdout
    assert "RunFenrirSetup\t3090\tFenrirSetupExe\t--quiet" in action  # deferred, as SYSTEM, from the installed file
    props = subprocess.run(["msiinfo", "export", str(path), "Property"], capture_output=True, text=True).stdout
    assert "Acme Dental" in props and rmm_deploy.UPGRADE_CODE in props
    # The console route needs the token it was shown, and is audited.
    wrong = client.post(f"/api/console/deploy-scripts/{made['id']}/msi", headers=admin, json={"token": "fet_nope"})
    assert wrong.status_code == 403
    right = client.post(f"/api/console/deploy-scripts/{made['id']}/msi", headers=admin, json={"token": made["token"]})
    assert right.status_code == 200 and right.headers["content-disposition"].endswith('"FenrirAgent.msi"')
