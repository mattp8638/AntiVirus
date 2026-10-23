"""OS-specific deployment regression tests: no unauthorised downloads or phantom tokens."""
import hashlib
import io
import zipfile

from fenrir_cloud import deployment_installers as installers
from fenrir_cloud.db import get_db
from fenrir_cloud.models import EnrollmentToken
from sqlalchemy import select


def _request(client, tenant_id, os_name):
    return client.post("/api/console/enrollment-installers", json={
        "tenantId": tenant_id, "label": "Pilot", "os": os_name,
        "expiresInDays": 14,
    })


def test_linux_installer_is_authenticated_customer_bound_and_persistent(client, admin, tenant, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    for arch in ("amd64", "arm64"):
        (tmp_path / f"fenrir-agent-linux-{arch}").write_bytes(b"linux-test-binary-" + arch.encode())
    unauthorised = _request(client, tenant["id"], "linux")
    assert unauthorised.status_code == 401
    result = client.post("/api/console/enrollment-installers", headers=admin, json={
        "tenantId": tenant["id"], "os": "linux", "label": "Pilot", "expiresInDays": 14
    })
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"].startswith("private, no-store")
    assert "Install-Fenrir-Linux.sh" in result.headers["content-disposition"]
    script = result.content.decode()
    assert "systemctl enable fenrir-agent" in script
    assert "systemctl restart fenrir-agent" in script
    assert "chmod 600 /etc/fenrir/agent.env" in script
    assert "fenrir.test/downloads/fenrir-agent-linux-$arch" in script
    assert "fet_" in script
    assert hashlib.sha256((tmp_path / "fenrir-agent-linux-amd64").read_bytes()).hexdigest() in script
    tokens = client.get("/api/console/enrollment-tokens", headers=admin).json()
    assert any(t["tenantId"] == tenant["id"] and t["label"] == "Pilot" for t in tokens)
    assert all("token" not in t or t["token"] is None for t in tokens)


def test_missing_artifact_and_macos_do_not_create_credentials(client, admin, tenant, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    before = len(client.get("/api/console/enrollment-tokens", headers=admin).json())
    for os_name in ("linux", "windows", "macos"):
        resp = client.post("/api/console/enrollment-installers", headers=admin, json={
            "tenantId": tenant["id"], "os": os_name, "expiresInDays": 30,
        })
        assert resp.status_code == 409
    after = len(client.get("/api/console/enrollment-tokens", headers=admin).json())
    assert before == after
    status = client.get("/api/console/enrollment-installers/status", headers=admin).json()
    assert not status["windows"]["ready"] and not status["linux"]["ready"] and not status["macos"]["ready"]


def test_windows_bundle_includes_checked_setup_and_customer_enrollment(client, admin, tenant, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    monkeypatch.setenv("FENRIR_WINDOWS_SIGNER_THUMBPRINT", "a" * 40)
    (tmp_path / "releases").mkdir()
    binary = b"MZ" + b"test-only-unsigned-fixture"
    (tmp_path / "releases" / "FenrirSetup.exe").write_bytes(binary)
    response = client.post("/api/console/enrollment-installers", headers=admin, json={
        "tenantId": tenant["id"], "os": "windows", "expiresInDays": 3,
    })
    assert response.status_code == 200, response.text
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {"FenrirSetup.exe", "Install-Fenrir.ps1", "README.txt"}
        assert archive.read("FenrirSetup.exe") == binary
        powershell = archive.read("Install-Fenrir.ps1").decode()
        assert hashlib.sha256(binary).hexdigest().upper() in powershell
        assert ("a" * 40).upper() in powershell
        assert "fet_" in powershell
        assert "Get-AuthenticodeSignature" in powershell
        assert "Get-Service -Name 'FenrirAgent'" in powershell


def test_invalid_target_and_expiry_are_rejected(client, admin, tenant):
    bad = [
        {"tenantId": tenant["id"], "os": "bad-os", "expiresInDays": 20},
        {"tenantId": "not-a-tenant", "os": "linux", "expiresInDays": 20},
        {"tenantId": tenant["id"], "os": "linux", "expiresInDays": 0},
        {"tenantId": tenant["id"], "os": "linux", "expiresInDays": 366},
    ]
    for request in bad:
        response = client.post("/api/console/enrollment-installers", headers=admin, json=request)
        assert response.status_code in (404, 422)
