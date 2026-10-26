"""OS-specific deployment regression tests: no unauthorised downloads or phantom tokens."""
import hashlib
import json
import struct
import shlex
import subprocess

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
    syntax = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True, check=False)
    assert syntax.returncode == 0, syntax.stderr
    assert "systemctl enable fenrir-agent" in script
    assert "systemctl restart fenrir-agent" in script
    assert "chmod 600 /etc/fenrir/agent.env" in script
    assert "base=" + shlex.quote("https://fenrir.test") in script
    assert "FENRIR_AMD64_PAYLOAD" in script
    assert "curl --fail" not in script
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


def test_macos_installer_is_customer_bound_launchdaemon(client, admin, tenant, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    for arch in ("amd64", "arm64"):
        (tmp_path / f"fenrir-agent-darwin-{arch}").write_bytes(b"macho-test-binary-" + arch.encode())
    status = client.get("/api/console/enrollment-installers/status", headers=admin).json()
    assert status["macos"]["ready"] and status["macos"]["extension"] == ".sh"
    result = client.post("/api/console/enrollment-installers", headers=admin, json={
        "tenantId": tenant["id"], "os": "macos", "label": "Mac pilot", "expiresInDays": 14,
    })
    assert result.status_code == 200, result.text
    assert "Install-Fenrir-macOS.sh" in result.headers["content-disposition"]
    script = result.content.decode()
    syntax = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True, check=False)
    assert syntax.returncode == 0, syntax.stderr
    assert "/Library/LaunchDaemons/com.fenrir.agent.plist" in script
    assert "launchctl bootstrap system" in script
    assert "shasum -a 256 -c -s" in script
    assert "fet_" in script and "Full Disk Access" in script
    for arch in ("amd64", "arm64"):
        assert hashlib.sha256((tmp_path / f"fenrir-agent-darwin-{arch}").read_bytes()).hexdigest() in script


def _windows_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    (tmp_path / "windows").mkdir()
    binary = b"MZ" + b"automatically-built-test-fixture"
    (tmp_path / "windows" / "FenrirSetup.exe").write_bytes(binary)
    (tmp_path / "windows" / "build.json").write_text(json.dumps({"sha256": hashlib.sha256(binary).hexdigest()}))
    return binary


def test_windows_exe_is_unique_self_contained_and_customer_bound(client, admin, tenant, monkeypatch, tmp_path):
    binary = _windows_payload(tmp_path, monkeypatch)
    results = [client.post("/api/console/enrollment-installers", headers=admin, json={
        "tenantId": tenant["id"], "os": "windows", "expiresInDays": 3,
    }) for _ in range(2)]
    assert all(r.status_code == 200 for r in results)
    assert results[0].content != results[1].content
    assert results[0].headers["content-disposition"] != results[1].headers["content-disposition"]
    for response in results:
        assert ".exe" in response.headers["content-disposition"]
        assert response.headers["cache-control"].startswith("private, no-store")
        assert response.content.startswith(binary)
        assert response.content.endswith(installers.WINDOWS_CONFIG_MAGIC)
        footer = len(installers.WINDOWS_CONFIG_MAGIC) + 4
        length = struct.unpack("<I", response.content[-footer:-footer+4])[0]
        base, token, request_id = response.content[-footer-length:-footer].decode().split("\n")
        assert base == "https://fenrir.test"
        assert token.startswith("fet_") and len(request_id) == 32
        from fenrir_cloud.security import digest
        db = next(get_db())
        try:
            row = db.scalar(select(EnrollmentToken).where(EnrollmentToken.token_hash == digest(token)))
            assert row.tenant_id == tenant["id"]
        finally:
            db.close()


def test_invalid_target_and_expiry_are_rejected(client, admin, tenant):
    bad = [
        {"tenantId": tenant["id"], "os": "bad-os", "expiresInDays": 20},
        {"tenantId": "not-a-tenant", "os": "linux", "expiresInDays": 20},
        {"tenantId": tenant["id"], "os": "linux", "expiresInDays": 0},
        {"tenantId": tenant["id"], "os": "linux", "expiresInDays": 366},
    ]
    for request in bad:
        response = client.post("/api/console/enrollment-installers", headers=admin, json=request)
        assert response.status_code in (403, 404, 422)


def test_windows_automatic_manifest_rejects_tampering_without_creating_token(client, admin, tenant, monkeypatch, tmp_path):
    _windows_payload(tmp_path, monkeypatch)
    (tmp_path / "windows" / "FenrirSetup.exe").write_bytes(b"MZtampered")
    response = client.post("/api/console/enrollment-installers", headers=admin, json={
        "tenantId": tenant["id"], "os": "windows"})
    assert response.status_code == 409
    assert "SHA-256" in response.text
    assert client.get("/api/console/enrollment-tokens", headers=admin).json() == []


def test_windows_manifest_malformed_or_symlink_refuses_download(monkeypatch, tmp_path):
    _windows_payload(tmp_path, monkeypatch)
    manifest = tmp_path / "windows" / "build.json"
    for content in ("bad", "{}", '{"sha256":123}', 'null'):
        manifest.write_text(content)
        assert not installers.available()["windows"]["ready"]
    manifest.unlink()
    manifest.symlink_to(tmp_path / "elsewhere")
    assert not installers.available()["windows"]["ready"]
