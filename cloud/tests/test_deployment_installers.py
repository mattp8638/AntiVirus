"""OS installer contracts: unique, confidential customer-bound downloads."""
import hashlib
import shlex
import subprocess

import pytest

from fenrir_cloud import deployment_installers as installers
from fenrir_cloud import installer_overlay
from fenrir_cloud.models import EnrollmentToken
from sqlalchemy import select


def _request(client, tenant_id, os_name):
    return client.post("/api/console/enrollment-installers", json={
        "tenantId": tenant_id, "label": "Pilot", "os": os_name,
        "expiresInDays": 14,
    })


def _template(tmp_path):
    directory = tmp_path / "windows"
    directory.mkdir(exist_ok=True)
    # Mock PE prefix; the real Docker cross-build test verifies native PE
    # resource/linker construction and the Windows VM verifies execution.
    body = b"MZ" + b"test-fixture-executable-content" * 5
    (directory / "FenrirSetup.exe").write_bytes(body)
    return body


def test_linux_installer_is_authenticated_customer_bound_and_persistent(client, admin, tenant, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    for arch in ("amd64", "arm64"):
        (tmp_path / f"fenrir-agent-linux-{arch}").write_bytes(b"linux-test-binary-" + arch.encode())
    assert _request(client, tenant["id"], "linux").status_code == 401
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
    assert "$base/downloads/fenrir-agent-linux-$arch" in script
    assert "fet_" in script
    assert hashlib.sha256((tmp_path / "fenrir-agent-linux-amd64").read_bytes()).hexdigest() in script
    tokens = client.get("/api/console/enrollment-tokens", headers=admin).json()
    assert any(t["tenantId"] == tenant["id"] and t["label"] == "Pilot" for t in tokens)
    assert all("token" not in t or t["token"] is None for t in tokens)


def test_missing_build_and_macos_do_not_create_credentials(client, admin, tenant, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    before = len(client.get("/api/console/enrollment-tokens", headers=admin).json())
    for os_name in ("linux", "windows", "macos"):
        response = client.post("/api/console/enrollment-installers", headers=admin, json={
            "tenantId": tenant["id"], "os": os_name, "expiresInDays": 30
        })
        assert response.status_code == 409
    assert len(client.get("/api/console/enrollment-tokens", headers=admin).json()) == before
    status = client.get("/api/console/enrollment-installers/status", headers=admin).json()
    assert all(not status[k]["ready"] for k in ("windows", "linux", "macos"))
    assert "rebuild" in status["windows"]["reason"].lower()


def test_windows_single_exe_unique_per_request_and_bound_to_customer(client, admin, tenant, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    template = _template(tmp_path)
    before = len(client.get("/api/console/enrollment-tokens", headers=admin).json())
    assert _request(client, tenant["id"], "windows").status_code == 401
    status = client.get("/api/console/enrollment-installers/status", headers=admin).json()
    assert status["windows"]["ready"] is True
    assert status["windows"]["mode"] == "cloud-built"
    assert status["windows"]["extension"] == ".exe"
    first = client.post("/api/console/enrollment-installers", headers=admin, json={
        "tenantId": tenant["id"], "os": "windows", "label": "First VM"
    })
    second = client.post("/api/console/enrollment-installers", headers=admin, json={
        "tenantId": tenant["id"], "os": "windows", "label": "Second VM"
    })
    for response in (first, second):
        assert response.status_code == 200, response.text
        assert response.content.startswith(template)
        assert response.headers["content-type"].startswith("application/vnd.microsoft.portable-executable")
        assert response.headers["cache-control"].startswith("private, no-store")
        assert "no-store" in response.headers["cache-control"]
        assert "Fenrir-Windows-Installer.exe" in response.headers["content-disposition"]
        assert response.headers["x-content-type-options"] == "nosniff"
    assert first.content != second.content
    base1, token1 = installer_overlay.inspect(first.content)
    base2, token2 = installer_overlay.inspect(second.content)
    assert base1 == base2 == "https://fenrir.test"
    assert token1.startswith("fet_") and token2.startswith("fet_")
    assert token1 != token2
    assert len(client.get("/api/console/enrollment-tokens", headers=admin).json()) == before + 2
    # No customer secrets are ever staged in a publicly downloadable path.
    assert list(tmp_path.rglob("*")) == [tmp_path / "windows", tmp_path / "windows" / "FenrirSetup.exe"]
    assert (tmp_path / "windows" / "FenrirSetup.exe").read_bytes() == template


def test_windows_overlay_detects_invalid_data_and_corruption():
    template = b"MZ" + b"PE fixture"
    exe = installer_overlay.personalise(template, "https://fenrir.test", "fet_" + "x" * 24)
    assert installer_overlay.inspect(exe) == ("https://fenrir.test", "fet_" + "x" * 24)
    modified = bytearray(exe)
    modified[-48] ^= 1
    with pytest.raises(ValueError, match="integrity"):
        installer_overlay.inspect(bytes(modified))
    with pytest.raises(ValueError):
        installer_overlay.inspect(exe[:-8])
    with pytest.raises(ValueError):
        installer_overlay.personalise(template, "https://bad" + chr(10) + "server", "fet_" + "x" * 24)
    with pytest.raises(ValueError):
        installer_overlay.personalise(b"not-a-pe", "https://fenrir.test", "fet_" + "x" * 24)


def test_invalid_target_and_expiry_are_rejected(client, admin, tenant):
    bad = [
        {"tenantId": tenant["id"], "os": "bad-os", "expiresInDays": 20},
        {"tenantId": "not-a-tenant", "os": "windows", "expiresInDays": 20},
        {"tenantId": tenant["id"], "os": "windows", "expiresInDays": 0},
        {"tenantId": tenant["id"], "os": "windows", "expiresInDays": 366},
    ]
    for body in bad:
        response = client.post("/api/console/enrollment-installers", headers=admin, json=body)
        assert response.status_code in (403, 404, 422)


def test_windows_template_must_exist_and_be_a_real_pe_header(client, admin, tenant, monkeypatch, tmp_path):
    monkeypatch.setattr(installers, "DOWNLOADS", tmp_path)
    _template(tmp_path)
    file = tmp_path / "windows" / "FenrirSetup.exe"
    file.write_bytes(b"invalid-data")
    before = len(client.get("/api/console/enrollment-tokens", headers=admin).json())
    response = client.post("/api/console/enrollment-installers", headers=admin, json={
        "tenantId": tenant["id"], "os": "windows"})
    assert response.status_code == 409
    assert len(client.get("/api/console/enrollment-tokens", headers=admin).json()) == before
