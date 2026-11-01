"""deploy/preflight.sh: the go-live check catches unsafe configuration and never prints a secret."""
from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import stat
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy" / "preflight.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("openssl") is None,
                                reason="needs bash and openssl")


def good_env() -> dict[str, str]:
    return {
        "POSTGRES_PASSWORD": secrets.token_hex(32),
        "FENRIR_SECRET_KEY": secrets.token_hex(32),
        "FENRIR_VAULT_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
        "FENRIR_ADMIN_PASSWORD": secrets.token_hex(24),
        "FENRIR_PUBLIC_URL": "https://rmm.msp-test.net",
        "FENRIR_DOMAIN": "rmm.msp-test.net",
        "FENRIR_OPEN_ENROLLMENT": "false",
        "FENRIR_VAULT_ALLOW_DERIVED_LEGACY": "false",
        "FENRIR_SMTP_HOST": "smtp.msp-test.net",
        "FENRIR_BUILD_PROFILE": "production",
        "FENRIR_RELEASE_KEY": "./signing/release-ed25519.pem",
    }


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


@pytest.fixture()
def deploy(tmp_path: Path):
    """A copy of the script in an empty deploy folder (outside Git), with signing material."""
    folder = tmp_path / "deploy"
    signing = folder / "signing"
    signing.mkdir(parents=True)
    shutil.copy(SCRIPT, folder / "preflight.sh")
    key, cert = tmp_path / "k.pem", tmp_path / "c.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
            "-days", "365", "-subj", "/CN=Fenrir Test Signing")
    (signing / "codesign.password").write_text("pfx-pass-123")
    openssl("pkcs12", "-export", "-inkey", str(key), "-in", str(cert), "-out", str(signing / "codesign.pfx"),
            "-passout", "pass:pfx-pass-123")
    openssl("genpkey", "-algorithm", "ed25519", "-out", str(signing / "release-ed25519.pem"))
    for f in signing.iterdir():
        f.chmod(0o600)
    return folder


def write_env(folder: Path, values: dict[str, str], extra: str = "") -> Path:
    path = folder / ".env"
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()) + extra)
    path.chmod(0o600)
    return path


def run(folder: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "NO_COLOR": "1", "FENRIR_BACKUP_DIR": str(folder / "no-backups"),
           "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"}
    return subprocess.run(["bash", str(folder / "preflight.sh"), *args], capture_output=True, text=True, env=env,
                          timeout=60)


def assert_no_secrets(output: str, values: dict[str, str]) -> None:
    for name in ("POSTGRES_PASSWORD", "FENRIR_SECRET_KEY", "FENRIR_VAULT_KEY", "FENRIR_ADMIN_PASSWORD"):
        assert values[name] not in output, f"{name} was printed"
    assert "pfx-pass-123" not in output


def test_good_configuration_is_ready_and_prints_no_secret(deploy):
    values = good_env()
    write_env(deploy, values)
    result = run(deploy, "--offline", "--no-host")
    assert result.returncode == 0, result.stdout
    assert "FAIL" not in result.stdout
    assert "Code-signing certificate opens and is valid for" in result.stdout
    assert "Release signing key present, Ed25519, owner-only" in result.stdout
    assert result.stdout.rstrip().endswith("Ready, with the warnings above to decide on.") \
        or result.stdout.rstrip().endswith("Ready.")
    assert_no_secrets(result.stdout + result.stderr, values)


def test_template_values_fail(deploy):
    shutil.copy(REPO / "deploy" / ".env.example", deploy / ".env")
    (deploy / ".env").chmod(0o600)
    result = run(deploy, "--offline", "--no-host")
    assert result.returncode == 1
    out = result.stdout
    assert "FAIL  POSTGRES_PASSWORD is still the template placeholder" in out
    assert "FAIL  FENRIR_SECRET_KEY is still the template placeholder" in out
    assert "FAIL  FENRIR_ADMIN_PASSWORD is still the template placeholder" in out
    assert "FAIL  FENRIR_VAULT_KEY is empty" in out
    assert "FAIL  FENRIR_PUBLIC_URL is still the template's example address" in out
    assert "Not ready" in out


def test_unsafe_settings_fail(deploy):
    values = good_env()
    values["FENRIR_ADMIN_PASSWORD"] = values["FENRIR_SECRET_KEY"]  # reused secret
    values["FENRIR_VAULT_KEY"] = base64.b64encode(b"too short").decode()
    values["FENRIR_PUBLIC_URL"] = "http://rmm.msp-test.net"
    env = write_env(deploy, values, "FENRIR_ENV=development\nFENRIR_IGNORE_CONSOLE_ALLOWLIST=true\n")
    env.chmod(0o644)
    (deploy / "signing" / "release-ed25519.pem").chmod(0o640)
    out = run(deploy, "--offline", "--no-host").stdout
    for expected in (
        "FAIL  .env can be read by other accounts",
        "FAIL  These secrets share a value: FENRIR_SECRET_KEY=FENRIR_ADMIN_PASSWORD",
        "FAIL  FENRIR_VAULT_KEY is not base64 of 32 bytes",
        "FAIL  FENRIR_ENV is 'development'",
        "FAIL  FENRIR_PUBLIC_URL (http://rmm.msp-test.net) is not HTTPS",
        "FAIL  FENRIR_IGNORE_CONSOLE_ALLOWLIST is on",
        "FAIL  The release key can be read by other accounts",
    ):
        assert expected in out, expected
    assert_no_secrets(out, values)


def test_wrong_certificate_password_and_missing_caddyfile(deploy):
    values = good_env()
    write_env(deploy, values)
    (deploy / "signing" / "codesign.password").write_text("not-the-password")
    (deploy / "docker-compose.https.yml").write_text("services: {}\n")
    out = run(deploy, "--offline", "--no-host").stdout
    assert "FAIL  The certificate cannot be opened with the stored password" in out
    assert "FAIL  deploy/docker-compose.https.yml is present but deploy/Caddyfile is not" in out
    (deploy / "Caddyfile").write_text("{$FENRIR_DOMAIN} { reverse_proxy cloud:8080 }\n")
    values["FENRIR_DOMAIN"] = "other.msp-test.net"
    write_env(deploy, values)
    assert "FAIL  FENRIR_DOMAIN (other.msp-test.net) is not the host in FENRIR_PUBLIC_URL" in \
        run(deploy, "--offline", "--no-host").stdout


def test_env_parsed_like_compose_without_executing_it(deploy, tmp_path):
    values = good_env()
    marker = tmp_path / "executed"
    extra = (f'FENRIR_SECRET_KEY="{secrets.token_hex(32)}"\n'                # quoted, last one wins
             f"FENRIR_ADMIN_PASSWORD={secrets.token_hex(24)}   # comment\n"   # inline comment
             f"FENRIR_SMTP_FROM=$(touch {marker})\n")                          # must never run
    write_env(deploy, {k: v for k, v in values.items() if k not in {"FENRIR_SECRET_KEY", "FENRIR_ADMIN_PASSWORD"}},
              extra)
    out = run(deploy, "--offline", "--no-host").stdout
    assert "PASS  FENRIR_SECRET_KEY is set and long enough" in out
    assert "PASS  FENRIR_ADMIN_PASSWORD is set and long enough" in out
    assert not marker.exists()


class _Stub(BaseHTTPRequestHandler):
    background_ok = True

    def do_GET(self):  # noqa: N802
        routes = {
            "/health": (200, {"status": "ok", "version": "9.9.9"}),
            "/ready": (200, {"ready": True}),
            "/health/background": (200, {"ok": True}) if _Stub.background_ok
            else (503, {"ok": False, "problems": ["scheduler has not completed for 12 minutes"]}),
            "/downloads/fenrir-codesign.cer": (200, {}),
        }
        code, body = routes.get(self.path, (404, {"detail": "not found"}))
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def test_live_checks(deploy):
    write_env(deploy, good_env())
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        out = run(deploy, "--no-host", "--url", url).stdout
        assert "PASS  /health answers (version 9.9.9)" in out
        assert "PASS  /ready: database up and schema current" in out
        assert "PASS  /health/background" in out
        assert "PASS  Windows installers are code-signed" in out
        assert "WARN  Checked over plain HTTP" in out

        _Stub.background_ok = False
        result = run(deploy, "--no-host", "--url", url)
        assert result.returncode == 1
        assert "FAIL  /health/background returned HTTP 503" in result.stdout
        assert "scheduler has not completed for 12 minutes" in result.stdout
    finally:
        _Stub.background_ok = True
        server.shutdown()
        server.server_close()
    assert "FAIL  Cannot reach" in run(deploy, "--no-host", "--url", url).stdout


def test_strict_fails_on_warnings(deploy):
    values = good_env()
    values["FENRIR_OPEN_ENROLLMENT"] = "true"
    write_env(deploy, values)
    assert run(deploy, "--offline", "--no-host").returncode == 0
    result = run(deploy, "--offline", "--no-host", "--strict")
    assert result.returncode == 1
    assert "WARN  FENRIR_OPEN_ENROLLMENT is not false" in result.stdout


def test_script_is_executable():
    assert SCRIPT.stat().st_mode & stat.S_IXUSR
