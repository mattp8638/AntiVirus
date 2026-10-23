"""Authenticated, one-time, OS-specific endpoint deployment artifacts.

Do not publish these files through /downloads: every generated file contains a
customer enrollment secret. They are returned only by an authenticated POST.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import shlex
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from fastapi import HTTPException

DOWNLOADS = Path(__file__).resolve().parents[1] / "downloads"
MAX_SETUP_BYTES = 180 * 1024 * 1024


def server_address(value: str) -> str:
    value = value.rstrip("/")
    parsed = urlparse(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise HTTPException(503, "Configure FENRIR_PUBLIC_URL as a public HTTPS origin (no path or credentials).")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")):
        raise HTTPException(503, "Agent enrollment requires a public HTTPS server URL.")
    if not parsed.netloc:
        raise HTTPException(503, "FENRIR_PUBLIC_URL is missing a hostname.")
    return value


def release_file(name: str) -> Path | None:
    """Only serve pre-staged local artifacts, never arbitrary user paths/symlinks."""
    root = DOWNLOADS.resolve()
    candidate = root / name
    if candidate.is_symlink() or not candidate.is_file():
        return None
    resolved = candidate.resolve()
    if root not in resolved.parents:
        return None
    return resolved


def available() -> dict:
    linux = all(release_file(f"fenrir-agent-linux-{arch}") for arch in ("amd64", "arm64"))
    win = release_file("releases/FenrirSetup.exe")
    fingerprint = os.getenv("FENRIR_WINDOWS_SIGNER_THUMBPRINT", "").strip()
    signed_release_ready = bool(win and win.stat().st_size <= MAX_SETUP_BYTES and re.fullmatch(r"[a-fA-F0-9]{40}", fingerprint))
    # Swift source is present, but there is no packaged/entitled agent with
    # fenrirctl enrollment + launchd service yet. Never claim it is installable.
    return {
        "linux": {"ready": linux, "extension": ".sh", "reason": "" if linux else "Linux x64 and ARM64 agent binaries must be built in the cloud image."},
        "windows": {"ready": signed_release_ready, "extension": ".zip",
                    "reason": "" if signed_release_ready else "Stage signed FenrirSetup.exe and configure its trusted Authenticode certificate thumbprint."},
        "macos": {"ready": False, "extension": ".pkg",
                  "reason": "Not yet deployable: the macOS agent lacks a signed, entitled PKG, enrollment client and launchd integration."},
    }


def _check_token(token: str) -> str:
    if not re.fullmatch(r"fet_[A-Za-z0-9_-]{16,120}", token):
        raise HTTPException(500, "Unexpected enrollment token format.")
    return token


def _digest(file: Path) -> str:
    checksum = hashlib.sha256()
    with file.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def _linux_script(base: str, token: str) -> bytes:
    bins = {arch: release_file(f"fenrir-agent-linux-{arch}") for arch in ("amd64", "arm64")}
    if not all(bins.values()):
        raise HTTPException(409, "Linux agent binaries are not available; rebuild the cloud image.")
    digests = {arch: _digest(path) for arch, path in bins.items()}
    # File is sensitive: the operator must download it from the authenticated UI
    # and store /etc/fenrir/agent.env with root-only permissions.
    script = f"""#!/bin/sh
# Fenrir Linux customer installer. Treat this file as a secret until enrollment completes.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "Run this installer with sudo." >&2; exit 1; fi
for tool in curl sha256sum install systemctl mktemp; do
  command -v "$tool" >/dev/null 2>&1 || {{ echo "Missing dependency: $tool" >&2; exit 1; }}
done
[ -d /run/systemd/system ] || {{ echo "systemd is required for a persistent installation." >&2; exit 1; }}
case "$(uname -m)" in
  x86_64|amd64) arch=amd64; expected={digests['amd64']} ;;
  aarch64|arm64) arch=arm64; expected={digests['arm64']} ;;
  *) echo "Unsupported Linux architecture." >&2; exit 1 ;;
esac
base={shlex.quote(base)}
token={shlex.quote(token)}
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
curl --fail --silent --show-error --location --retry 3 "$base/downloads/fenrir-agent-linux-$arch" -o "$tmp/fenrir-agent"
printf '%s  %s\\n' "$expected" "$tmp/fenrir-agent" | sha256sum --check --status || {{
  echo "Agent binary SHA-256 mismatch; refusing installation." >&2; exit 1;
}}
# Do not erase an existing device identity or runtime database on a repair.
install -d -m 0700 /etc/fenrir /var/lib/fenrir
install -m 0755 "$tmp/fenrir-agent" /usr/local/bin/fenrir-agent.new
mv -f /usr/local/bin/fenrir-agent.new /usr/local/bin/fenrir-agent
umask 077
cat > /etc/fenrir/agent.env <<EOF
FENRIR_SERVER=$base
FENRIR_ENROLLMENT_TOKEN=$token
FENRIR_STATE_DIR=/var/lib/fenrir
EOF
chmod 600 /etc/fenrir/agent.env
cat > /etc/systemd/system/fenrir-agent.service <<'EOF'
[Unit]
Description=Fenrir managed endpoint agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
EnvironmentFile=/etc/fenrir/agent.env
ExecStart=/usr/local/bin/fenrir-agent
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/fenrir-agent.service
systemctl daemon-reload
systemctl enable fenrir-agent
systemctl restart fenrir-agent
sleep 2
if ! systemctl is-active --quiet fenrir-agent; then
  echo "Agent service failed; inspect journalctl -u fenrir-agent." >&2; exit 1
fi
echo "Fenrir agent installed as an automatic-start service. Confirm the device checks in to your tenant."
"""
    return script.encode("utf-8")


def _windows_script(base: str, token: str, checksum: str, signer_fingerprint: str) -> bytes:
    # Generated scripts are never available at public /downloads URLs.
    # Installer is expected to be Authenticode signed by the releasing organisation.
    content = r'''#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$setup = Join-Path $PSScriptRoot 'FenrirSetup.exe'
$expectedHash = '__SHA256__'
$expectedSigner = '__CERT__'
$server = '__SERVER__'
$enroll = '__TOKEN__'
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) { throw 'FenrirSetup.exe is missing from this package.' }
$hash = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash
if ($hash -ne $expectedHash) { throw 'Installer SHA-256 mismatch. Do not run this package.' }
$signature = Get-AuthenticodeSignature -LiteralPath $setup
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw "Installer signature is not valid: $($signature.Status). Request a signed release." }
if ($signature.SignerCertificate.Thumbprint -ne $expectedSigner) { throw 'Installer certificate does not match the approved Fenrir release signer.' }
Write-Host 'Opening Fenrir Setup. Complete the installation in its window.'
$args = '--server "' + $server + '" --enroll-token "' + $enroll + '"'
$process = Start-Process -FilePath $setup -ArgumentList $args -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Fenrir Setup failed with exit code $($process.ExitCode)." }
$service = Get-Service -Name 'FenrirAgent' -ErrorAction SilentlyContinue
if (-not $service -or $service.Status -ne 'Running') { throw 'FenrirAgent is not running after setup. Inspect the setup log.' }
$configured = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\FenrirAgent' -Name ControlPlaneBaseUrl -ErrorAction Stop).ControlPlaneBaseUrl
if ($configured.TrimEnd('/') -ne $server) { throw 'The installed agent is not configured for the intended cloud server.' }
Write-Host 'Fenrir service is running. Confirm the device appears in the selected customer tenant.'
'''
    return (content.replace("__SHA256__", checksum.upper())
            .replace("__CERT__", signer_fingerprint.upper())
            .replace("__SERVER__", base).replace("__TOKEN__", token).encode("utf-8"))


def build(os_name: str, base: str, token: str) -> tuple[bytes, str, str]:
    """Return (body, filename, MIME). Artifact checks must run before DB token creation."""
    base = server_address(base)
    token = _check_token(token)
    if os_name == "linux":
        return _linux_script(base, token), "Install-Fenrir-Linux.sh", "text/x-shellscript"
    if os_name == "windows":
        executable = release_file("releases/FenrirSetup.exe")
        if not executable or executable.stat().st_size > MAX_SETUP_BYTES:
            raise HTTPException(409, "No verified Windows installer release is staged on this server.")
        signer = os.getenv("FENRIR_WINDOWS_SIGNER_THUMBPRINT", "").strip()
        if not re.fullmatch(r"[a-fA-F0-9]{40}", signer):
            raise HTTPException(409, "Configure FENRIR_WINDOWS_SIGNER_THUMBPRINT for your signed Windows release.")
        executable_hash = _digest(executable)
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=2) as archive:
            archive.write(executable, "FenrirSetup.exe")
            archive.writestr("Install-Fenrir.ps1", _windows_script(base, token, executable_hash, signer))
            archive.writestr("README.txt",
                "Fenrir Windows enrollment bundle - contains a customer secret.\\r\\n"
                "Extract this ZIP on the target Windows PC. In an elevated PowerShell window,\\r\\n"
                "verify the source, run Unblock-File .\\Install-Fenrir.ps1 if needed, then\\r\\n"
                "run .\\Install-Fenrir.ps1 and complete Fenrir Setup.\\r\\n"
                "The installer verifies the release signature and SHA-256 before executing.\\r\\n"
                "Delete this ZIP after successful enrollment. Do not publish it.\\r\\n")
        return data.getvalue(), "Fenrir-Windows-Enrollment.zip", "application/zip"
    raise HTTPException(409, "The selected operating system does not have an installable agent release yet.")
