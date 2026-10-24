"""Authenticated, one-time, OS-specific endpoint deployment artifacts.

Do not publish these files through /downloads: every generated file contains a
customer enrollment secret. They are returned only by an authenticated POST.
"""
from __future__ import annotations

import hashlib
import os
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse

from fastapi import HTTPException

from . import installer_overlay

DOWNLOADS = Path(__file__).resolve().parents[1] / "downloads"
MAX_SETUP_BYTES = 180 * 1024 * 1024


def server_address(value: str) -> str:
    value = value.rstrip("/")
    parsed = urlparse(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise HTTPException(503, "Configure FENRIR_PUBLIC_URL as a public HTTPS origin (no path or credentials).")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")):
        raise HTTPException(503, "Agent enrollment requires a public HTTPS server URL.")
    if not parsed.netloc or not parsed.hostname or not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname):
        raise HTTPException(503, "FENRIR_PUBLIC_URL must contain a valid DNS hostname or IPv4 address.")
    try:
        port = parsed.port
    except ValueError:
        raise HTTPException(503, "FENRIR_PUBLIC_URL contains an invalid port.") from None
    if port is not None and not (1 <= port <= 65535):
        raise HTTPException(503, "FENRIR_PUBLIC_URL contains an invalid port.")
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


def windows_template() -> tuple[Path | None, str]:
    """Windows installer compiled automatically from source into the Docker image.

    No host-mounted releases, administrator staging, GitHub downloads, signing,
    or per-request native recompilation. The cloud keeps only a read-only
    executable template; personalised enrollment is generated in memory.
    """
    executable = release_file("windows/FenrirSetup.exe")
    if executable is None:
        return None, "Windows build is missing from this cloud image. Rebuild Fenrir Docker with the Windows cross-compiler stage."
    if not 2 <= executable.stat().st_size <= MAX_SETUP_BYTES:
        return None, "The cloud-built Windows installer has an invalid size."
    with executable.open("rb") as stream:
        if stream.read(2) != b"MZ":
            return None, "The Windows installer template is not a PE executable."
    return executable, ""



def available() -> dict:
    linux = all(release_file(f"fenrir-agent-linux-{arch}") for arch in ("amd64", "arm64"))
    windows_executable, windows_reason = windows_template()
    # Swift source is present, but there is no packaged/entitled agent with
    # fenrirctl enrollment + launchd service yet. Never claim it is installable.
    return {
        "linux": {"ready": linux, "extension": ".sh", "reason": "" if linux else "Linux x64 and ARM64 agent binaries must be built in the cloud image."},
        "windows": {"ready": windows_executable is not None, "extension": ".exe",
                    "mode": "cloud-built" if windows_executable else "unavailable",
                    "reason": windows_reason,
                    "warning": "Unsigned user-mode hobby installer. Windows security controls remain enabled; "
                               "there is no signed kernel minifilter or full antivirus protection."},
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


def build(os_name: str, base: str, token: str) -> tuple[bytes, str, str]:
    """Return (body, filename, MIME). Artifact checks must run before DB token creation."""
    base = server_address(base)
    token = _check_token(token)
    if os_name == "linux":
        return _linux_script(base, token), "Install-Fenrir-Linux.sh", "text/x-shellscript"
    if os_name == "windows":
        executable, problem = windows_template()
        if executable is None:
            raise HTTPException(409, problem)
        # This template contains all compiled agent components as PE resources.
        # Different customer+token values produce a distinct standalone EXE;
        # no publicly hosted artifact, on-disk secret, or installation script.
        try:
            result = installer_overlay.personalise(executable.read_bytes(), base, token)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return result, "Fenrir-Windows-Installer.exe", "application/vnd.microsoft.portable-executable"
    raise HTTPException(409, "The selected operating system does not have an installable agent release yet.")
