"""Authenticated, one-time, OS-specific endpoint deployment artifacts.

Do not publish these files through /downloads: every generated file contains a
customer enrollment secret. They are returned only by an authenticated POST.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import shlex
import struct
import uuid
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


def windows_release_mode() -> tuple[str | None, str]:
    """Validate the automatically compiled, immutable image payload."""
    executable = release_file("windows/FenrirSetup.exe")
    manifest = release_file("windows/build.json")
    if not executable or not manifest or executable.stat().st_size > MAX_SETUP_BYTES:
        return None, "Windows components are missing. Rebuild the cloud Docker image; no manual staging is required."
    try:
        metadata = json.loads(manifest.read_text())
        expected = metadata["sha256"]
    except (OSError, ValueError, KeyError, TypeError):
        return None, "Windows build manifest is invalid; rebuild the cloud image."
    if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected) or _digest(executable) != expected:
        return None, "Windows components failed SHA-256 verification; rebuild the cloud image."
    return "unsigned-hobby", ""


def available() -> dict:
    linux = all(release_file(f"fenrir-agent-linux-{arch}") for arch in ("amd64", "arm64"))
    macos = all(release_file(f"fenrir-agent-darwin-{arch}") for arch in ("amd64", "arm64"))
    windows_mode, windows_reason = windows_release_mode()
    return {
        "linux": {"ready": linux, "extension": ".sh", "reason": "" if linux else "Linux x64 and ARM64 agent binaries must be built in the cloud image."},
        "windows": {"ready": windows_mode is not None, "extension": ".exe",
                    "mode": windows_mode or "unavailable", "reason": windows_reason,
                    "warning": ("Unsigned hobby build: user-mode testing only; no signed Windows kernel driver or "
                                "full antivirus protection." if windows_mode == "unsigned-hobby" else "")},
        "macos": {"ready": macos, "extension": ".sh",
                  "reason": "" if macos else "macOS Intel and Apple Silicon agent binaries must be built in the cloud image.",
                  "warning": ("Unsigned build installed as a LaunchDaemon. Allow the agent Full Disk Access for complete "
                              "scanning, and Screen Recording plus Accessibility for remote control." if macos else "")},
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
for tool in base64 gzip sha256sum install systemctl mktemp; do
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
# Both architectures are embedded; installation never fetches mutable binaries.
case "$arch" in
  amd64) base64 -d <<'FENRIR_AMD64_PAYLOAD' | gzip -d > "$tmp/fenrir-agent"
{base64.encodebytes(gzip.compress(bins['amd64'].read_bytes(), mtime=0)).decode().rstrip()}
FENRIR_AMD64_PAYLOAD
    ;;
  arm64) base64 -d <<'FENRIR_ARM64_PAYLOAD' | gzip -d > "$tmp/fenrir-agent"
{base64.encodebytes(gzip.compress(bins['arm64'].read_bytes(), mtime=0)).decode().rstrip()}
FENRIR_ARM64_PAYLOAD
    ;;
esac
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


def _macos_script(base: str, token: str) -> bytes:
    bins = {arch: release_file(f"fenrir-agent-darwin-{arch}") for arch in ("amd64", "arm64")}
    if not all(bins.values()):
        raise HTTPException(409, "macOS agent binaries are not available; rebuild the cloud image.")
    digests = {arch: _digest(path) for arch, path in bins.items()}
    payloads = {arch: base64.encodebytes(gzip.compress(path.read_bytes(), mtime=0)).decode().rstrip()
                for arch, path in bins.items()}
    script = f"""#!/bin/sh
# Fenrir macOS customer installer. Treat this file as a secret until enrollment completes.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "Run this installer with sudo." >&2; exit 1; fi
case "$(uname -m)" in
  x86_64) arch=amd64; expected={digests['amd64']} ;;
  arm64) arch=arm64; expected={digests['arm64']} ;;
  *) echo "Unsupported macOS architecture." >&2; exit 1 ;;
esac
base={shlex.quote(base)}
token={shlex.quote(token)}
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
case "$arch" in
  amd64) /usr/bin/base64 -D <<'FENRIR_AMD64_PAYLOAD' | /usr/bin/gzip -d > "$tmp/fenrir-agent"
{payloads['amd64']}
FENRIR_AMD64_PAYLOAD
    ;;
  arm64) /usr/bin/base64 -D <<'FENRIR_ARM64_PAYLOAD' | /usr/bin/gzip -d > "$tmp/fenrir-agent"
{payloads['arm64']}
FENRIR_ARM64_PAYLOAD
    ;;
esac
printf '%s  %s\\n' "$expected" "$tmp/fenrir-agent" | /usr/bin/shasum -a 256 -c -s || {{
  echo "Agent binary SHA-256 mismatch; refusing installation." >&2; exit 1;
}}
/bin/mkdir -p /usr/local/bin /var/db/fenrir
/bin/chmod 700 /var/db/fenrir
/usr/bin/install -m 0755 "$tmp/fenrir-agent" /usr/local/bin/fenrir-agent.new
/bin/mv -f /usr/local/bin/fenrir-agent.new /usr/local/bin/fenrir-agent
/usr/bin/xattr -d com.apple.quarantine /usr/local/bin/fenrir-agent 2>/dev/null || true
plist=/Library/LaunchDaemons/com.fenrir.agent.plist
umask 077
cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.fenrir.agent</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/fenrir-agent</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>FENRIR_SERVER</key><string>$base</string>
    <key>FENRIR_ENROLLMENT_TOKEN</key><string>$token</string>
    <key>FENRIR_STATE_DIR</key><string>/var/db/fenrir</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>/var/log/fenrir-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/fenrir-agent.log</string>
</dict>
</plist>
EOF
/usr/sbin/chown root:wheel "$plist"
/bin/chmod 600 "$plist"
/bin/launchctl bootout system/com.fenrir.agent 2>/dev/null || true
/bin/launchctl bootstrap system "$plist"
/bin/launchctl enable system/com.fenrir.agent
/bin/launchctl kickstart -k system/com.fenrir.agent
echo "Fenrir agent installed as a LaunchDaemon. Confirm the device checks in to your tenant."
echo "In System Settings > Privacy & Security, allow /usr/local/bin/fenrir-agent under:"
echo "  - Full Disk Access (complete scanning)"
echo "  - Screen Recording and Accessibility (remote screen view and control)"
"""
    return script.encode("utf-8")


WINDOWS_CONFIG_MAGIC = b"FENRIR_ENROLL_V1!"


def _windows_executable(base: str, token: str) -> tuple[bytes, str, str]:
    mode, problem = windows_release_mode()
    if mode is None:
        raise HTTPException(409, problem)
    executable = release_file("windows/FenrirSetup.exe")
    # A small overlay is read by native setup before its UAC elevation. All agent
    # components are already embedded as PE resources in the shared template.
    # No shell, compiler, temporary customer files or public download URL needed.
    request_id = uuid.uuid4().hex
    payload = (base + "\n" + token + "\n" + request_id).encode("ascii")
    if len(payload) > 4096:
        raise HTTPException(422, "Installer enrollment configuration is too large.")
    data = executable.read_bytes() + payload + struct.pack("<I", len(payload)) + WINDOWS_CONFIG_MAGIC
    return data, f"FenrirSetup-{request_id}.exe", "application/vnd.microsoft.portable-executable"


def build(os_name: str, base: str, token: str) -> tuple[bytes, str, str]:
    """Return (body, filename, MIME). Artifact checks must run before DB token creation."""
    base = server_address(base)
    token = _check_token(token)
    if os_name == "linux":
        return _linux_script(base, token), "Install-Fenrir-Linux.sh", "text/x-shellscript"
    if os_name == "windows":
        return _windows_executable(base, token)
    if os_name == "macos":
        return _macos_script(base, token), "Install-Fenrir-macOS.sh", "text/x-shellscript"
    raise HTTPException(409, "The selected operating system does not have an installable agent release yet.")
