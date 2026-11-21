"""All-in-one Fenrir installers: the device backup agent ships inside the security agent's installers.

* Windows: FenrirSetup.exe embeds fenrir-backup-agent.exe (deploy/Dockerfile, agent/windows/service/CMakeLists.txt)
  and installs it after the security agent (installer/native/src/SetupMain.cpp, InstallBundledBackupAgent).
* Linux and macOS: the installer scripts carry the backup agent too (this module), next to the security agent.

Either way the backup agent enrols with the same deployment token (routers/backup_agent.py accepts fet_ tokens) and is
linked to the device by host name once the security agent has enrolled (backup.link_devices). A deployment can leave
backup out (EnrollmentToken.include_backup = False). Backup is never allowed to fail the security agent's install.
"""

from __future__ import annotations

import base64
import gzip

from . import backup as bk

TRIPLES = {"linux": {"amd64": "x86_64-unknown-linux-musl", "arm64": "aarch64-unknown-linux-musl"},
           "macos": {"amd64": "x86_64-apple-darwin", "arm64": "aarch64-apple-darwin"}}

LINUX_SERVICE = r"""  mkdir -p /etc/systemd/system/fenrir-backup-agent.service.d
  dropin=/etc/systemd/system/fenrir-backup-agent.service.d/proxy.conf
  if [ -n "$proxy" ]; then
    printf '[Service]\nEnvironment=HTTPS_PROXY=%s HTTP_PROXY=%s NO_PROXY=localhost,127.0.0.1,::1\n' "$proxy" "$proxy" > "$dropin"
  elif [ -f "$dropin" ]; then
    : > "$dropin"
  fi
  cat > /etc/systemd/system/fenrir-backup-agent.service <<'UNIT'
[Unit]
Description=Fenrir device backup agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/fenrir-backup-agent run
Restart=always
RestartSec=30
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT
  chmod 644 /etc/systemd/system/fenrir-backup-agent.service
  systemctl daemon-reload
  if systemctl enable fenrir-backup-agent >/dev/null 2>&1 && systemctl restart fenrir-backup-agent; then
    echo "Device backup agent installed (fenrir-backup-agent service)."
  else
    echo "Device backup: the service did not start; see journalctl -u fenrir-backup-agent." >&2
  fi"""

MACOS_SERVICE = r"""  bplist=/Library/LaunchDaemons/uk.fenrir-backup.agent.plist
  cat > "$bplist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>uk.fenrir-backup.agent</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/fenrir-backup-agent</string><string>run</string></array>
  <key>EnvironmentVariables</key><dict>$proxy_env</dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Library/Logs/fenrir-backup-agent.log</string>
</dict>
</plist>
EOF
  /bin/chmod 0644 "$bplist"
  if /bin/launchctl bootstrap system "$bplist"; then
    echo "Device backup agent installed (uk.fenrir-backup.agent)."
    echo "  Also allow /usr/local/bin/fenrir-backup-agent under Full Disk Access, so it can read the disks."
  else
    echo "Device backup: launchd did not start it; see /Library/Logs/fenrir-backup-agent.log." >&2
  fi"""

LINUX_INSTALL = r"""  systemctl stop fenrir-backup-agent 2>/dev/null || true
  install -m 0755 "$tmp/fenrir-backup-agent" /usr/local/bin/fenrir-backup-agent.new
  mv -f /usr/local/bin/fenrir-backup-agent.new /usr/local/bin/fenrir-backup-agent"""

MACOS_INSTALL = r"""  /bin/launchctl bootout system/uk.fenrir-backup.agent 2>/dev/null || true
  /usr/bin/install -m 0755 "$tmp/fenrir-backup-agent" /usr/local/bin/fenrir-backup-agent.new
  /bin/mv -f /usr/local/bin/fenrir-backup-agent.new /usr/local/bin/fenrir-backup-agent
  /usr/bin/xattr -d com.apple.quarantine /usr/local/bin/fenrir-backup-agent 2>/dev/null || true"""


def available(platform: str) -> dict[str, bool]:
    """Which CPU architectures of `platform` ("linux" | "macos") have a backup agent build on this server."""
    return {arch: bk.binary_info(bk.ALL_TARGETS[t]) is not None for arch, t in TRIPLES[platform].items()}


def unix_block(platform: str) -> str:
    """Shell appended to the Linux / macOS Fenrir installer. Uses the installer's $base, $token, $proxy,
    $arch (amd64 | arm64) and $tmp, plus $proxy_env on macOS."""
    linux = platform == "linux"
    decode = "base64 -d" if linux else "/usr/bin/base64 -D"
    unzip = "gzip -d" if linux else "/usr/bin/gzip -d"
    check = "sha256sum --check --status" if linux else "/usr/bin/shasum -a 256 -c -s"
    branches = []
    for arch, triple in TRIPLES[platform].items():
        target = bk.ALL_TARGETS[triple]
        info = bk.binary_info(target)
        if info is None:
            branches.append(f'    {arch}) echo "Device backup: this server has no backup agent for $(uname -m) yet; skipped."\n'
                            "      return 0 ;;")
            continue
        payload = base64.encodebytes(gzip.compress(bk.binary_path(target).read_bytes(), mtime=0)).decode().rstrip()
        tag = f"FENRIR_BACKUP_{arch.upper()}_PAYLOAD"
        branches.append(f"    {arch}) bexpected={info[0]}\n"
                        f"      {decode} <<'{tag}' | {unzip} > \"$tmp/fenrir-backup-agent\"\n{payload}\n{tag}\n"
                        "      ;;")
    body = "\n".join(branches)
    return f"""
# --- Device backup (backup/ in the Fenrir repository) ---------------------------------------------------------
# Installed alongside as its own service and enrolled with the same deployment token. Never fatal: protection is
# installed either way, and backup can be added later from the device's Backup tab in Fenrir.
install_fenrir_backup() {{
  case "$arch" in
{body}
    *) return 0 ;;
  esac
  printf '%s  %s\\n' "$bexpected" "$tmp/fenrir-backup-agent" | {check} || {{
    echo "Device backup: checksum mismatch; skipped." >&2; return 0; }}
{LINUX_INSTALL if linux else MACOS_INSTALL}
  if ! ( if [ -n "$proxy" ]; then export HTTPS_PROXY="$proxy" HTTP_PROXY="$proxy"; fi
         exec /usr/local/bin/fenrir-backup-agent enroll --server "${{base%/}}/backup" --token "$token" --role auto ); then
    echo "Device backup: enrolment failed; protection is installed. Add backup later from the device's Backup tab." >&2
    return 0
  fi
{LINUX_SERVICE if linux else MACOS_SERVICE}
}}
install_fenrir_backup || true
"""
