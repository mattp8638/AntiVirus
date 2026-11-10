"""Deploy the agent the way MSPs already do: from their current RMM, Group Policy or Intune.

A *deployment token* is an ordinary enrolment token meant for many devices (one customer, optional group, an expiry).
With it:

- ``GET /api/v1/install/windows.exe`` / ``windows.msi`` / ``linux.sh`` / ``macos.sh`` return that customer's installer.
  The token travels in the ``X-Fenrir-Token`` header, so it never lands in a URL, proxy log or browser history. The
  download does not use up the token; enrolment does, and revoking the token stops both.
- The console generates a PowerShell script and a shell script that any RMM can run as SYSTEM/root (Itarian, Level,
  NinjaOne, Datto...), a Group Policy startup script, or an Intune platform script. They do nothing on a device that
  already has the agent, so they are safe to run on a schedule, and exit 0 (installed) or 1 (failed).
- The MSI (built here with wixl from msitools) installs the customer's own setup program and runs it quietly as SYSTEM,
  for Group Policy software installation and Intune line-of-business apps. Removing the MSI does not remove the agent,
  which is protected against tampering; remove it from the console.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

UPGRADE_CODE = "6B4F2C9E-8E57-4C1B-9D3A-2F6E9C0A1B7D"  # fixed: a newer package replaces an older one
_SAFE = re.compile(r"[^A-Za-z0-9 ._()&,+-]")


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _header(label: str, customer: str, expires: datetime | None, comment: str) -> str:
    when = f"Expires {expires:%d %b %Y}." if expires else "Does not expire."
    return (f"{comment} Fenrir agent deployment: {label} ({customer}). {when}\n"
            f"{comment} Run as SYSTEM/root from any RMM (Itarian, Level, NinjaOne...), a Group Policy startup script or Intune.\n"
            f"{comment} Safe to run again: it does nothing when the agent is already installed. Exit 0 = installed, 1 = failed.\n"
            f"{comment} Contains this customer's deployment token: keep it inside your RMM, and revoke it in Fenrir if it leaks.\n")


def windows_script(base: str, token: str, label: str, customer: str, expires: datetime | None) -> str:
    return _header(label, customer, expires, "#") + f"""$ErrorActionPreference = 'Stop'
$Server = {_ps_quote(base)}
$Token = {_ps_quote(token)}
try {{
  $service = Get-Service -Name FenrirAgent -ErrorAction SilentlyContinue
  if ($service) {{
    if ($service.Status -ne 'Running') {{ Start-Service -Name FenrirAgent -ErrorAction SilentlyContinue }}
    Write-Output "Fenrir agent is already installed ($((Get-Service -Name FenrirAgent).Status))."
    exit 0
  }}
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $file = Join-Path $env:TEMP ('FenrirSetup-' + [guid]::NewGuid().ToString('N') + '.exe')
  Invoke-WebRequest -UseBasicParsing -Uri "$Server/api/v1/install/windows.exe" -Headers @{{ 'X-Fenrir-Token' = $Token }} -OutFile $file
  $setup = Start-Process -FilePath $file -ArgumentList '--quiet' -Wait -PassThru
  Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
  if ($setup.ExitCode -ne 0) {{
    $log = Join-Path $env:ProgramFiles 'Fenrir Endpoint\\runtime\\last-upgrade.log'
    if (Test-Path $log) {{ Get-Content -Path $log -Tail 20 }}
    Write-Output "Fenrir setup failed (exit $($setup.ExitCode))."
    exit 1
  }}
  for ($i = 0; $i -lt 30; $i++) {{
    if ((Get-Service -Name FenrirAgent -ErrorAction SilentlyContinue).Status -eq 'Running') {{
      Write-Output 'Fenrir agent installed and running.'
      exit 0
    }}
    Start-Sleep -Seconds 2
  }}
  Write-Output 'Fenrir setup finished but the agent service is not running yet.'
  exit 1
}} catch {{
  Write-Output "Fenrir deployment failed: $($_.Exception.Message)"
  exit 1
}}
"""


def unix_script(base: str, token: str, label: str, customer: str, expires: datetime | None) -> str:
    return "#!/bin/sh\n" + _header(label, customer, expires, "#") + f"""set -u
SERVER={_sh_quote(base)}
TOKEN={_sh_quote(token)}
if [ "$(id -u)" -ne 0 ]; then echo "Run this as root (RMM scripts normally are)."; exit 1; fi
case "$(uname -s)" in
  Linux)
    os=linux
    if [ -x /usr/local/bin/fenrir-agent ] && systemctl is-active --quiet fenrir-agent 2>/dev/null; then
      echo "Fenrir agent is already installed and running."; exit 0
    fi ;;
  Darwin)
    os=macos
    if [ -x /usr/local/bin/fenrir-agent ] && launchctl print system/com.fenrir.agent >/dev/null 2>&1; then
      echo "Fenrir agent is already installed and running."; exit 0
    fi ;;
  *) echo "Unsupported system: $(uname -s)"; exit 1 ;;
esac
command -v curl >/dev/null 2>&1 || {{ echo "curl is required."; exit 1; }}
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
if ! curl -fsS --retry 3 -H "X-Fenrir-Token: $TOKEN" "$SERVER/api/v1/install/$os.sh" -o "$tmp"; then
  echo "Could not download the Fenrir installer from $SERVER."; exit 1
fi
if sh "$tmp"; then echo "Fenrir agent installed."; exit 0; fi
echo "Fenrir installer failed."; exit 1
"""


def intune_command(file_name: str = "FenrirAgent.msi") -> dict:
    return {
        "msiexec": f'msiexec /i "{file_name}" /qn /norestart /l*v "%WINDIR%\\Temp\\FenrirAgent-msi.log"',
        "gpo": "Group Policy: Computer Configuration > Policies > Software Settings > Software installation > New > Package "
               "(assigned), pointing at the MSI on a share that domain computers can read.",
        "intune": "Intune: Apps > Windows > Add > Line-of-business app, upload the MSI, assign to device groups. Or use the "
                  "PowerShell script as a platform script (run as SYSTEM, 64-bit).",
    }


def msi_available() -> bool:
    return shutil.which("wixl") is not None


def windows_msi(setup_exe: bytes, label: str, customer: str, version: str = "1.0.0") -> bytes:
    """An MSI that installs this customer's setup program and runs it quietly as SYSTEM. Raises RuntimeError."""
    wixl = shutil.which("wixl")
    if not wixl:
        raise RuntimeError("MSI packages need msitools (wixl) on the server; it is included in the Docker image")
    version = version if re.fullmatch(r"\d+\.\d+\.\d+", version or "") else "1.0.0"
    name = escape(_SAFE.sub("", f"Fenrir Endpoint Agent ({customer})")[:120])
    description = escape(_SAFE.sub("", label)[:120] or "Fenrir Endpoint Agent")
    wxs = f"""<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="{name}" Language="1033" Version="{version}" Manufacturer="Fenrir" UpgradeCode="{UPGRADE_CODE}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" Description="{description}"/>
    <MajorUpgrade DowngradeErrorMessage="A newer Fenrir deployment package is already installed."/>
    <Media Id="1" Cabinet="fenrir.cab" EmbedCab="yes"/>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLDIR" Name="Fenrir Deployment">
          <Component Id="Setup" Guid="*" Win64="yes">
            <File Id="FenrirSetupExe" Name="FenrirSetup.exe" Source="FenrirSetup.exe" KeyPath="yes"/>
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Main" Level="1"><ComponentRef Id="Setup"/></Feature>
    <CustomAction Id="RunFenrirSetup" FileKey="FenrirSetupExe" ExeCommand="--quiet" Execute="deferred" Impersonate="no" Return="check"/>
    <InstallExecuteSequence>
      <Custom Action="RunFenrirSetup" After="InstallFiles">NOT REMOVE</Custom>
    </InstallExecuteSequence>
  </Product>
</Wix>
"""
    with tempfile.TemporaryDirectory() as work:
        folder = Path(work)
        (folder / "FenrirSetup.exe").write_bytes(setup_exe)
        (folder / "fenrir.wxs").write_text(wxs, encoding="utf-8")
        result = subprocess.run([wixl, "-a", "x64", "-o", str(folder / "fenrir.msi"), str(folder / "fenrir.wxs")],
                                cwd=folder, capture_output=True, text=True, timeout=120)
        out = folder / "fenrir.msi"
        if result.returncode != 0 or not out.is_file():
            raise RuntimeError(f"wixl could not build the MSI: {(result.stderr or result.stdout).strip()[-300:]}")
        return out.read_bytes()
