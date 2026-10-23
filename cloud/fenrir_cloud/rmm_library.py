"""Built-in scripts, monitors and software packages seeded on first start.

Every script here is plain, readable and safe to run on a production machine:
they inspect, clean caches or restart services. Nothing destructive.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import MonitorCondition, Script, SoftwarePackage

WIN = ["windows"]
NIX = ["linux", "macos"]

SCRIPTS: list[dict] = [
    {"name": "Clear temporary files", "category": "Maintenance", "language": "powershell", "platforms": WIN,
     "description": "Deletes files older than a set number of days from Windows and user temp folders.",
     "parameters": [{"name": "OlderThanDays", "label": "Older than (days)", "type": "number", "default": "2", "required": True}],
     "body": r"""$ErrorActionPreference = 'SilentlyContinue'
$cutoff = (Get-Date).AddDays(-[int]$OlderThanDays)
$paths = @("$env:windir\Temp") + (Get-ChildItem 'C:\Users' -Directory | ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' })
$freed = 0
foreach ($p in $paths) {
  if (-not (Test-Path $p)) { continue }
  Get-ChildItem $p -Recurse -Force -File | Where-Object { $_.LastWriteTime -lt $cutoff } | ForEach-Object {
    $size = $_.Length; Remove-Item $_.FullName -Force; if ($?) { $freed += $size }
  }
}
"Freed {0:N1} MB" -f ($freed / 1MB)"""},
    {"name": "Restart a service", "category": "Services", "language": "powershell", "platforms": WIN,
     "description": "Restarts a Windows service and reports its status.",
     "parameters": [{"name": "ServiceName", "label": "Service name", "type": "string", "default": "Spooler", "required": True}],
     "body": r"""Restart-Service -Name $ServiceName -Force -ErrorAction Stop
Start-Sleep -Seconds 2
Get-Service -Name $ServiceName | Format-List Name, DisplayName, Status, StartType"""},
    {"name": "Flush DNS and renew IP", "category": "Network", "language": "powershell", "platforms": WIN,
     "description": "Clears the DNS client cache and renews DHCP leases.",
     "body": "ipconfig /flushdns\nipconfig /renew | Out-Null\nGet-NetIPConfiguration | Format-List InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer"},
    {"name": "Disk space report", "category": "Inventory", "language": "powershell", "platforms": WIN,
     "description": "Free space on every fixed disk and the 15 largest folders under a path.",
     "parameters": [{"name": "Path", "label": "Folder to analyse", "type": "string", "default": "C:\\Users", "required": False}],
     "body": r"""Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,
  @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}}, @{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}},
  @{n='FreePct';e={[math]::Round(100*$_.FreeSpace/$_.Size,1)}} | Format-Table -AutoSize
if ($Path -and (Test-Path $Path)) {
  Get-ChildItem $Path -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $size = (Get-ChildItem $_.FullName -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    [pscustomobject]@{Folder=$_.FullName; SizeGB=[math]::Round($size/1GB,2)}
  } | Sort-Object SizeGB -Descending | Select-Object -First 15 | Format-Table -AutoSize
}"""},
    {"name": "Run Disk Cleanup (cleanmgr)", "category": "Maintenance", "language": "powershell", "platforms": WIN,
     "description": "Runs Windows Disk Cleanup silently with the common categories selected.",
     "body": r"""$key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
foreach ($name in 'Temporary Files','Recycle Bin','Windows Error Reporting Files','Delivery Optimization Files','Thumbnail Cache','Update Cleanup') {
  if (Test-Path "$key\$name") { Set-ItemProperty "$key\$name" -Name StateFlags0099 -Value 2 -Type DWord }
}
Start-Process cleanmgr.exe -ArgumentList '/sagerun:99' -Wait
'Disk Cleanup finished'"""},
    {"name": "Reset Windows Update components", "category": "Patching", "language": "powershell", "platforms": WIN,
     "description": "Stops update services, renames SoftwareDistribution and catroot2, and restarts them. Fixes most stuck updates.",
     "body": r"""$services = 'wuauserv','bits','cryptsvc','msiserver'
Stop-Service $services -Force -ErrorAction SilentlyContinue
$stamp = Get-Date -Format yyyyMMddHHmmss
Rename-Item "$env:windir\SoftwareDistribution" "SoftwareDistribution.$stamp" -ErrorAction SilentlyContinue
Rename-Item "$env:windir\System32\catroot2" "catroot2.$stamp" -ErrorAction SilentlyContinue
Start-Service $services -ErrorAction SilentlyContinue
'Windows Update components reset'"""},
    # Safe protection test: the EICAR test string is an industry-standard, harmless file every antivirus
    # detects. It is assembled at run time from two halves so this source file is not itself flagged.
    {"name": "Validate real-time protection (EICAR test)", "category": "Security", "language": "powershell", "platforms": WIN,
     "description": "Writes the harmless EICAR test file to the temp folder and checks that real-time protection (Fenrir or "
                    "Microsoft Defender) removes it within 60 seconds. Exit code 0 means protection worked. Leaves nothing behind.",
     "body": r"""$ErrorActionPreference = 'SilentlyContinue'
$path = Join-Path $env:TEMP ('fenrir-eicar-test-' + [guid]::NewGuid().ToString('N') + '.com')
$a = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR'
$b = '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
try { [IO.File]::WriteAllText($path, $a + $b, [Text.Encoding]::ASCII) } catch { "PASS: protection blocked creating the test file ($($_.Exception.Message))"; exit 0 }
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Seconds 1
  if (-not (Test-Path $path)) { "PASS: the EICAR test file was removed after $($i + 1) seconds"; exit 0 }
  try { $null = Get-Content $path -TotalCount 1 -ErrorAction Stop } catch { "PASS: the test file is blocked from being read"; Remove-Item $path -Force; exit 0 }
}
Remove-Item $path -Force
"FAIL: the EICAR test file was still present after 60 seconds. Check that real-time protection is on."
exit 1"""},
    {"name": "Validate real-time protection (EICAR test, Linux/macOS)", "category": "Security", "language": "bash", "platforms": NIX,
     "description": "Writes the harmless EICAR test file to /tmp and checks that real-time protection removes or blocks it within "
                    "60 seconds. Exit code 0 means protection worked. Leaves nothing behind.",
     "body": r"""#!/bin/bash
path="/tmp/fenrir-eicar-test-$$.com"
a='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR'
b='-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
if ! printf '%s%s' "$a" "$b" > "$path" 2>/dev/null; then echo "PASS: protection blocked creating the test file"; exit 0; fi
for i in $(seq 1 60); do
  sleep 1
  if [ ! -e "$path" ]; then echo "PASS: the EICAR test file was removed after $i seconds"; exit 0; fi
  if ! head -c 1 "$path" >/dev/null 2>&1; then echo "PASS: the test file is blocked from being read"; rm -f "$path"; exit 0; fi
done
rm -f "$path"
echo "FAIL: the EICAR test file was still present after 60 seconds. Check that real-time protection is on."
exit 1"""},
    {"name": "BitLocker status", "category": "Security", "language": "powershell", "platforms": WIN,
     "description": "Encryption status and protectors for every volume.",
     "body": "Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus, @{n='Protectors';e={($_.KeyProtector.KeyProtectorType) -join ', '}} | Format-Table -AutoSize"},
    {"name": "List local administrators", "category": "Security", "language": "powershell", "platforms": WIN,
     "description": "Members of the local Administrators group.",
     "body": "Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize"},
    {"name": "Recent system errors", "category": "Diagnostics", "language": "powershell", "platforms": WIN,
     "description": "Errors and critical events from the System and Application logs.",
     "parameters": [{"name": "Hours", "label": "Look back (hours)", "type": "number", "default": "24", "required": True}],
     "body": r"""$since = (Get-Date).AddHours(-[int]$Hours)
Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=$since} -MaxEvents 100 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, LogName, ProviderName, Id, @{n='Message';e={($_.Message -split "`n")[0]}} | Format-Table -Wrap"""},
    {"name": "Installed software", "category": "Inventory", "language": "powershell", "platforms": WIN,
     "description": "Programs from the uninstall registry keys.",
     "body": r"""$keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object DisplayName | Sort-Object DisplayName |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize"""},
    {"name": "Enable or disable Remote Desktop", "category": "Configuration", "language": "powershell", "platforms": WIN,
     "description": "Turns RDP on (with Network Level Authentication) or off, and opens or closes the firewall rule.",
     "parameters": [{"name": "State", "label": "State", "type": "choice", "choices": ["Enable", "Disable"], "default": "Enable", "required": True}],
     "body": r"""$deny = if ($State -eq 'Enable') { 0 } else { 1 }
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value $deny
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
if ($State -eq 'Enable') { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' } else { Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' }
"Remote Desktop: $State" """},
    {"name": "Get uptime and pending reboot", "category": "Diagnostics", "language": "powershell", "platforms": WIN,
     "description": "Last boot time and whether a restart is pending.",
     "body": r"""$os = Get-CimInstance Win32_OperatingSystem
$pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
           (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
[pscustomobject]@{LastBoot=$os.LastBootUpTime; UptimeDays=[math]::Round(((Get-Date)-$os.LastBootUpTime).TotalDays,1); RebootPending=$pending} | Format-List"""},
    {"name": "Restart a service", "category": "Services", "language": "bash", "platforms": NIX,
     "description": "Restarts a systemd service and shows its status.",
     "parameters": [{"name": "ServiceName", "label": "Service name", "type": "string", "default": "cron", "required": True}],
     "body": "#!/bin/bash\nset -e\nsystemctl restart \"$ServiceName\"\nsleep 1\nsystemctl --no-pager status \"$ServiceName\" | head -n 15"},
    {"name": "Disk space report", "category": "Inventory", "language": "bash", "platforms": NIX,
     "description": "Filesystem usage and the largest directories under a path.",
     "parameters": [{"name": "Path", "label": "Directory to analyse", "type": "string", "default": "/var", "required": False}],
     "body": "#!/bin/bash\ndf -hT -x tmpfs -x devtmpfs\necho\n[ -n \"$Path\" ] && du -xh --max-depth=1 \"$Path\" 2>/dev/null | sort -rh | head -n 15"},
    {"name": "Top processes", "category": "Diagnostics", "language": "bash", "platforms": NIX,
     "description": "Processes using the most CPU and memory.",
     "body": "#!/bin/bash\necho '== CPU =='\nps -eo pid,user,pcpu,pmem,comm --sort=-pcpu | head -n 11\necho\necho '== Memory =='\nps -eo pid,user,pcpu,pmem,comm --sort=-pmem | head -n 11"},
    {"name": "Recent system errors", "category": "Diagnostics", "language": "bash", "platforms": ["linux"],
     "description": "Error-level journal entries.",
     "parameters": [{"name": "Hours", "label": "Look back (hours)", "type": "number", "default": "24", "required": True}],
     "body": "#!/bin/bash\njournalctl -p err --since \"$Hours hours ago\" --no-pager | tail -n 200"},
    {"name": "Clean package cache", "category": "Maintenance", "language": "bash", "platforms": ["linux"],
     "description": "Removes cached package downloads and old journal files.",
     "body": "#!/bin/bash\nif command -v apt-get >/dev/null; then apt-get clean && apt-get -y autoremove; fi\n"
             "if command -v dnf >/dev/null; then dnf clean all; fi\njournalctl --vacuum-time=14d\ndf -h /"},
]

MONITORS: list[dict] = [
    {"name": "High CPU", "metric": "cpu", "operator": ">", "threshold": 90, "duration_minutes": 15, "severity": "medium", "enabled": True},
    {"name": "High memory", "metric": "memory", "operator": ">", "threshold": 92, "duration_minutes": 15, "severity": "medium", "enabled": True},
    {"name": "Low disk space", "metric": "disk_free_percent", "operator": "<", "threshold": 10, "duration_minutes": 5,
     "severity": "high", "enabled": True, "actions": [{"type": "ticket", "board": "Monitoring Alerts"}]},
    {"name": "Server offline", "metric": "offline_minutes", "operator": ">", "threshold": 15, "duration_minutes": 0,
     "severity": "high", "enabled": False, "scope": {"tags": ["server"]}, "actions": [{"type": "ticket", "board": "Monitoring Alerts"}]},
    {"name": "Restart pending for a week", "metric": "uptime_days", "operator": ">", "threshold": 7, "duration_minutes": 0,
     "severity": "low", "enabled": False},
    {"name": "Protection unhealthy", "metric": "av_unhealthy", "operator": "==", "threshold": 1, "duration_minutes": 30,
     "severity": "high", "enabled": True},
    {"name": "Missing critical patches", "metric": "pending_patches", "operator": ">", "threshold": 0, "target": "critical",
     "duration_minutes": 0, "severity": "medium", "enabled": False},
]

SOFTWARE: list[dict] = [
    {"name": "Google Chrome", "publisher": "Google", "installer": "winget", "identifier": "Google.Chrome"},
    {"name": "Mozilla Firefox", "publisher": "Mozilla", "installer": "winget", "identifier": "Mozilla.Firefox"},
    {"name": "7-Zip", "publisher": "Igor Pavlov", "installer": "winget", "identifier": "7zip.7zip"},
    {"name": "Adobe Acrobat Reader", "publisher": "Adobe", "installer": "winget", "identifier": "Adobe.Acrobat.Reader.64-bit"},
    {"name": "VLC media player", "publisher": "VideoLAN", "installer": "winget", "identifier": "VideoLAN.VLC"},
    {"name": "Notepad++", "publisher": "Notepad++", "installer": "winget", "identifier": "Notepad++.Notepad++"},
    {"name": "Zoom Workplace", "publisher": "Zoom", "installer": "winget", "identifier": "Zoom.Zoom"},
    {"name": "Microsoft Teams", "publisher": "Microsoft", "installer": "winget", "identifier": "Microsoft.Teams"},
    {"name": "Visual Studio Code", "publisher": "Microsoft", "installer": "winget", "identifier": "Microsoft.VisualStudioCode"},
    {"name": "Microsoft PowerShell 7", "publisher": "Microsoft", "installer": "winget", "identifier": "Microsoft.PowerShell"},
    {"name": "htop", "publisher": "", "installer": "apt", "identifier": "htop", "platform": "linux"},
    {"name": "curl", "publisher": "", "installer": "apt", "identifier": "curl", "platform": "linux"},
    {"name": "fail2ban", "publisher": "", "installer": "apt", "identifier": "fail2ban", "platform": "linux"},
]


def seed(db: Session) -> None:
    # Add built-in scripts that are missing by name, so upgrades get new ones without touching existing rows.
    present = {name for (name,) in db.execute(select(Script.name).where(Script.builtin.is_(True))).all()}
    for item in SCRIPTS:
        if item["name"] in present:
            continue
        db.add(Script(tenant_id=None, builtin=True, updated_by="system", parameters=item.get("parameters", []),
                      **{k: v for k, v in item.items() if k != "parameters"}))
    if db.execute(select(MonitorCondition.id)).first() is None:
        for item in MONITORS:
            db.add(MonitorCondition(tenant_id=None, target=item.get("target", ""), scope=item.get("scope", {}),
                                    actions=item.get("actions", []),
                                    **{k: v for k, v in item.items() if k not in {"target", "scope", "actions"}}))
    if db.execute(select(SoftwarePackage.id).where(SoftwarePackage.builtin.is_(True))).first() is None:
        for item in SOFTWARE:
            db.add(SoftwarePackage(tenant_id=None, builtin=True, platform=item.get("platform", "windows"),
                                   **{k: v for k, v in item.items() if k != "platform"}))
