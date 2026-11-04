<#
.SYNOPSIS
  Brings back a Fenrir agent that Microsoft Defender quarantined, and stops it happening again on this PC.

.DESCRIPTION
  Run in an elevated PowerShell (Run as administrator) on the affected PC:
    powershell -ExecutionPolicy Bypass -File .\Repair-FenrirDefender.ps1

  It shows what Defender detected, adds Fenrir's folders and programs to Defender's exclusions, restores the agent
  program from quarantine, starts the agent, and tells you if a domain or Intune policy makes Defender ignore exclusions
  set on this PC (then add the exclusions in that policy instead). Nothing outside Fenrir is changed.
#>
$ErrorActionPreference = 'Continue'

function Say($text, $colour = 'Gray') { Write-Host $text -ForegroundColor $colour }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Say 'Run this in PowerShell opened with "Run as administrator".' Red
  exit 1
}

# Where the agent is installed (from its service registration), with the usual folder as the fallback.
$install = 'C:\Program Files\Fenrir Endpoint'
$image = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\FenrirAgent' -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
if ($image -match '^\s*"([^"]+)"') { $install = Split-Path -Parent $Matches[1] } elseif ($image) { $install = Split-Path -Parent (($image -split '\s+')[0]) }
$runtime = (Get-ItemProperty 'HKLM:\SOFTWARE\FenrirAgent' -Name RuntimeRoot -ErrorAction SilentlyContinue).RuntimeRoot
if (-not $runtime) { $runtime = Join-Path $env:ProgramData 'FenrirAgent' }
$exe = Join-Path $install 'fenrir-agent-service.exe'
$programs = 'fenrir-agent-service.exe', 'fenrir-endpoint-client.exe', 'fenrir-pam.exe', 'fenrir-remote.exe', 'FenrirSetup.exe' | ForEach-Object { Join-Path $install $_ }
Say "Fenrir install folder: $install"
Say "Fenrir data folder:    $runtime"

Say "`n1. What Microsoft Defender detected" Cyan
$found = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { ($_.Resources -join ' ') -like "*$install*" })
if (-not $found.Count) { Say '   No Defender detections of Fenrir files.' Green }
foreach ($detection in $found) {
  $threat = Get-MpThreat -ThreatID $detection.ThreatID -ErrorAction SilentlyContinue
  Say ("   {0}  {1}  {2}" -f $detection.InitialDetectionTime, $threat.ThreatName, ($detection.Resources -join '; ')) Yellow
}

Say "`n2. Exclusions" Cyan
$policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableLocalAdminMerge -ErrorAction SilentlyContinue
if ($policy.DisableLocalAdminMerge -eq 1) {
  Say '   A Group Policy or Intune setting makes Defender IGNORE exclusions set on this PC.' Red
  Say "   Add these to the Defender exclusions in that policy:" Red
  Say "     Folders:  $install ; $runtime" Red
  Say "     Processes: $($programs -join ' ; ')" Red
}
try {
  Add-MpPreference -ExclusionPath $install, $runtime -ExclusionProcess $programs -ErrorAction Stop
  Say '   Added Fenrir''s folders and programs to Defender''s exclusions on this PC.' Green
} catch {
  Say "   Could not add exclusions: $($_.Exception.Message)" Red
}

Say "`n3. The agent program" Cyan
if (-not (Test-Path $exe)) {
  $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
  if (Test-Path $mp) { & $mp -Restore -FilePath $exe | Out-Host }
  if (-not (Test-Path $exe) -and $found.Count) {
    foreach ($detection in $found) {
      $threat = Get-MpThreat -ThreatID $detection.ThreatID -ErrorAction SilentlyContinue
      if ($threat.ThreatName -and (Test-Path $mp)) { & $mp -Restore -Name $threat.ThreatName -All | Out-Host }
    }
  }
}
if (Test-Path $exe) { Say "   $exe is in place." Green } else {
  Say "   $exe is missing and could not be restored. Reinstall the agent from the console (Deploy agents)." Red
}

Say "`n4. Starting the agent" Cyan
if (Test-Path $exe) {
  $service = Get-Service FenrirAgent -ErrorAction SilentlyContinue
  if (-not $service) { Say '   The FenrirAgent service is not registered: reinstall the agent.' Red }
  else {
    if ($service.Status -ne 'Running') { Start-Service FenrirAgent -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 5
    Say ("   FenrirAgent is " + (Get-Service FenrirAgent).Status + '.') Green
  }
}

Say "`nAlso report the file to Microsoft as a false positive (see docs/DEVICE_PRESENCE.md), so Defender stops flagging it everywhere." Cyan
