<#
.SYNOPSIS
Builds Fenrir-Backup recovery media on Windows PE, with your own Windows ADK
(design: docs/design/phase-2.md §6). Windows PE is not redistributed by this
project; this script assembles it on your PC.

.DESCRIPTION
Use Windows PE media when the Linux recovery ISO cannot see a machine's
disks (a storage controller with Windows-only drivers), or to add drivers to
the restored Windows (DISM). Started from it, the machine connects to your
server as a recovery session, like the Linux ISO, and its disks are restored
from the web UI.

Needs, on the PC that builds the media (run as Administrator):
  * Windows ADK "Deployment Tools" and the "Windows PE add-on"
    (https://learn.microsoft.com/windows-hardware/get-started/adk-install);
  * the Windows agent and CLI: fenrir-backup-agent.exe and fenrir-backup.exe
    (from the server's agents folder or a release).

.PARAMETER Agent
fenrir-backup-agent.exe (Windows x64).
.PARAMETER Cli
fenrir-backup.exe (Windows x64). Optional.
.PARAMETER Settings
fenrir-recovery.json from the web UI (Add machines > Recovery media >
Settings file only): the media then connects to that server by itself.
Without it, put the file on a USB stick later.
.PARAMETER Drivers
A folder of driver packages (.inf). They are added to Windows PE (so it
sees the disks) and kept on the media, and after a restore they are added
to the restored Windows with DISM.
.PARAMETER Out
The ISO to write (default .\fenrir-recovery-winpe.iso).
.PARAMETER UsbDrive
Instead of an ISO, write the media to this USB drive letter (e.g. E:). The
drive is formatted.

.EXAMPLE
.\New-FenrirWinPE.ps1 -Agent .\fenrir-backup-agent.exe -Cli .\fenrir-backup.exe -Settings .\fenrir-recovery.json -Drivers .\raid-drivers
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Agent,
    [string] $Cli,
    [string] $Settings,
    [string] $Drivers,
    [string] $Out = ".\fenrir-recovery-winpe.iso",
    [string] $UsbDrive,
    [string] $Work = (Join-Path $env:TEMP "fenrir-winpe")
)
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from PowerShell opened as Administrator.'
}
$Agent = (Resolve-Path $Agent).Path
if ($Cli) { $Cli = (Resolve-Path $Cli).Path }
if ($Settings) {
    $Settings = (Resolve-Path $Settings).Path
    $s = Get-Content $Settings -Raw | ConvertFrom-Json
    if (-not $s.server -or -not $s.token) { throw "$Settings is not a Fenrir-Backup recovery settings file" }
}
if ($Drivers) { $Drivers = (Resolve-Path $Drivers).Path }

# The ADK.
$kits = @(${env:ProgramFiles(x86)}, $env:ProgramFiles) | ForEach-Object { Join-Path $_ 'Windows Kits\10\Assessment and Deployment Kit' }
$adk = $kits | Where-Object { Test-Path (Join-Path $_ 'Deployment Tools\DandISetEnv.bat') } | Select-Object -First 1
if (-not $adk) { throw 'Windows ADK Deployment Tools not found. Install the Windows ADK and the Windows PE add-on.' }
$env_bat = Join-Path $adk 'Deployment Tools\DandISetEnv.bat'
if (-not (Test-Path (Join-Path $adk 'Windows Preinstallation Environment\copype.cmd'))) {
    throw 'The Windows PE add-on for the ADK is not installed.'
}
$dism = Join-Path $adk 'Deployment Tools\amd64\DISM\dism.exe'
if (-not (Test-Path $dism)) { $dism = 'dism.exe' }

function Invoke-Adk([string] $Command) {
    cmd.exe /c "call `"$env_bat`" >nul && $Command"
    if ($LASTEXITCODE -ne 0) { throw "failed: $Command" }
}

# A fresh working copy of Windows PE.
$mount = Join-Path $Work 'mount'
if (Test-Path $Work) {
    if (Test-Path (Join-Path $mount 'Windows')) { & $dism /Unmount-Image /MountDir:$mount /Discard | Out-Null }
    Remove-Item -Recurse -Force $Work
}
Write-Host '== Windows PE working copy'
Invoke-Adk "copype amd64 `"$Work`""
$wim = Join-Path $Work 'media\sources\boot.wim'
& $dism /Mount-Image /ImageFile:$wim /Index:1 /MountDir:$mount
if ($LASTEXITCODE -ne 0) { throw 'could not mount boot.wim' }
$committed = $false
try {
    Write-Host '== Fenrir-Backup'
    Copy-Item $Agent (Join-Path $mount 'Windows\System32\fenrir-backup-agent.exe')
    if ($Cli) { Copy-Item $Cli (Join-Path $mount 'Windows\System32\fenrir-backup.exe') }
    $fenrir = Join-Path $mount 'fenrir'
    New-Item -ItemType Directory $fenrir -Force | Out-Null
    if ($Drivers) {
        Write-Host '== Drivers'
        & $dism /Image:$mount /Add-Driver /Driver:$Drivers /Recurse
        if ($LASTEXITCODE -ne 0) { throw 'DISM could not add the drivers to Windows PE' }
        # Kept on X:\fenrir\drivers for the restored Windows.
        Copy-Item -Recurse $Drivers (Join-Path $fenrir 'drivers')
    }
    # Started by Windows PE: network, then the agent in its own window, and a
    # status window.
    @'
@echo off
wpeinit
title Fenrir-Backup recovery
start "Fenrir-Backup agent" /min X:\Windows\System32\fenrir-backup-agent.exe recovery
X:\Windows\System32\cmd.exe /k X:\fenrir\status.cmd
'@ | Set-Content -Encoding ascii (Join-Path $mount 'Windows\System32\startnet.cmd')
    @'
@echo off
:loop
cls
echo  Fenrir-Backup recovery (Windows PE)
echo  ===================================
echo.
if exist X:\fenrir\status (type X:\fenrir\status) else (echo  starting ...)
echo.
ipconfig | findstr /i "IPv4"
echo.
echo  Continue in the web UI: Machines ^> Recovery sessions.
echo  Without a server: put fenrir-recovery.json on a USB stick (root).
echo  Drivers for the restored Windows: a fenrir-drivers folder on a USB stick.
echo.
echo  [Enter] refresh   [c] command prompt   [r] restart   [s] shut down
set /p k=" > "
if /i "%k%"=="c" (start cmd.exe & goto loop)
if /i "%k%"=="r" (wpeutil reboot)
if /i "%k%"=="s" (wpeutil shutdown)
goto loop
'@ | Set-Content -Encoding ascii (Join-Path $fenrir 'status.cmd')
    Write-Host '== Saving the image'
    & $dism /Unmount-Image /MountDir:$mount /Commit
    if ($LASTEXITCODE -ne 0) { throw 'could not save boot.wim' }
    $committed = $true
} finally {
    if (-not $committed) { & $dism /Unmount-Image /MountDir:$mount /Discard | Out-Null }
}

# Settings beside Windows PE on the media (the agent looks for
# <drive>:\fenrir\recovery.json).
if ($Settings) {
    New-Item -ItemType Directory (Join-Path $Work 'media\fenrir') -Force | Out-Null
    Copy-Item $Settings (Join-Path $Work 'media\fenrir\recovery.json')
}

if ($UsbDrive) {
    Write-Host "== Writing to $UsbDrive (it is formatted)"
    Invoke-Adk "MakeWinPEMedia /UFD /F `"$Work`" $UsbDrive"
    Write-Host "Done: $UsbDrive"
} else {
    $Out = [IO.Path]::GetFullPath($Out)
    # MakeWinPEMedia (oscdimg) does not create the folder.
    New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
    Write-Host "== ISO"
    Invoke-Adk "MakeWinPEMedia /ISO /F `"$Work`" `"$Out`""
    $h = (Get-FileHash $Out -Algorithm SHA256).Hash.ToLower()
    Write-Host "Done: $Out ($([math]::Round((Get-Item $Out).Length / 1MB)) MB, SHA-256 $h)"
}
