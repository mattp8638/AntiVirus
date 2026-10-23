# Read-only Windows agent persistence diagnostics.
# Run from an elevated PowerShell console before and after restarting Windows.
# Does not change services, Windows Defender, tamper protection or enrolled identity.
param([string]$ServiceName = 'FenrirAgent', [int]$Hours = 48)
$ErrorActionPreference = 'Continue'
$now = Get-Date
$svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
$serviceResult = if ($svc) {
    [ordered]@{
        Exists = $true
        Name = $svc.Name
        State = $svc.State
        StartMode = $svc.StartMode
        ExitCode = $svc.ExitCode
        ProcessId = $svc.ProcessId
        ServicePath = $svc.PathName
    }
} else { [ordered]@{ Exists = $false; Name = $ServiceName } }

$binary = $null
if ($svc -and $svc.PathName) {
    if ($svc.PathName -match '^"([^"]+)"') { $binary = $Matches[1] }
    elseif ($svc.PathName -match '^(.*?\.exe)(?:\s|$)') { $binary = $Matches[1] }
}
$serviceResult['BinaryExists'] = [bool]($binary -and (Test-Path -LiteralPath $binary -PathType Leaf))
$serviceResult['BinaryPath'] = $binary

$recovery = & sc.exe qfailure $ServiceName 2>&1 | Out-String
$recentScm = @(Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Service Control Manager'
    StartTime = $now.AddHours(-[Math]::Abs($Hours))
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*$ServiceName*" -or $_.Message -like '*Fenrir*'
} | Select-Object -First 30 TimeCreated, Id, LevelDisplayName, Message)
$application = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    StartTime = $now.AddHours(-[Math]::Abs($Hours))
} -ErrorAction SilentlyContinue | Where-Object {
    $_.ProviderName -eq 'FenrirAgent' -or
    ($_.Message -match 'FenrirAgent|fenrir-agent-service' -and $_.Level -le 3)
} | Select-Object -First 30 TimeCreated, ProviderName, Id, LevelDisplayName, Message)
$defender = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    StartTime = $now.AddHours(-[Math]::Abs($Hours))
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match 'Fenrir|fenrir-agent-service|AntivirusMinifilter'
} | Select-Object -First 30 TimeCreated, Id, LevelDisplayName, Message)
$uninstall = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FenrirEndpoint' -ErrorAction SilentlyContinue
$autostart = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'FenrirEndpointClient' -ErrorAction SilentlyContinue).'FenrirEndpointClient'

$report = [ordered]@{
    RecordedAt = $now.ToString('o')
    ComputerName = $env:COMPUTERNAME
    Service = $serviceResult
    RecoveryConfiguration = $recovery.Trim()
    UninstallEntryPresent = [bool]$uninstall
    UninstallLocation = if ($uninstall) { $uninstall.InstallLocation } else { $null }
    EndpointClientAutostart = $autostart
    ServiceEvents = $recentScm
    AgentApplicationEvents = $application
    RelevantDefenderEvents = $defender
    Note = 'Only service, local Windows logging and startup entries are checked. An absent service, stopped service and quarantined binary are different failure modes.'
}
$report | ConvertTo-Json -Depth 6
