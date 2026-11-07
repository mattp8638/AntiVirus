# Collect repeatable before/after-reboot evidence on a disposable Windows test machine.
# Does not stop services, disable Windows security or modify the agent enrollment.
# Run as Administrator: -Mode Baseline, reboot, -Mode Verify, reboot, -Mode Verify.
[CmdletBinding()]
param(
    [ValidateSet('Baseline', 'Verify')][string]$Mode = 'Baseline',
    [string]$DeviceId,  # optional cloud check using FENRIR_ACCEPTANCE_CONSOLE_TOKEN
    [string]$StateFile = (Join-Path $env:ProgramData 'FenrirAgent\Phase1\reboot-check.json')
)

$ErrorActionPreference = 'Stop'
$diagnosticsPath = Join-Path $PSScriptRoot 'Get-FenrirAgentDiagnostics.ps1'
if (-not (Test-Path -LiteralPath $diagnosticsPath)) {
    throw 'Get-FenrirAgentDiagnostics.ps1 must be adjacent to this script.'
}
$diagnostics = & $diagnosticsPath -AssertHealthy | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Fenrir Windows service is not healthy. Inspect the diagnostics output.' }
$service = Get-CimInstance Win32_Service -Filter "Name='FenrirAgent'"
if (-not $service -or -not $service.ProcessId) { throw 'FenrirAgent has no running service process.' }
$firstPid = $service.ProcessId
Start-Sleep -Seconds 10
$secondService = Get-CimInstance Win32_Service -Filter "Name='FenrirAgent'"
if (-not $secondService -or $secondService.State -ne 'Running' -or $secondService.ProcessId -ne $firstPid) {
    throw 'FenrirAgent restarted or stopped during the ten-second stability observation.'
}

$installSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\FenrirAgent' -ErrorAction Stop
$server = [string]$installSettings.ControlPlaneBaseUrl
$token = [string]$installSettings.EnrollmentToken
if (-not $server.StartsWith('https://') -or -not $token.StartsWith('fet_')) {
    throw 'Managed HTTPS cloud server or customer enrollment token not configured.'
}
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $tokenFingerprint = [Convert]::ToBase64String(
        $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($token))
    )
} finally { $sha.Dispose() }
$os = Get-CimInstance Win32_OperatingSystem
$boot = $os.LastBootUpTime.ToUniversalTime().ToString('o')
$record = [ordered]@{
    serviceBinary = [string]$diagnostics.Service.BinaryPath
    cloudServer = $server.TrimEnd('/')
    tokenFingerprint = $tokenFingerprint
    lastBootUtc = $boot
    verifiedReboots = 0
    lastCheckUtc = (Get-Date).ToUniversalTime().ToString('o')
}

if ($Mode -eq 'Verify' -and (Test-Path -LiteralPath $StateFile)) {
    $baseline = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    if ($baseline.cloudServer -ne $record.cloudServer) { throw 'The enrolled server changed.' }
    if ($baseline.deviceId) {
        if ($DeviceId -and $DeviceId -ne $baseline.deviceId) { throw 'The selected device differs from the baseline.' }
        $DeviceId = $baseline.deviceId
    }
}
if ($DeviceId) {
    if ($DeviceId -notmatch '^dev_[a-zA-Z0-9]+$' -or -not $env:FENRIR_ACCEPTANCE_CONSOLE_TOKEN) {
        throw 'Supply a device ID and a console token authorised to request inventory.'
    }
    $headers = @{ Authorization = "Bearer $env:FENRIR_ACCEPTANCE_CONSOLE_TOKEN" }
    $console = "$($record.cloudServer)/api/console"
    $detail = Invoke-RestMethod -Uri "$console/devices/$DeviceId" -Headers $headers
    if ($detail.device.hostname -ne $env:COMPUTERNAME) { throw 'Device hostname differs from this test machine.' }
    $request = @{ type = 'inventory.refresh'; reason = 'Windows reboot acceptance' } | ConvertTo-Json
    $command = Invoke-RestMethod -Method Post -Uri "$console/devices/$DeviceId/commands" -Headers $headers -ContentType 'application/json' -Body $request
    $until = [DateTime]::UtcNow.AddMinutes(5)
    do {
        Start-Sleep -Seconds 3
        $commands = Invoke-RestMethod -Uri "$console/commands?device_id=$DeviceId" -Headers $headers
        $result = $commands | Where-Object { $_.id -eq $command.id } | Select-Object -First 1
        if ($result.status -in @('failed','cancelled','expired')) { throw "Inventory command $($result.status)." }
    } until ($result.status -eq 'completed' -or [DateTime]::UtcNow -ge $until)
    if ($result.status -ne 'completed') { throw 'The original device did not complete its inventory request.' }
    $record.deviceId = $DeviceId
    $record.inventoryCommandId = $command.id
}

if ($Mode -eq 'Baseline') {
    $directory = Split-Path -Parent $StateFile
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $record | ConvertTo-Json | Set-Content -LiteralPath $StateFile -Encoding UTF8 -Force
    Write-Host "Baseline recorded at $StateFile. Reboot Windows and run -Mode Verify."
    return
}

if (-not (Test-Path -LiteralPath $StateFile)) { throw 'No baseline found. Run -Mode Baseline first.' }
$previous = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
if ($previous.lastBootUtc -eq $record.lastBootUtc) {
    throw 'Windows has not rebooted since the previous successful check.'
}
foreach ($field in @('serviceBinary', 'cloudServer', 'tokenFingerprint')) {
    if ($previous.$field -ne $record.$field) {
        throw "Windows agent $field changed after reboot. Inspect the agent before proceeding."
    }
}
$record.verifiedReboots = [int]$previous.verifiedReboots + 1
$record | ConvertTo-Json | Set-Content -LiteralPath $StateFile -Encoding UTF8 -Force
Write-Host "Fenrir remained installed, automatically started, and retained its server and enrollment token after reboot $($record.verifiedReboots)/2."
if ($record.verifiedReboots -ge 2) {
    if ($record.inventoryCommandId) { Write-Host 'Cloud check passed on the original device ID after reboot.'; return }
    Write-Host 'LOCAL reboot stability checkpoint passed twice. Verify cloud check-in, unchanged device ID and real RMM command completion separately.'
}
