# Fenrir: why does this machine show offline? Read-only; run in an elevated PowerShell on the machine while the console
# shows it offline, then send the output to your Fenrir administrator.
#   powershell -ExecutionPolicy Bypass -File Get-FenrirOfflineReport.ps1 -Server www.example.com
param([Parameter(Mandatory = $true)][string]$Server)  # your Fenrir server's host name
$ErrorActionPreference = 'Continue'
"== Fenrir offline report $(Get-Date -Format s) on $env:COMPUTERNAME"

$svc = Get-CimInstance Win32_Service -Filter "Name='FenrirAgent'" -ErrorAction SilentlyContinue
if (-not $svc) { "Service: not installed"; return }
"Service: $($svc.State), PID $($svc.ProcessId), $($svc.PathName)"
$proc = Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue
if ($proc) {
    $cpu1 = $proc.TotalProcessorTime; Start-Sleep -Seconds 15; $proc.Refresh(); $cpu2 = $proc.TotalProcessorTime
    "Process: started $($proc.StartTime), threads $($proc.Threads.Count), memory $([int]($proc.WorkingSet64/1MB)) MB, CPU used in 15 s: $([int]($cpu2-$cpu1).TotalMilliseconds) ms"
}

"`n== Connections from the agent to the server"
$addresses = @([System.Net.Dns]::GetHostAddresses($Server) | ForEach-Object { $_.IPAddressToString })
"$Server resolves to: $($addresses -join ', ')"
Get-NetTCPConnection -OwningProcess $svc.ProcessId -ErrorAction SilentlyContinue |
    Select-Object State, LocalPort, RemoteAddress, RemotePort, @{n='ToServer';e={$addresses -contains $_.RemoteAddress}} | Format-Table -AutoSize | Out-String
$test = Test-NetConnection -ComputerName $Server -Port 443 -WarningAction SilentlyContinue
"TCP 443 to ${Server}: $($test.TcpTestSucceeded)"
try {
    $r = Invoke-WebRequest -Uri "https://$Server/health" -UseBasicParsing -TimeoutSec 15
    "HTTPS: $($r.StatusCode)"
} catch { "HTTPS: $($_.Exception.Message)" }

"`n== Agent files (last written)"
foreach ($dir in @("$env:ProgramData\FenrirAgent\runtime", "$env:ProgramFiles\Fenrir Endpoint\runtime")) {
    Get-ChildItem $dir -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 8 Name, LastWriteTime, Length | Format-Table -AutoSize | Out-String
}
"`n== Last install or upgrade"
Get-Content "$env:ProgramFiles\Fenrir Endpoint\runtime\setup-last.log" -Tail 15 -ErrorAction SilentlyContinue

"`n== Service and agent events (last 6 hours)"
Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddHours(-6) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like '*Fenrir*' } | Select-Object -First 15 TimeCreated, Id, Message | Format-List | Out-String
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddHours(-6) } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -like '*Fenrir*' -or $_.Message -like '*fenrir*' } | Select-Object -First 15 TimeCreated, ProviderName, Id, Message | Format-List | Out-String

"`n== Microsoft Defender detections today"
Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-1) } |
    Select-Object InitialDetectionTime, ThreatID, ActionSuccess, @{n='Files';e={$_.Resources -join '; '}} | Format-List | Out-String
"== End of report"
