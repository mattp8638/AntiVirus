# Clean-software false-positive suite: scans real, signed software installed on the Windows runner (Microsoft, Google,
# Mozilla, Git, Node.js, Python, Java, 7-Zip and others) with the real scanner, configured like an installed agent
# (the shipped signature bundle and trusted-publisher, known-good and observe-only lists).
#
# Fails when anything would be quarantined, or when software signed by a trusted publisher is reported at all.
# Other findings (unsigned tools) are listed for review: a clean machine should produce few or none.
param(
  [string]$Scanner = (Join-Path $PSScriptRoot '..\out\dev\tools\fenrir-scannercli.exe'),
  [int]$MaxFiles = 400,
  [int]$BatchSize = 100,
  [int]$BudgetMinutes = 12
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Scanner)) { throw "Scanner not built: $Scanner" }
$signatures = (Resolve-Path (Join-Path $PSScriptRoot '..\signatures')).Path
$env:ANTIVIRUS_SIGNATURE_BUNDLE_PATH = Join-Path $signatures 'default-signatures.tsv'
$env:ANTIVIRUS_CLEANWARE_SIGNERS_PATH = Join-Path $signatures 'default-cleanware-signers.tsv'
$env:ANTIVIRUS_KNOWN_GOOD_HASHES_PATH = Join-Path $signatures 'default-known-good-hashes.tsv'
$env:ANTIVIRUS_OBSERVE_ONLY_RULES_PATH = Join-Path $signatures 'default-observe-only.tsv'

# Trusted publishers: the shipped list plus the vendors whose software is on the runner image.
$trusted = @(Get-Content -LiteralPath $env:ANTIVIRUS_CLEANWARE_SIGNERS_PATH | Where-Object { $_ -and -not $_.StartsWith('#') } |
  ForEach-Object { ($_ -split "`t")[0].Trim().ToLowerInvariant() })

$roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:SystemRoot 'System32')) | Where-Object { $_ -and (Test-Path $_) }
$files = New-Object System.Collections.Generic.List[string]
foreach ($root in $roots) {
  # A spread across vendors, not thousands of files from one SDK: at most 25 programs per top-level folder.
  foreach ($dir in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
    Get-ChildItem -LiteralPath $dir.FullName -Recurse -File -Include *.exe, *.dll, *.ps1, *.msi -ErrorAction SilentlyContinue |
      Where-Object { $_.Length -gt 0 -and $_.Length -lt 16MB } | Select-Object -First 8 | ForEach-Object { $files.Add($_.FullName) }
  }
  Get-ChildItem -LiteralPath $root -File -Filter *.exe -ErrorAction SilentlyContinue | Select-Object -First 40 | ForEach-Object { $files.Add($_.FullName) }
}
$files = @($files | Select-Object -Unique | Select-Object -First $MaxFiles)
Write-Host "Scanning $($files.Count) installed files from $($roots -join ', ')"

$findings = New-Object System.Collections.Generic.List[object]
$clock = [Diagnostics.Stopwatch]::StartNew()
$scanned = 0
for ($i = 0; $i -lt $files.Count; $i += $BatchSize) {
  if ($clock.Elapsed.TotalMinutes -gt $BudgetMinutes) { Write-Warning "Time budget reached after $scanned files; judging what was scanned."; break }
  $batch = $files[$i..([Math]::Min($i + $BatchSize, $files.Count) - 1)]
  $scanArgs = @('--json', '--no-telemetry', '--no-remediation')
  foreach ($f in $batch) { $scanArgs += @('--path', $f) }
  $out = & $Scanner @scanArgs 2>$null | Out-String
  $start = $out.IndexOf('{"findings"')
  if ($start -lt 0) { Write-Warning "No JSON from the scanner for batch at $i"; continue }
  $parsed = $out.Substring($start) | ConvertFrom-Json
  foreach ($f in @($parsed.findings)) { if ($f -and $f.disposition -ne 'allow') { $findings.Add($f) } }
  $scanned += $batch.Count
  Write-Host ("  {0} files scanned, {1} findings, {2:n0}s" -f $scanned, $findings.Count, $clock.Elapsed.TotalSeconds)
}
if ($scanned -lt 50) { throw "FAILED: only $scanned files could be scanned in the time budget." }

$quarantined = @($findings | Where-Object { $_.disposition -eq 'quarantine' })
$trustedHits = @($findings | Where-Object { $s = "$($_.signer)".ToLowerInvariant(); $s -and ($trusted | Where-Object { $s.Contains($_) }) })
$rate = if ($scanned) { [Math]::Round(100.0 * $findings.Count / $scanned, 2) } else { 0 }
Write-Host "Findings: $($findings.Count) of $scanned files ($rate%); quarantine verdicts: $($quarantined.Count); trusted-publisher findings: $($trustedHits.Count)"
foreach ($f in $findings) {
  Write-Host ("  [{0}] {1} (signer: {2}; score {3}) {4}" -f $f.disposition, $f.path, $(if ($f.signer) { $f.signer } else { 'unsigned' }), $f.heuristicScore, (@($f.reasons) -join ','))
}
if ($quarantined.Count -gt 0) { throw "FAILED: $($quarantined.Count) clean installed file(s) would be quarantined." }
if ($trustedHits.Count -gt 0) { throw "FAILED: $($trustedHits.Count) file(s) signed by a trusted publisher were reported." }
if ($rate -gt 2) { throw "FAILED: $rate% of clean installed files were reported (limit 2%)." }
Write-Host 'Clean-software false-positive suite: passed.'
