# Scans two small test programs with the real scanner and the repository's signature bundle.
# A program that only uses Windows' standard process-memory functions (as Firefox, Chrome and many updaters do) must
# not be reported as BlackCat ransomware. One that also carries the ransomware's shadow-copy deletion must be.
param([string]$Scanner = (Join-Path $PSScriptRoot '..\out\dev\tools\fenrir-scannercli.exe'))
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Scanner)) { throw "Scanner not built: $Scanner" }
$env:ANTIVIRUS_SIGNATURE_BUNDLE_PATH = (Resolve-Path (Join-Path $PSScriptRoot '..\signatures\default-signatures.tsv')).Path

$work = Join-Path $env:TEMP "fenrir-signature-tests-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $work | Out-Null
function TestProgram([string]$name, [string]$strings) {
  $bytes = New-Object byte[] 4096
  $bytes[0] = [byte][char]'M'; $bytes[1] = [byte][char]'Z'
  $text = [Text.Encoding]::ASCII.GetBytes($strings)
  [Array]::Copy($text, 0, $bytes, 512, $text.Length)
  $path = Join-Path $work $name
  [IO.File]::WriteAllBytes($path, $bytes)
  $path
}
function Scan([string]$path) {
  $out = & $Scanner --no-telemetry --no-remediation --path $path 2>&1 | Out-String
  Write-Host $out
  $out
}
function Check([bool]$ok, [string]$what) { if (-not $ok) { throw "FAILED: $what" }; Write-Host "ok: $what" }

try {
  $browserLike = TestProgram 'browserlike.exe' "kernel32.dll`0CreateRemoteThread`0WriteProcessMemory`0VirtualAllocEx`0"
  $out = Scan $browserLike
  Check (-not ($out -match 'BLACKCAT_PROCESS_INJECTION_CHAIN')) 'standard process-memory functions alone are not BlackCat'

  $chain = TestProgram 'chain.exe' "CreateRemoteThread`0WriteProcessMemory`0cmd.exe /c vssadmin delete shadows /all /quiet`0"
  $out = Scan $chain
  Check ($out -match 'BLACKCAT_PROCESS_INJECTION_CHAIN') 'the whole chain (injection and shadow-copy deletion) is still detected'
  Write-Host 'Signature rule matching: all checks passed.'
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
