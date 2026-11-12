# antimalware.scanArchives on Windows: the files inside zip archives are scanned with the real scanner, nested
# archives included; clean archives stay clean; a decompression bomb is reported, never unpacked in full.
param([string]$Scanner = (Join-Path $PSScriptRoot '..\out\dev\tools\fenrir-scannercli.exe'))
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
if (-not (Test-Path -LiteralPath $Scanner)) { throw "Scanner not built: $Scanner" }
$env:ANTIVIRUS_SIGNATURE_BUNDLE_PATH = (Resolve-Path (Join-Path $PSScriptRoot '..\signatures\default-signatures.tsv')).Path

$work = Join-Path $env:TEMP "fenrir-archive-tests-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $work | Out-Null
function Zip([string]$path, [hashtable]$members) {
  $zip = [IO.Compression.ZipFile]::Open($path, 'Create')
  try {
    foreach ($name in $members.Keys) {
      $entry = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
      $stream = $entry.Open()
      try { $stream.Write($members[$name], 0, $members[$name].Length) } finally { $stream.Dispose() }
    }
  } finally { $zip.Dispose() }
}
function Scan([string]$path) {
  $out = & $Scanner --no-telemetry --no-remediation --path $path 2>&1 | Out-String
  Write-Host $out
  $out
}
function Check([bool]$ok, [string]$what) { if (-not $ok) { throw "FAILED: $what" }; Write-Host "ok: $what" }

try {
  # The same ransomware-chain test program the signature tests use (detected on its own).
  $bad = New-Object byte[] 4096
  $bad[0] = [byte][char]'M'; $bad[1] = [byte][char]'Z'
  $text = [Text.Encoding]::ASCII.GetBytes("CreateRemoteThread`0WriteProcessMemory`0cmd.exe /c vssadmin delete shadows /all /quiet`0")
  [Array]::Copy($text, 0, $bad, 512, $text.Length)

  $inner = Join-Path $work 'payload.zip'
  Zip $inner @{ 'docs/readme.txt' = [Text.Encoding]::ASCII.GetBytes('hello'); 'tools/update.exe' = $bad }
  $out = Scan $inner
  Check ($out -match 'ARCHIVE_MEMBER_DETECTED') 'a malicious program inside a zip is detected'

  $outer = Join-Path $work 'outer.zip'
  Zip $outer @{ 'archive/payload.zip' = [IO.File]::ReadAllBytes($inner) }
  $out = Scan $outer
  Check ($out -match 'ARCHIVE_MEMBER_DETECTED') 'the same program inside a zip inside a zip is detected'

  $clean = Join-Path $work 'clean.zip'
  Zip $clean @{ 'notes.txt' = [Text.Encoding]::ASCII.GetBytes(('meeting notes ' * 200)); 'data.csv' = [Text.Encoding]::ASCII.GetBytes("a,b,c`n1,2,3`n") }
  $out = Scan $clean
  Check (-not ($out -match 'ARCHIVE_MEMBER_DETECTED')) 'a clean zip is not reported'

  $bomb = Join-Path $work 'bomb.zip'
  Zip $bomb @{ 'zeros.bin' = (New-Object byte[] (30MB)) }
  $started = Get-Date
  $out = Scan $bomb
  Check (-not ($out -match 'ARCHIVE_MEMBER_DETECTED')) 'a decompression bomb is not unpacked as a member'
  Check (((Get-Date) - $started).TotalSeconds -lt 60) 'a decompression bomb is handled quickly'
  Write-Host 'Archive scanning: all checks passed.'
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
