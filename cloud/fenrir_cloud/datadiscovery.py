"""PII discovery: which devices hold personal data, so their vulnerabilities rank higher.

Linux and macOS agents run the native ``pii.scan`` command (``fleet/pii.go``). Windows runs the PowerShell
script below through ``script.run`` with the same detectors; it prints one ``FENRIR-PII-RESULT:`` line.
Both report counts per type and file paths only, never the matched values.

Detectors: payment cards (issuer prefix + Luhn), UK National Insurance numbers (HMRC prefix rules), NHS
numbers (modulus 11, with "NHS" written just before), IBANs (ISO 13616 mod 97) and email addresses.
Cards, NI numbers, NHS numbers and IBANs are sensitive: finding any marks the device ``pii-high``, which
raises its vulnerabilities one priority level (vulnmgmt.priority).
"""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, services
from .models import Command, DataDiscoveryScan, Device, utcnow

SENSITIVE = {"payment-card", "uk-nino", "nhs-number", "iban"}
KNOWN_TYPES = SENSITIVE | {"email"}
MARKER = "FENRIR-PII-RESULT:"

WINDOWS_SCRIPT = r"""$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$maxFiles = 20000; $maxBytes = 20MB; $deadline = (Get-Date).AddMinutes(10)
$exts = @('.txt','.csv','.tsv','.log','.json','.xml','.md','.docx','.xlsx')
$badNino = @('BG','GB','NK','KN','TN','NT','ZZ')
function Test-Luhn([string]$n) { $sum = 0; $alt = $false
  for ($i = $n.Length - 1; $i -ge 0; $i--) { $d = [int][string]$n[$i]; if ($alt) { $d *= 2; if ($d -gt 9) { $d -= 9 } }; $sum += $d; $alt = -not $alt }
  return ($sum % 10) -eq 0 }
function Test-Issuer([string]$n) {
  if ($n.Length -lt 13 -or $n.Length -gt 19) { return $false }
  if ($n[0] -eq '4') { return $true }
  $two = [int]$n.Substring(0,2); $four = [int]$n.Substring(0,4)
  if (($two -ge 51 -and $two -le 55) -or ($four -ge 2221 -and $four -le 2720)) { return $true }
  if ($two -eq 34 -or $two -eq 37) { return $n.Length -eq 15 }
  return $n.StartsWith('6011') -or $n.StartsWith('65') }
function Test-Nhs([string]$n) { if ($n.Length -ne 10) { return $false }; $sum = 0
  for ($i = 0; $i -lt 9; $i++) { $sum += ([int][string]$n[$i]) * (10 - $i) }
  $check = 11 - ($sum % 11); if ($check -eq 11) { $check = 0 }
  return ($check -ne 10) -and ($check -eq [int][string]$n[9]) }
function Test-Iban([string]$raw) { $s = $raw -replace ' ', ''
  if ($s.Length -lt 15 -or $s.Length -gt 34) { return $false }
  $r = $s.Substring(4) + $s.Substring(0,4); $rem = 0
  foreach ($c in $r.ToCharArray()) {
    if ($c -ge '0' -and $c -le '9') { $rem = ($rem * 10 + [int][string]$c) % 97 }
    elseif ($c -ge 'A' -and $c -le 'Z') { $rem = ($rem * 100 + ([int]$c - 55)) % 97 }
    else { return $false } }
  return $rem -eq 1 }
function Get-Pii([string]$text) { $found = @{}
  foreach ($m in [regex]::Matches($text, '\b(?:\d[ -]?){12,18}\d\b')) { $n = $m.Value -replace '\D', ''
    if ((Test-Issuer $n) -and (Test-Luhn $n)) { $found['payment-card'] = 1 + [int]$found['payment-card'] } }
  foreach ($m in [regex]::Matches($text, '(?i)\b([A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z])\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D]\b')) {
    if ($badNino -notcontains $m.Groups[1].Value.ToUpper()) { $found['uk-nino'] = 1 + [int]$found['uk-nino'] } }
  foreach ($m in [regex]::Matches($text, '\b\d{3}[ -]\d{3}[ -]\d{4}\b')) { $start = [Math]::Max(0, $m.Index - 25)
    if ((Test-Nhs ($m.Value -replace '\D', '')) -and $text.Substring($start, $m.Index - $start).ToLower().Contains('nhs')) {
      $found['nhs-number'] = 1 + [int]$found['nhs-number'] } }
  foreach ($m in [regex]::Matches($text, '\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b')) {
    if (Test-Iban $m.Value) { $found['iban'] = 1 + [int]$found['iban'] } }
  $emails = [regex]::Matches($text, '(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b').Count
  if ($emails -gt 0) { $found['email'] = $emails }
  return $found }
function Get-OfficeText([string]$path) { $sb = New-Object System.Text.StringBuilder
  $zip = [System.IO.Compression.ZipFile]::OpenRead($path)
  try { foreach ($e in $zip.Entries) {
      if ($e.FullName -eq 'word/document.xml' -or $e.FullName -eq 'xl/sharedStrings.xml' -or $e.FullName -like 'xl/worksheets/sheet*') {
        $reader = New-Object System.IO.StreamReader($e.Open()); [void]$sb.Append($reader.ReadToEnd()); [void]$sb.Append(' '); $reader.Close() } } }
  finally { $zip.Dispose() }
  $xml = [regex]::Replace($sb.ToString(), '</(w:p|w:tc|c|si|row)>', ' ')
  return [regex]::Replace($xml, '<[^>]+>', '') }
$roots = @()
foreach ($userDir in Get-ChildItem 'C:\Users' -Directory -Force) {
  foreach ($sub in 'Documents','Desktop','Downloads','OneDrive') { $p = Join-Path $userDir.FullName $sub; if (Test-Path $p) { $roots += $p } } }
$counts = @{}; $files = New-Object System.Collections.ArrayList; $scanned = 0; $withPii = 0; $truncated = $false
:outer foreach ($root in $roots) {
  foreach ($f in Get-ChildItem $root -Recurse -File -Force) {
    if ($scanned -ge $maxFiles -or (Get-Date) -gt $deadline) { $truncated = $true; break outer }
    if ($exts -notcontains $f.Extension.ToLower() -or $f.Length -gt $maxBytes -or $f.FullName -match '\\\.') { continue }
    try { if ($f.Extension -in '.docx','.xlsx') { $text = Get-OfficeText $f.FullName } else { $text = [System.IO.File]::ReadAllText($f.FullName) } }
    catch { continue }
    $scanned++
    $found = Get-Pii $text
    if ($found.Count -gt 0) { $withPii++
      foreach ($k in $found.Keys) { $counts[$k] = [int]$counts[$k] + $found[$k] }
      [void]$files.Add([ordered]@{ path = $f.FullName; types = $found }) } } }
$weight = { param($t) $w = 0; foreach ($k in $t.Keys) { if ($k -eq 'email') { $w += $t[$k] } else { $w += 1000 * $t[$k] } }; $w }
$top = @($files | Sort-Object { & $weight $_.types } -Descending | Select-Object -First 100)
if ($files.Count -gt 100) { $truncated = $true }
$result = [ordered]@{ filesScanned = $scanned; filesWithPii = $withPii; counts = $counts; files = $top; truncated = $truncated; roots = $roots }
'FENRIR-PII-RESULT:' + ($result | ConvertTo-Json -Compress -Depth 6)
"""


def request_scan(db: Session, device: Device, actor: str) -> DataDiscoveryScan:
    if device.platform in {"linux", "macos"}:
        command = services.enqueue_command(db, device, "pii.scan", actor, payload={"piiScan": True},
                                           reason="PII discovery: find files holding personal data")
    elif device.platform == "windows":
        command = services.enqueue_command(db, device, "script.run", actor,
                                           payload={"language": "powershell", "body": WINDOWS_SCRIPT, "timeoutSeconds": 900,
                                                    "scriptName": "PII discovery", "piiScan": True},
                                           reason="PII discovery: find files holding personal data")
    else:
        raise services.CommandError(f"PII discovery is not available on {device.platform}")
    db.flush()
    scan = DataDiscoveryScan(tenant_id=device.tenant_id, device_id=device.id, command_id=command.id, requested_by=actor)
    db.add(scan)
    audit.record(db, actor, "pii.scan.requested", device.hostname, device.tenant_id, command=command.id)
    return scan


def _parse(command: Command) -> dict | None:
    result = command.result or {}
    if isinstance(result.get("pii"), dict):
        return result["pii"]
    for line in reversed(str(result.get("stdout") or "").splitlines()):
        if line.startswith(MARKER):
            try:
                parsed = json.loads(line[len(MARKER):])
            except json.JSONDecodeError:
                return None
            return parsed if isinstance(parsed, dict) else None
    return None


def _clean_counts(raw) -> dict:
    if not isinstance(raw, dict):
        return {}
    return {k: int(v) for k, v in raw.items() if k in KNOWN_TYPES and isinstance(v, (int, float)) and v >= 0}


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    scan = db.execute(select(DataDiscoveryScan).where(DataDiscoveryScan.command_id == command.id)).scalar_one_or_none()
    if scan is None or scan.device_id != device.id:
        return
    scan.completed_at = utcnow()
    parsed = _parse(command) if command.status == "completed" else None
    if parsed is None:
        scan.status = "failed"
        scan.error = str((command.result or {}).get("error") or "The device returned no PII discovery result")[:500]
        return
    scan.status = "completed"
    scan.files_scanned = int(parsed.get("filesScanned") or 0)
    scan.files_with_pii = int(parsed.get("filesWithPii") or 0)
    scan.counts = _clean_counts(parsed.get("counts"))
    scan.truncated = bool(parsed.get("truncated"))
    files = []
    for item in (parsed.get("files") or [])[:200]:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            files.append({"path": item["path"][:500], "types": _clean_counts(item.get("types"))})
    scan.files = files
    scan.sensitivity = "high" if SENSITIVE & set(scan.counts) else "low" if scan.counts else "none"
    flags = [f for f in (device.exposure_flags or []) if f != "pii-high"]
    if scan.sensitivity == "high":
        flags.append("pii-high")
    device.exposure_flags = flags
    audit.record(db, "system", "pii.scan.completed", device.hostname, device.tenant_id, sensitivity=scan.sensitivity,
                 filesWithPii=scan.files_with_pii)


def view(scan: DataDiscoveryScan, hostname: str = "") -> dict:
    return {"id": scan.id, "deviceId": scan.device_id, "hostname": hostname, "status": scan.status, "requestedBy": scan.requested_by,
            "requestedAt": scan.requested_at.isoformat() + "Z" if scan.requested_at else None,
            "completedAt": scan.completed_at.isoformat() + "Z" if scan.completed_at else None,
            "filesScanned": scan.files_scanned, "filesWithPii": scan.files_with_pii, "counts": scan.counts or {},
            "files": scan.files or [], "sensitivity": scan.sensitivity, "truncated": scan.truncated, "error": scan.error}
