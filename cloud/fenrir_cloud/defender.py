"""Managed Microsoft Defender: Defender as the prevention engine on Windows, with Fenrir's EDR, ML and DNS on top.

Most Microsoft 365 Business Premium customers already pay for Defender. With "Manage Microsoft Defender" on in policy,
Fenrir sets Defender's real-time and cloud protection, potentially-unwanted-app blocking, network protection,
controlled folder access, its attack surface reduction rules (taken from Fenrir's own rules, which Defender then
enforces before a program runs) and exclusions. It re-applies them every six hours and whenever the policy changes,
reads back what Defender actually has, and turns Defender's detections into Fenrir alerts, so they land in the inbox
with everything else. A device whose managed Defender is off or passive raises a protection alert.

No agent change is needed: the server queues a system PowerShell command (Set-MpPreference, Add-MpPreference,
Get-MpComputerStatus, Get-MpPreference, Get-MpThreatDetection) through the normal command channel and reads the JSON
it prints. Tamper protection cannot be switched on from a device; it is reported, with how to turn it on.
Without "managed", Fenrir only reads Defender's state, and raises nothing about it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Alert, Command, DefenderState, Device, Tenant, utcnow

log = logging.getLogger("fenrir.defender")

# Fenrir attack surface rule -> Defender ASR rule GUID. Rules without a Defender equivalent stay Fenrir-only.
ASR_GUIDS = {
    "blockOfficeChildProcesses": "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "blockOfficeExecutableContent": "3b576869-a4ec-4529-8536-b80a7769e899",
    "blockOfficeCodeInjection": "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "blockObfuscatedScripts": "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "blockScriptDownloadedPayloads": "d3e037e1-3eb8-44c8-a917-57927947596d",
    "blockEmailExecutables": "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "blockCredentialStealingLsass": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "blockPsexecWmiProcessCreation": "d1e49aac-8f56-4280-b9ba-993a6d77406c",
    "blockUntrustedUsbProcesses": "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    "blockWmiPersistence": "e6db77e5-3df2-4cf1-b95a-636979351e5b",
    "blockVulnerableSignedDrivers": "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "blockAdobeReaderChildProcesses": "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    "blockWebshellCreation": "a8f5898e-1dc8-49a9-9878-85004b8a61e6",
    "advancedRansomwareProtection": "c1db55ab-c21a-4637-bb3f-a12568109d35",
}
ASR_ACTION = {"off": "Disabled", "block": "Enabled", "audit": "AuditMode", "warn": "Warn"}
ASR_ACTION_NUMBER = {"off": 0, "block": 1, "audit": 2, "warn": 6}
TRISTATE = {"off": "Disabled", "block": "Enabled", "audit": "AuditMode"}
TRISTATE_NUMBER = {"off": 0, "block": 1, "audit": 2}
CLOUD = {"off": ("Disabled", "Default"), "default": ("Advanced", "Default"), "high": ("Advanced", "High"),
         "highPlus": ("Advanced", "HighPlus"), "zeroTolerance": ("Advanced", "ZeroTolerance")}
CLOUD_LEVEL_NUMBER = {"default": 0, "high": 2, "highPlus": 4, "zeroTolerance": 6, "off": 0}
SEVERITY = {5: "critical", 4: "high", 2: "medium", 1: "low"}
SAMPLES = {"safe": "SendSafeSamples", "all": "SendAllSamples", "never": "NeverSend"}
THREAT_ACTION = {"quarantine": "Quarantine", "remove": "Remove"}
DAYS = {"sunday": 1, "monday": 2, "tuesday": 3, "wednesday": 4, "thursday": 5, "friday": 6, "saturday": 7}
# Where the agent remembers which exclusions Fenrir added, so removing one from policy removes it from Defender.
MANAGED_KEY = r"HKLM:\SOFTWARE\Fenrir\Defender"
MARKER = "FENRIR-DEFENDER:"
CHECK_EVERY = timedelta(hours=6)
STALE_COMMAND = timedelta(hours=2)
SEEN_WITHIN = timedelta(days=1)
MAX_PER_TICK = 500
OFF_RULE = "defender:protection-off"
ACTIVE_MODES = {"normal", "edr block mode"}


def settings_for(db: Session, device: Device) -> dict:
    """The device's effective Defender and attack-surface settings."""
    from . import policy_schema, services

    tenant = db.get(Tenant, device.tenant_id)
    resolved = policy_schema.resolve(services.policy_layers(db, tenant, device=device))["settings"]
    return {"defender": resolved.get("defender") or {}, "attackSurface": resolved.get("attackSurface") or {}}


def revision(settings: dict) -> str | None:
    """Fingerprint of what Fenrir wants Defender to have; None when Defender is not managed."""
    if not settings["defender"].get("managed"):
        return None
    return hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:32]


def asr_wanted(settings: dict) -> dict[str, str]:
    """Defender rule GUID -> off | audit | warn | block, for the rules Defender has."""
    if not settings["defender"].get("enforceAttackSurfaceRules", True):
        return {}
    return {guid: settings["attackSurface"].get(key, "off") for key, guid in ASR_GUIDS.items()}


def _ps(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _ps_list(values) -> str:
    return "@(" + ",".join(_ps(v) for v in values) + ")"


def _bool(value) -> str:
    return "$true" if value else "$false"


def _clean(values, limit: int = 500) -> list[str]:
    return [str(v).strip()[:400] for v in (values or [])[:limit] if str(v).strip()]


# Fenrir's own Defender exclusions, from where the agent service is installed (the installer adds the same ones).
OWN_EXCLUSIONS = r"""$own = @{ ExclusionPath = @(); ExclusionProcess = @(); ExclusionExtension = @() }
try {
  $image = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\FenrirAgent' -Name ImagePath -ErrorAction Stop).ImagePath
  $exe = if ($image -match '^\s*"([^"]+)"') { $Matches[1] } else { ($image -split '\s+')[0] }
  $root = Split-Path -Parent $exe
  if ($root) {
    $own.ExclusionPath = @($root, (Join-Path $env:ProgramData 'FenrirAgent'))
    $own.ExclusionProcess = @('fenrir-agent-service.exe','fenrir-endpoint-client.exe','fenrir-pam.exe','fenrir-remote.exe','FenrirSetup.exe' |
      ForEach-Object { Join-Path $root $_ })
  }
} catch { }"""


def fenrir_own(path) -> bool:
    """One of Fenrir's own folders (kept excluded from Defender whatever the policy says)."""
    name = str(path).rstrip("\\/").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return name.startswith("fenrir")


def script(settings: dict) -> str:
    """PowerShell that applies the managed settings (when managed) and prints Defender's state as one JSON line."""
    d = settings["defender"]
    lines = ["$ErrorActionPreference = 'Stop'", "$errors = @()"]
    if d.get("managed"):
        maps, level = CLOUD[d.get("cloudProtection", "high")]
        action = THREAT_ACTION.get(d.get("threatAction", "quarantine"), "Quarantine")
        prefs = (f"-DisableRealtimeMonitoring ${'false' if d.get('realTimeProtection', True) else 'true'} "
                 f"-MAPSReporting {maps} -SubmitSamplesConsent {SAMPLES.get(d.get('sampleSubmission', 'safe'), 'SendSafeSamples')} "
                 f"-CloudBlockLevel {level} "
                 f"-PUAProtection {TRISTATE[d.get('puaProtection', 'block')]} "
                 f"-EnableNetworkProtection {TRISTATE[d.get('networkProtection', 'audit')]} "
                 f"-EnableControlledFolderAccess {TRISTATE[d.get('controlledFolderAccess', 'off')]}")
        lines.append(f"try {{ Set-MpPreference {prefs} }} catch {{ $errors += ('settings: ' + $_.Exception.Message) }}")
        scanning = (f"-DisableBlockAtFirstSeen {_bool(not d.get('blockAtFirstSight', True))} "
                    f"-DisableBehaviorMonitoring {_bool(not d.get('behaviorMonitoring', True))} "
                    f"-DisableScriptScanning {_bool(not d.get('scriptScanning', True))} "
                    f"-DisableIOAVProtection {_bool(not d.get('downloadScanning', True))} "
                    f"-DisableArchiveScanning {_bool(not d.get('archiveScanning', True))} "
                    f"-DisableEmailScanning {_bool(not d.get('emailScanning', True))} "
                    f"-DisableRemovableDriveScanning {_bool(not d.get('removableDriveScanning', True))} "
                    f"-LowThreatDefaultAction {action} -ModerateThreatDefaultAction {action} "
                    f"-HighThreatDefaultAction {action} -SevereThreatDefaultAction {action} "
                    f"-QuarantinePurgeItemsAfterDelay {int(d.get('quarantineRetentionDays', 90))} "
                    f"-SignatureUpdateInterval {int(d.get('signatureUpdateHours', 4))} "
                    f"-UILockdown {_bool(d.get('hideDefenderInterface', False))}")
        lines.append(f"try {{ Set-MpPreference {scanning} }} catch {{ $errors += ('scanning: ' + $_.Exception.Message) }}")
        # Scheduled scans: a daily quick scan at the hour chosen; a weekly full scan on the day chosen (8 = never).
        full_day = DAYS.get(str(d.get("fullScanDay", "off")), 8)
        schedule = (f"-ScanParameters 2 -ScanScheduleDay {full_day} -ScanScheduleTime (Get-Date -Hour {int(d.get('fullScanHour', 2))} -Minute 0 -Second 0)"
                    + (f" -ScanScheduleQuickScanTime (Get-Date -Hour {int(d.get('quickScanHour', 12))} -Minute 0 -Second 0)"
                       if d.get("quickScanDaily", True) else ""))
        lines.append(f"try {{ Set-MpPreference {schedule} }} catch {{ $errors += ('scan schedule: ' + $_.Exception.Message) }}")
        for field, parameter in (("controlledFolders", "ControlledFolderAccessProtectedFolders"),
                                 ("controlledFolderApps", "ControlledFolderAccessAllowedApplications")):
            if _clean(d.get(field)):
                lines.append(f"try {{ Add-MpPreference -{parameter} {_ps_list(_clean(d[field]))} }} "
                             f"catch {{ $errors += ('{parameter}: ' + $_.Exception.Message) }}")
        threats = [t for t in _clean(d.get("allowedThreats"), 200) if t.isdigit()]
        if threats:
            lines.append(f"try {{ Add-MpPreference -ThreatIDDefaultAction_Ids {_ps_list(threats)} "
                         f"-ThreatIDDefaultAction_Actions {_ps_list(['Allow'] * len(threats))} }} "
                         "catch { $errors += ('allowed threats: ' + $_.Exception.Message) }")
        rules = asr_wanted(settings)
        if rules:
            lines.append(f"try {{ Add-MpPreference -AttackSurfaceReductionRules_Ids {_ps_list(rules)} "
                         f"-AttackSurfaceReductionRules_Actions {_ps_list(ASR_ACTION[m] for m in rules.values())} }} "
                         "catch { $errors += ('attack surface rules: ' + $_.Exception.Message) }")
        # Exclusions follow the policy both ways. The agent remembers what Fenrir added (MANAGED_KEY); an exclusion that
        # leaves the policy is removed. "Only Fenrir's exclusions" removes every other exclusion as well.
        authoritative = bool(d.get("exclusionsAuthoritative"))
        lines.append(f"$key = {_ps(MANAGED_KEY)}; $managed = @{{}}")
        lines.append("try { $saved = (Get-ItemProperty -Path $key -Name ManagedExclusions -ErrorAction Stop).ManagedExclusions; "
                     "($saved | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $managed[$_.Name] = @($_.Value) } } catch { }")
        lines.append("try { $current = Get-MpPreference } catch { $current = $null }")
        lines.append("$applied = [ordered]@{}; $removed = @()")
        # Fenrir's own folders and programs stay excluded whatever the policy says: the installer adds them so Defender
        # never scans, blocks or quarantines the agent, and removing them leaves Defender fighting the agent.
        lines.append(OWN_EXCLUSIONS)
        for field, parameter in (("exclusionPaths", "ExclusionPath"), ("exclusionProcesses", "ExclusionProcess"),
                                 ("exclusionExtensions", "ExclusionExtension")):
            wanted = _clean(d.get(field))
            lines.append(f"$want = @({_ps_list(wanted)} + $own['{parameter}'] | Where-Object {{ $_ }} | Select-Object -Unique)")
            lines.append(f"$had = @($managed['{parameter}'])" if not authoritative else
                         f"$had = @($current.{parameter} | Where-Object {{ $_ -and -not ([string]$_).StartsWith('N/A') }})")
            lines.append("$drop = @($had | Where-Object { $_ -and ($want -notcontains $_) })")
            lines.append(f"if ($drop.Count) {{ try {{ Remove-MpPreference -{parameter} $drop; $removed += $drop }} "
                         f"catch {{ $errors += ('remove {parameter}: ' + $_.Exception.Message) }} }}")
            lines.append(f"if ($want.Count) {{ try {{ Add-MpPreference -{parameter} $want }} "
                         f"catch {{ $errors += ('{parameter}: ' + $_.Exception.Message) }} }}")
            lines.append(f"$applied['{parameter}'] = $want")
        lines.append("try { New-Item -Path $key -Force | Out-Null; Set-ItemProperty -Path $key -Name ManagedExclusions "
                     "-Value ($applied | ConvertTo-Json -Compress) } catch { $errors += ('remember exclusions: ' + $_.Exception.Message) }")
    lines.append(r"""
try { $status = Get-MpComputerStatus; $pref = Get-MpPreference } catch {
  Write-Output ('FENRIR-DEFENDER:' + (@{ available = $false; error = $_.Exception.Message; errors = $errors } | ConvertTo-Json -Compress))
  exit 0
}
$names = @{}
try { Get-MpThreat | ForEach-Object { $names[[string]$_.ThreatID] = @{ name = $_.ThreatName; severity = [int]$_.SeverityID } } } catch { }
$since = (Get-Date).AddDays(-30)
$detections = @()
try {
  $detections = @(Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt $since } | Sort-Object InitialDetectionTime -Descending |
    Select-Object -First 50 | ForEach-Object {
      $t = $names[[string]$_.ThreatID]
      [ordered]@{ id = [string]$_.DetectionID; threatId = [string]$_.ThreatID; name = $(if ($t) { $t.name } else { '' });
                  severity = $(if ($t) { $t.severity } else { 0 }); at = $_.InitialDetectionTime.ToUniversalTime().ToString('o');
                  resources = @($_.Resources | Select-Object -First 5); actionSuccess = [bool]$_.ActionSuccess;
                  status = [int]$_.ThreatStatusID; process = [string]$_.ProcessName; user = [string]$_.DomainUser }
    })
} catch { $errors += ('detections: ' + $_.Exception.Message) }
# Ages are unsigned; Defender reports "never" as 4294967295 (or 65535), which does not fit an Int32.
function Days($value) { if ($null -eq $value) { return $null }; $n = [int64]$value; if ($n -ge 65535) { return $null }; return $n }
try {
  $ids = @($pref.AttackSurfaceReductionRules_Ids); $actions = @($pref.AttackSurfaceReductionRules_Actions)
  $asr = [ordered]@{}
  for ($i = 0; $i -lt $ids.Count; $i++) { if ($ids[$i]) { $asr[([string]$ids[$i]).ToLower()] = [int64]$actions[$i] } }
  $out = [ordered]@{
    available = $true; mode = [string]$status.AMRunningMode; antivirus = [bool]$status.AntivirusEnabled;
    realTime = [bool]$status.RealTimeProtectionEnabled; tamper = [bool]$status.IsTamperProtected;
    signatureAgeDays = (Days $status.AntivirusSignatureAge); signatureVersion = [string]$status.AntivirusSignatureVersion;
    product = [string]$status.AMProductVersion; quickScanAgeDays = (Days $status.QuickScanAge);
    cloudBlockLevel = [int64]$pref.CloudBlockLevel; maps = [int64]$pref.MAPSReporting; pua = [int64]$pref.PUAProtection;
    blockAtFirstSight = -not [bool]$pref.DisableBlockAtFirstSeen; behaviorMonitoring = [bool]$status.BehaviorMonitorEnabled;
    downloadScanning = [bool]$status.IoavProtectionEnabled; uiLockdown = [bool]$pref.UILockdown;
    signatureUpdateHours = [int64]$pref.SignatureUpdateInterval; fullScanAgeDays = (Days $status.FullScanAge);
    exclusionsRemoved = @($removed);
    networkProtection = [int64]$pref.EnableNetworkProtection; controlledFolderAccess = [int64]$pref.EnableControlledFolderAccess;
    asr = $asr; exclusions = [ordered]@{ paths = @($pref.ExclusionPath | Where-Object { $_ }); processes = @($pref.ExclusionProcess | Where-Object { $_ });
                                   extensions = @($pref.ExclusionExtension | Where-Object { $_ }) };
    detections = $detections; errors = $errors
  }
  Write-Output ('FENRIR-DEFENDER:' + ($out | ConvertTo-Json -Depth 6 -Compress))
} catch {
  # Say what went wrong rather than exit with an error: the server keeps the last good state and shows this.
  Write-Output ('FENRIR-DEFENDER:' + (@{ reportError = ('report: ' + $_.Exception.Message); errors = $errors } | ConvertTo-Json -Compress))
}""")
    return "\n".join(lines)


def payload(settings: dict) -> dict:
    rev = revision(settings)
    return {"language": "powershell", "body": script(settings), "timeoutSeconds": 300, "runAs": "system",
            "scriptName": "Microsoft Defender: " + ("apply policy and report" if rev else "report"),
            "defender": "apply" if rev else "status", "defenderRevision": rev}


# --------------------------------------------------------------------------- sending checks


def is_candidate(device: Device, now: datetime) -> bool:
    return ((device.platform or "").lower() == "windows" and bool(device.approved) and device.api_key_hash != f"retired-{device.id}"
            and bool(device.last_seen_at) and device.last_seen_at >= now - SEEN_WITHIN)


def request(db: Session, device: Device, actor: str, settings: dict | None = None) -> Command:
    """Queue an apply-and-report (or report) on this device now."""
    from . import services

    settings = settings or settings_for(db, device)
    command = services.enqueue_command(db, device, "script.run", actor, payload=payload(settings),
                                       reason="Microsoft Defender " + ("policy and status" if revision(settings) else "status"))
    db.flush()
    state = db.get(DefenderState, device.id) or DefenderState(device_id=device.id, tenant_id=device.tenant_id)
    state.command_id, state.requested_at = command.id, utcnow()
    db.add(state)
    return command


def tick(db: Session, now: datetime | None = None) -> dict:
    """Hourly: re-apply where policy changed or six hours passed, and refresh state; one check in flight per device."""
    from . import services

    now = now or utcnow()
    sent = 0
    states = {s.device_id: s for s in db.execute(select(DefenderState)).scalars()}
    for device in db.execute(select(Device).where(Device.platform == "windows", Device.approved.is_(True),
                                                  Device.last_seen_at >= now - SEEN_WITHIN)).scalars():
        if sent >= MAX_PER_TICK:
            break
        if not is_candidate(device, now):
            continue
        state = states.get(device.id)
        if state and state.command_id:
            pending = db.get(Command, state.command_id)
            if pending is not None and pending.status in ("pending", "dispatched", "running") and \
                    state.requested_at and state.requested_at > now - STALE_COMMAND:
                continue
        settings = settings_for(db, device)
        due = state is None or state.checked_at is None or state.checked_at < now - CHECK_EVERY \
            or (revision(settings) is not None and state.applied_revision != revision(settings))
        if not due:
            continue
        try:
            request(db, device, "system:defender", settings)
            sent += 1
        except services.CommandError as exc:  # the emergency stop, or the device cannot take commands
            log.info("defender check not sent to %s: %s", device.hostname, exc)
    db.commit()
    return {"sent": sent}


# --------------------------------------------------------------------------- results


def parse(stdout: str) -> dict | None:
    for line in reversed((stdout or "").splitlines()):
        if line.startswith(MARKER):
            try:
                value = json.loads(line[len(MARKER):])
            except ValueError:
                return None
            return value if isinstance(value, dict) else None
    return None


def _file(resources) -> str:
    for resource in resources or []:
        text = str(resource)
        if text.lower().startswith("file:_"):
            return text[6:]
    return str((resources or [""])[0])


def _raise_detections(db: Session, device: Device, detections: list[dict]) -> int:
    known = set()
    for details in db.execute(select(Alert.details).where(Alert.device_id == device.id, Alert.rule_id.like("defender:%"))).scalars():
        known.add(str((details or {}).get("detectionId") or ""))
    raised = 0
    for item in detections[:50]:
        detection_id = str(item.get("id") or "")
        if not detection_id or detection_id in known:
            continue
        name = str(item.get("name") or f"threat {item.get('threatId')}")
        db.add(Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=f"defender:{item.get('threatId') or 'unknown'}",
                     title=f"Microsoft Defender: {name}"[:300], severity=SEVERITY.get(int(item.get("severity") or 0), "medium"),
                     mitre=[], event_ids=[],
                     details={"category": "malware", "source": "Microsoft Defender", "detectionId": detection_id,
                              "threatId": item.get("threatId"), "threatName": name, "file": _file(item.get("resources")),
                              "resources": item.get("resources") or [], "handled": bool(item.get("actionSuccess")),
                              "process": item.get("process"), "user": item.get("user"), "detectedAt": item.get("at"),
                              "description": "Microsoft Defender detected this and " +
                                             ("dealt with it (quarantined or removed)." if item.get("actionSuccess")
                                              else "could not finish dealing with it. Check the device.")}))
        known.add(detection_id)
        raised += 1
    return raised


def problems(status: dict, settings: dict) -> list[str]:
    """Why Defender is not doing what policy asks, in words; empty when it is."""
    if not status.get("available", True):
        return [f"Microsoft Defender is not available: {status.get('error') or 'not installed'}"]
    found = []
    mode = str(status.get("mode") or "").lower()
    if mode and mode not in ACTIVE_MODES:
        found.append(f"Defender is in {status.get('mode')}: another antivirus has taken over")
    if not status.get("antivirus"):
        found.append("Defender antivirus is turned off")
    if settings["defender"].get("realTimeProtection", True) and not status.get("realTime"):
        found.append("Defender real-time protection is off (Group Policy, tamper protection or another product may be holding it off)")
    drives = sorted({str(p) for p in (status.get("exclusions") or {}).get("paths") or [] if re.fullmatch(r"[A-Za-z]:\\?", str(p).strip())})
    if drives:
        found.append(f"Defender excludes whole drives ({', '.join(drives)}), so it scans almost nothing there")
    wanted = asr_wanted(settings)
    actual = status.get("asr") or {}
    drift = [guid for guid, m in wanted.items() if m != "off" and actual.get(guid) != ASR_ACTION_NUMBER[m]]
    if drift:
        found.append(f"{len(drift)} attack surface rules are not set as policy asks (tamper protection or Intune may be overriding them)")
    d = settings["defender"]
    if d.get("managed"):
        held = [label for key, label, want in (("blockAtFirstSight", "block at first sight", d.get("blockAtFirstSight", True)),
                                               ("behaviorMonitoring", "behaviour monitoring", d.get("behaviorMonitoring", True)),
                                               ("downloadScanning", "download scanning", d.get("downloadScanning", True)),
                                               ("uiLockdown", "hiding Defender's interface", d.get("hideDefenderInterface", False)))
                if key in status and bool(status[key]) != bool(want)
                # Both run inside real-time protection and read as off whenever it is; that is reported above.
                and not (key in ("behaviorMonitoring", "downloadScanning") and not status.get("realTime"))]
        if held:
            found.append("Defender is not following policy for " + ", ".join(held) + " (Group Policy, Intune or tamper protection may be overriding it)")
        if d.get("exclusionsAuthoritative"):
            wanted_paths = {str(p).lower() for p in d.get("exclusionPaths") or []}
            extra = [p for p in (status.get("exclusions") or {}).get("paths") or [] if str(p).lower() not in wanted_paths
                     and not str(p).startswith("N/A") and not fenrir_own(p)]
            if extra:
                found.append(f"Defender still has exclusions policy does not allow: {', '.join(map(str, extra[:5]))}")
    return found


def advice(status: dict) -> list[str]:
    tips = []
    if status.get("available", True) and not status.get("tamper"):
        tips.append("Tamper protection is off. Turn it on in the Microsoft Defender portal or Intune, so malware cannot switch Defender off.")
    if int(status.get("signatureAgeDays") or 0) > 3:
        tips.append(f"Defender's signatures are {status.get('signatureAgeDays')} days old. Check the device can reach Windows Update.")
    return tips


def _protection_alert(db: Session, device: Device, issues: list[str], managed: bool) -> None:
    open_alert = db.execute(select(Alert).where(Alert.device_id == device.id, Alert.rule_id == OFF_RULE,
                                                Alert.status.in_(("new", "triaged")))).scalars().first()
    off = managed and any("turned off" in i or "real-time" in i or " Mode" in i or "not available" in i for i in issues)
    if off and open_alert is None:
        db.add(Alert(tenant_id=device.tenant_id, device_id=device.id, rule_id=OFF_RULE, severity="high", mitre=["T1562.001"],
                     title=f"Microsoft Defender protection is off on {device.hostname}"[:300], event_ids=[],
                     details={"category": "protection", "source": "Microsoft Defender", "description": "; ".join(issues)}))
    elif not off and open_alert is not None:
        open_alert.status, open_alert.updated_at = "resolved", utcnow()
        open_alert.details = {**(open_alert.details or {}), "autoResolved": "Defender protection is back on."}


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    payload_ = command.payload or {}
    if not payload_.get("defender"):
        return
    state = db.get(DefenderState, device.id) or DefenderState(device_id=device.id, tenant_id=device.tenant_id)
    db.add(state)
    if state.command_id == command.id:
        state.command_id = None
    result = command.result or {}
    status = parse(str(result.get("stdout") or ""))
    if command.status != "completed" or status is None:
        state.error = (str(result.get("error") or result.get("stderr") or "") or f"The check ended {command.status}")[:500]
        return
    if status.get("reportError"):  # the device could not put its report together: keep the last good state
        state.error, state.checked_at = str(status["reportError"])[:500], utcnow()
        return
    settings = settings_for(db, device)
    state.status, state.checked_at = status, utcnow()
    state.error = "; ".join(status.get("errors") or [])[:500]
    if payload_.get("defender") == "apply" and status.get("available", True) and not status.get("errors") \
            and payload_.get("defenderRevision"):
        state.applied_revision = payload_["defenderRevision"]
    managed = bool(settings["defender"].get("managed"))
    if managed:
        _raise_detections(db, device, [d for d in status.get("detections") or [] if isinstance(d, dict)])
    _protection_alert(db, device, problems(status, settings), managed)


def view(db: Session, device: Device) -> dict:
    settings = settings_for(db, device)
    state = db.get(DefenderState, device.id)
    status = (state.status if state else None) or {}
    rev = revision(settings)
    iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731
    return {"managed": rev is not None, "status": status or None, "checkedAt": iso(state.checked_at if state else None),
            "requestedAt": iso(state.requested_at if state else None), "checking": bool(state and state.command_id),
            "inSync": rev is None or bool(state and state.applied_revision == rev), "error": state.error if state else "",
            "problems": problems(status, settings) if status else [], "advice": advice(status) if status else [],
            "rules": [{"key": key, "guid": guid, "wanted": asr_wanted(settings).get(guid, "off"),
                       "actual": next((m for m, n in ASR_ACTION_NUMBER.items() if (status.get("asr") or {}).get(guid) == n), None)}
                      for key, guid in ASR_GUIDS.items()]}


# --------------------------------------------------------------------------- one-off actions on a device

ACTIONS = {
    "quick_scan": ("Run a Microsoft Defender quick scan", "Start-MpScan -ScanType QuickScan"),
    "full_scan": ("Run a Microsoft Defender full scan", "Start-MpScan -ScanType FullScan -AsJob | Out-Null; 'Full scan started'"),
    "update_signatures": ("Update Microsoft Defender's definitions", "Update-MpSignature"),
    "remove_threats": ("Remove the active threats Microsoft Defender found", "Remove-MpThreat"),
}


def action(db: Session, device: Device, name: str, actor: str, threat_id: str = "") -> Command:
    """Queue one Defender action; the regular report runs after it so the console shows the result. ``allow_threat``
    allows one threat ID on this device only (a false positive); add it to the policy's allowed threats for everyone."""
    from . import services

    if name == "allow_threat":
        if not re.fullmatch(r"\d{1,20}", str(threat_id or "")):
            raise ValueError("Give the numeric Defender threat ID")
        title, cmdlet = (f"Allow Microsoft Defender threat {threat_id} on this device",
                         f"Add-MpPreference -ThreatIDDefaultAction_Ids {threat_id} -ThreatIDDefaultAction_Actions Allow")
    elif name in ACTIONS:
        title, cmdlet = ACTIONS[name]
    else:
        raise ValueError("Unknown Defender action")
    body = f"$ErrorActionPreference = 'Stop'\n{cmdlet}\n'{title}: done'"
    command = services.enqueue_command(db, device, "script.run", actor, reason=title,
                                       payload={"language": "powershell", "body": body, "timeoutSeconds": 3600, "runAs": "system",
                                                "scriptName": title})
    db.flush()
    request(db, device, actor)  # a fresh report afterwards
    return command
