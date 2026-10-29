"""Condition-based background remediation: detection + remediation script pairs run silently on a schedule.

Monitors (rmm.py) react to heartbeat metrics. Remediation packages cover any condition a script can test,
the way Intune proactive remediations do:

1. **detect** runs on each targeted device on the package's interval. Exit code 0 means compliant; exit code 1
   means the condition is present; anything else is a detection error.
2. If the condition is present and the package remediates automatically, **remediate** runs.
3. **verify** runs the detection script again. Only a passing verification counts as remediated; a failure is
   recorded (and can open a ticket). Each device keeps its latest result per package.

Everything runs through the agents' ordinary ``script.run`` command, without user interaction, and respects
each device's policy switch for script execution. Built-in packages are templates: enabling one for a customer
makes a copy the MSP can edit.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, services
from .models import Command, ConditionPackage, ConditionResult, Device, utcnow

PHASES = ("detect", "remediate", "verify")

BUILTIN: list[dict] = [
    {"key": "win-spooler", "name": "Print Spooler stopped", "platforms": ["windows"], "language": "powershell",
     "description": "Starts the Print Spooler when it has stopped. A spooler disabled on purpose (for example against PrintNightmare) is left alone.",
     "detection": r"""$s = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($null -eq $s) { 'Print Spooler is not installed'; exit 0 }
if ($s.StartType -eq 'Disabled') { 'Print Spooler is disabled on purpose'; exit 0 }
if ($s.Status -ne 'Running') { "Print Spooler is $($s.Status)"; exit 1 }
'Print Spooler is running'; exit 0""",
     "remediation": r"""Start-Service -Name Spooler -ErrorAction Stop
'Print Spooler started'"""},
    {"key": "win-firewall", "name": "Windows Firewall profile turned off", "platforms": ["windows"], "language": "powershell",
     "description": "Turns the Domain, Private and Public firewall profiles back on.",
     "detection": r"""$off = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
if ($off) { 'Firewall off for: ' + (($off | ForEach-Object Name) -join ', '); exit 1 }
'All firewall profiles are on'; exit 0""",
     "remediation": r"""Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
'Firewall profiles turned on'"""},
    {"key": "win-wuauserv", "name": "Windows Update service disabled", "platforms": ["windows"], "language": "powershell",
     "description": "Sets the Windows Update service back to Manual so updates and patching work.",
     "detection": r"""$s = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if ($null -ne $s -and $s.StartType -eq 'Disabled') { 'Windows Update service is disabled'; exit 1 }
'Windows Update service is enabled'; exit 0""",
     "remediation": r"""Set-Service -Name wuauserv -StartupType Manual -ErrorAction Stop
'Windows Update service set to Manual'"""},
    {"key": "win-time", "name": "Windows Time service not running", "platforms": ["windows"], "language": "powershell",
     "description": "Starts Windows Time and resynchronises the clock (Kerberos sign-in fails when clocks drift).",
     "detection": r"""$s = Get-Service -Name W32Time -ErrorAction SilentlyContinue
if ($null -eq $s) { 'Windows Time is not installed'; exit 0 }
if ($s.Status -ne 'Running') { "Windows Time is $($s.Status)"; exit 1 }
'Windows Time is running'; exit 0""",
     "remediation": r"""Set-Service -Name W32Time -StartupType Automatic -ErrorAction Stop
Start-Service -Name W32Time -ErrorAction Stop
w32tm /resync /force | Out-String"""},
    {"key": "win-low-disk", "name": "System drive below 10% free", "platforms": ["windows"], "language": "powershell",
     "description": "Removes temporary files older than 7 days from Windows and user temp folders when C: is below 10% free.",
     "detection": r"""$d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$pct = [math]::Round(100 * $d.FreeSpace / $d.Size, 1)
if ($pct -lt 10) { "C: has $pct% free"; exit 1 }
"C: has $pct% free"; exit 0""",
     "remediation": r"""$cutoff = (Get-Date).AddDays(-7); $freed = 0
$paths = @("$env:windir\Temp") + (Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' })
foreach ($p in $paths) { if (Test-Path $p) {
  Get-ChildItem $p -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff } |
    ForEach-Object { $size = $_.Length; Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; if ($?) { $freed += $size } } } }
"Freed {0:N1} MB" -f ($freed / 1MB)"""},
    {"key": "linux-disk", "name": "Root filesystem above 90% used", "platforms": ["linux"], "language": "bash",
     "description": "Trims the systemd journal to 7 days and clears the package cache when / is over 90% full.",
     "detection": r"""used=$(df --output=pcent / | tail -1 | tr -dc '0-9')
echo "/ is ${used}% used"
[ "$used" -gt 90 ] && exit 1
exit 0""",
     "remediation": r"""command -v journalctl >/dev/null && journalctl --vacuum-time=7d
command -v apt-get >/dev/null && apt-get clean
command -v dnf >/dev/null && dnf clean all
df -h /"""},
    {"key": "linux-ntp", "name": "Clock not synchronised", "platforms": ["linux"], "language": "bash",
     "description": "Turns on NTP synchronisation with timedatectl when the clock is not synchronised.",
     "detection": r"""command -v timedatectl >/dev/null || { echo "timedatectl not available"; exit 0; }
state=$(timedatectl show -p NTPSynchronized --value)
echo "NTP synchronised: $state"
[ "$state" = "yes" ] && exit 0
exit 1""",
     "remediation": r"""timedatectl set-ntp true
sleep 5
timedatectl status"""},
]


def seed(db: Session) -> None:
    """Built-in templates (tenant_id None, disabled); new ones arrive with upgrades without touching copies."""
    present = set(db.execute(select(ConditionPackage.builtin_key).where(ConditionPackage.tenant_id.is_(None))).scalars())
    for item in BUILTIN:
        if item["key"] in present:
            continue
        db.add(ConditionPackage(tenant_id=None, builtin_key=item["key"], name=item["name"], description=item["description"],
                                platforms=item["platforms"], language=item["language"], detection_script=item["detection"],
                                remediation_script=item["remediation"], enabled=False))


def enable_for(db: Session, template: ConditionPackage, tenant_id: str, actor: str, **overrides) -> ConditionPackage:
    copy = ConditionPackage(tenant_id=tenant_id, builtin_key=template.builtin_key, name=template.name, description=template.description,
                            platforms=list(template.platforms or []), language=template.language,
                            detection_script=template.detection_script, remediation_script=template.remediation_script,
                            enabled=True, created_by=actor, **overrides)
    db.add(copy)
    return copy


def _payload(package: ConditionPackage, phase: str) -> dict:
    body = package.remediation_script if phase == "remediate" else package.detection_script
    return {"language": package.language, "body": body, "timeoutSeconds": int(package.timeout_seconds or 300), "runAs": "system",
            "scriptName": f"{package.name} ({phase})", "conditionPackageId": package.id, "phase": phase}


def _result(db: Session, package: ConditionPackage, device: Device) -> ConditionResult:
    row = db.execute(select(ConditionResult).where(ConditionResult.package_id == package.id,
                                                   ConditionResult.device_id == device.id)).scalar_one_or_none()
    if row is None:
        row = ConditionResult(package_id=package.id, device_id=device.id, tenant_id=device.tenant_id)
        db.add(row)
    return row


def queue(db: Session, package: ConditionPackage, device: Device, phase: str, actor: str) -> Command:
    command = services.enqueue_command(db, device, "script.run", actor, payload=_payload(package, phase),
                                       reason=f"Condition remediation: {package.name} ({phase})")
    db.flush()
    row = _result(db, package, device)
    row.command_id, row.phase = command.id, phase
    if phase == "detect":
        row.last_detect_at = utcnow()
    return command


def targets(db: Session, package: ConditionPackage) -> list[Device]:
    from .deps import tenant_subtree
    from .rmm import resolve_targets

    if package.tenant_id is None:
        return []
    chosen = dict(package.targets or {})
    if not any(chosen.get(k) for k in ("deviceIds", "groupIds", "tenantIds")):
        chosen["tenantIds"] = [package.tenant_id]
    devices = resolve_targets(db, tenant_subtree(db, package.tenant_id), chosen)
    return [d for d in devices if d.platform in (package.platforms or [])]


def tick(db: Session, now=None) -> int:
    """Queue detection where it is due. Never stacks a new run on a device that has not answered the last."""
    now = now or utcnow()
    queued = 0
    for package in db.execute(select(ConditionPackage).where(ConditionPackage.enabled.is_(True),
                                                             ConditionPackage.tenant_id.is_not(None))).scalars():
        every = timedelta(hours=max(1, int(package.interval_hours or 24)))
        for device in targets(db, package):
            row = db.execute(select(ConditionResult).where(ConditionResult.package_id == package.id,
                                                           ConditionResult.device_id == device.id)).scalar_one_or_none()
            if row is not None:
                waiting = db.get(Command, row.command_id) if row.command_id else None
                if waiting is not None and waiting.status in ("pending", "dispatched", "running"):
                    continue
                if row.last_detect_at and now - row.last_detect_at < every:
                    continue
            try:
                queue(db, package, device, "detect", "system:condition-remediation")
                queued += 1
            except services.CommandError:
                continue
    return queued


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    payload = command.payload or {}
    package = db.get(ConditionPackage, payload.get("conditionPackageId") or "")
    if package is None or package.tenant_id is None:
        return
    row = _result(db, package, device)
    if row.command_id and row.command_id != command.id:
        return  # a stale result from an older run
    phase = payload.get("phase")
    result = command.result or {}
    exit_code = result.get("exitCode")
    output = (str(result.get("stdout") or "") + str(result.get("stderr") or "")).strip()[-1000:]
    now = utcnow()
    row.command_id = None
    if phase in ("detect", "verify"):
        row.detect_output = output
        if exit_code == 0:
            row.status = "remediated" if phase == "verify" else "compliant"
            if phase == "verify":
                row.last_remediated_at = now
        elif exit_code == 1 and phase == "detect":
            row.status = "noncompliant"
            if package.auto_remediate and package.remediation_script.strip():
                try:
                    queue(db, package, device, "remediate", "system:condition-remediation")
                    row.status = "remediating"
                except services.CommandError as exc:
                    row.status, row.detect_output = "failed", f"{output}\n{exc}"[-1000:]
        elif exit_code == 1:
            row.status = "failed"  # remediation ran but the condition is still present
            row.failures = (row.failures or 0) + 1
            _maybe_ticket(db, package, device, row)
        else:
            row.status = "error"  # detection could not decide (exit code other than 0/1, or it did not run)
    elif phase == "remediate":
        row.remediate_output = output
        row.attempts = (row.attempts or 0) + 1
        try:
            queue(db, package, device, "verify", "system:condition-remediation")
            row.status = "verifying"
        except services.CommandError:
            row.status = "failed"
    audit.record(db, "system:condition-remediation", f"condition.{phase}", f"{device.hostname}:{package.name}", device.tenant_id,
                 status=row.status, exitCode=exit_code)


def _maybe_ticket(db: Session, package: ConditionPackage, device: Device, row: ConditionResult) -> None:
    from . import psa
    from .models import Ticket

    if not package.ticket_on_failure:
        return
    if row.ticket_id:
        ticket = db.get(Ticket, row.ticket_id)
        if ticket is not None and not psa.is_closed(db, ticket):
            return
    ticket = services.open_ticket(db, device.tenant_id, f"Automatic remediation failed: {package.name} on {device.hostname}",
                                  f"The condition '{package.name}' is still present after remediation.\n\nLast detection output:\n"
                                  f"{row.detect_output}\n\nRemediation output:\n{row.remediate_output}",
                                  priority="P3", source="condition-remediation", device_id=device.id)
    row.ticket_id = ticket.id


def view(package: ConditionPackage, results: list[ConditionResult] | None = None) -> dict:
    out = {"id": package.id, "tenantId": package.tenant_id, "builtinKey": package.builtin_key, "name": package.name,
           "description": package.description, "platforms": package.platforms or [], "language": package.language,
           "detectionScript": package.detection_script, "remediationScript": package.remediation_script,
           "intervalHours": package.interval_hours, "autoRemediate": package.auto_remediate, "ticketOnFailure": package.ticket_on_failure,
           "enabled": package.enabled, "targets": package.targets or {}, "template": package.tenant_id is None}
    if results is not None:
        counts: dict[str, int] = {}
        for r in results:
            counts[r.status] = counts.get(r.status, 0) + 1
        out["results"] = counts
    return out
