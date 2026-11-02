"""Vulnerability remediation ("Cyber Heal"): silent patching or uninstall through the agents' own commands.

A plan maps a vulnerability's fix onto a command the agents already run safely:

- a missing update the device itself reported (Windows Update KB, winget, apt/dnf) -> ``patch.install``
  with that one patch, exactly as an approved patch-window install;
- a vulnerable Linux package -> ``software.install`` with the package manager (installing an installed
  package upgrades only that package);
- a Windows program with a known winget ID -> ``software.install`` through winget (silent);
- ``uninstall`` mode -> ``software.uninstall`` with the same package identifiers.

Package names come from device inventory, so they are never pasted into a shell command: they travel as
data in the payload and each agent checks them against its own package-name rule. Nothing is guessed:
with no exact identifier there is no plan, and the reason says how to get one (usually a patch scan).

Each remediation records itself on the vulnerability (``remediation``) and on the command payload
(``vulnerabilityIds``). The command's result updates the record; only a later scan that no longer finds
the vulnerability marks it fixed (vulnmgmt verification), so a "successful" install proves nothing alone.

Automatic remediation is per customer (``Tenant.settings["autoRemediation"]``), off by default, update
only (never uninstall), limited to the priorities and EPSS floor it names, and paced per run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, services, vulnmgmt
from .models import Command, Device, DevicePatch, Tenant, Vulnerability, utcnow

_LINUX_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,127}$")
_WINGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
RETRY_AFTER = timedelta(hours=24)
# requireApproval: automatic remediation proposes the fix on the ticket and waits for a technician to approve it.
DEFAULT_AUTO = {"enabled": False, "priorities": ["P1"], "minEpss": 0.0, "maxPerRun": 25, "requireApproval": False}
# A fix the agent reported as applied must be confirmed by a rescan within this time, or it is reported unconfirmed.
VERIFY_WITHIN = timedelta(hours=24)
# Rescan a Linux/macOS device (OSV) at most this soon after its fix, and at most this many devices per pass.
RESCAN_AFTER = timedelta(minutes=10)
RESCANS_PER_PASS = 5


class RemediationError(ValueError):
    pass


@dataclass
class Plan:
    mode: str  # update | uninstall
    command_type: str
    payload: dict = field(default_factory=dict)
    description: str = ""
    destructive: bool = False
    record_id: str = ""  # software.uninstall names the package here, as library uninstalls do


def _linux_installer(device: Device, vuln: Vulnerability) -> str:
    ecosystem = str((vuln.evidence or {}).get("ecosystem") or "").lower()
    if any(name in ecosystem for name in ("debian", "ubuntu")):
        return "apt"
    if any(name in ecosystem for name in ("red hat", "rhel", "rocky", "alma", "fedora", "centos", "amazon", "oracle")):
        return "dnf"
    os_text = (device.os_version or "").lower()
    if any(name in os_text for name in ("debian", "ubuntu", "mint")):
        return "apt"
    if any(name in os_text for name in ("red hat", "rhel", "rocky", "alma", "fedora", "centos", "amazon", "oracle")):
        return "dnf"
    return ""


def _missing_patch(db: Session, device: Device, vuln: Vulnerability) -> DevicePatch | None:
    fix = vuln.fix or {}
    keys = [k for k in (fix.get("patchKey"), fix.get("update"), fix.get("ref") if fix.get("kind") == "kb" else None) if k]
    if fix.get("winget"):
        keys.append(f"winget:{fix['winget']}")
    rows = db.execute(select(DevicePatch).where(DevicePatch.device_id == device.id, DevicePatch.status.in_(("missing", "failed")))).scalars().all()
    for row in rows:
        if row.patch_key in keys:
            return row
    package = (vuln.package or "").lower()
    if package:
        for row in rows:
            if row.patch_key.lower().endswith(":" + package) or row.product.lower() == package:
                return row
    return None


def plan(db: Session, vuln: Vulnerability, mode: str = "update") -> Plan:
    if mode not in {"update", "uninstall"}:
        raise RemediationError("mode must be update or uninstall")
    if vuln.status not in vulnmgmt.UNRESOLVED:
        raise RemediationError("This vulnerability is already verified fixed")
    device = db.get(Device, vuln.device_id)
    if device is None or device.api_key_hash == f"retired-{device.id}":
        raise RemediationError("The device is no longer managed")
    fix = vuln.fix or {}
    tag = {"vulnerabilityIds": [vuln.id]}

    if mode == "update":
        patch = _missing_patch(db, device, vuln)
        if patch is not None:
            from .rmm import DEFAULT_REBOOT

            return Plan("update", "patch.install",
                        {"patchIds": [patch.patch_key], "patches": [{"id": patch.patch_key, "source": patch.source, "title": patch.title}],
                         "reboot": dict(DEFAULT_REBOOT), **tag},
                        f"Install {patch.title or patch.patch_key} ({patch.source}), which the device reports as missing")
        if vuln.source == "windows-update":
            raise RemediationError("The device has not reported this update as installable; run a patch scan first")

    if device.platform == "linux":
        installer = _linux_installer(device, vuln)
        if not installer:
            raise RemediationError("Unknown Linux package manager for this device")
        package = (vuln.package or "").strip()
        if not _LINUX_PACKAGE.fullmatch(package):
            raise RemediationError(f"'{package[:60]}' is not a valid {installer} package name")
        if mode == "update":
            return Plan("update", "software.install", {"installer": installer, "identifier": package, "action": "upgrade", **tag},
                        f"Upgrade {package} with {installer} (target {vuln.fixed_version or 'latest'})")
        return Plan("uninstall", "software.uninstall", {"installer": installer, "identifier": package, **tag},
                    f"Remove {package} with {installer}", destructive=True, record_id=package)

    if device.platform == "windows":
        winget = str(fix.get("winget") or "").strip()
        if not winget:
            raise RemediationError("No winget package ID is known for this program; run a patch scan so the device reports "
                                   "its available update, or remediate it manually")
        if not _WINGET_ID.fullmatch(winget):
            raise RemediationError(f"'{winget[:60]}' is not a valid winget package ID")
        if mode == "update":
            return Plan("update", "software.install", {"installer": "winget", "identifier": winget, **tag},
                        f"Update {vuln.package} silently with winget ({winget})")
        return Plan("uninstall", "software.uninstall", {"installer": "winget", "identifier": winget, **tag},
                    f"Uninstall {vuln.package} silently with winget ({winget})", destructive=True, record_id=winget)

    raise RemediationError(f"Automatic remediation is not available on {device.platform}")


def _ticket_for(db: Session, vuln: Vulnerability):
    """The remediation ticket for this finding: its own, an open one for the same CVE at this customer, or a new one."""
    from . import psa
    from .models import Ticket

    if vuln.ticket_id:
        ticket = db.get(Ticket, vuln.ticket_id)
        if ticket is not None:
            return ticket
    for (ticket_id,) in db.execute(select(Vulnerability.ticket_id).where(Vulnerability.tenant_id == vuln.tenant_id,
                                                                         Vulnerability.vuln_id == vuln.vuln_id,
                                                                         Vulnerability.ticket_id.is_not(None))).all():
        ticket = db.get(Ticket, ticket_id)
        if ticket is not None and not psa.is_closed(db, ticket):
            vuln.ticket_id = ticket.id
            return ticket
    return vulnmgmt.open_remediation_ticket(db, [vuln], "system:remediation")


def _note(db: Session, vuln: Vulnerability, text: str) -> None:
    from . import psa

    ticket = _ticket_for(db, vuln)
    host = db.execute(select(Device.hostname).where(Device.id == vuln.device_id)).scalar() or vuln.device_id
    psa.add_note(db, ticket, "system:remediation", f"{vuln.vuln_id} on {host}: {text}", kind="internal")


def propose(db: Session, vuln: Vulnerability, actor: str, mode: str = "update") -> dict:
    """Plan a fix and wait for a technician's approval on the ticket instead of running it. Raises RemediationError."""
    the_plan = plan(db, vuln, mode)
    vuln.remediation = {"mode": the_plan.mode, "status": "awaiting-approval", "description": the_plan.description,
                        "proposedAt": utcnow().isoformat() + "Z", "by": actor, "automatic": actor.startswith("system:")}
    _note(db, vuln, f"Fix proposed: {the_plan.description}. Approve it on the vulnerability to run it.")
    audit.record(db, actor, "vulnerability.remediation.proposed", f"{vuln.vuln_id}@{vuln.device_id}", vuln.tenant_id,
                 mode=the_plan.mode)
    return vuln.remediation


def execute(db: Session, vuln: Vulnerability, actor: str, mode: str = "update", *, automatic: bool = False) -> Command:
    """Queue the planned command and record it on the vulnerability. Raises RemediationError."""
    the_plan = plan(db, vuln, mode)
    device = db.get(Device, vuln.device_id)
    try:
        command = services.enqueue_command(db, device, the_plan.command_type, actor, payload=the_plan.payload, record_id=the_plan.record_id,
                                           reason=f"Remediate {vuln.vuln_id} ({vuln.package}): {the_plan.description}")
    except services.CommandError as exc:
        raise RemediationError(str(exc)) from exc
    db.flush()
    vuln.remediation = {"mode": the_plan.mode, "commandId": command.id, "commandType": command.type, "status": "queued",
                        "description": the_plan.description, "queuedAt": utcnow().isoformat() + "Z", "by": actor,
                        "automatic": automatic}
    if the_plan.mode == "update" and vuln.status == "open":
        vuln.status = "patching"  # a treatment, not a fix: verification still needs a clean rescan
        vuln.status_changed_at = utcnow()
        vulnmgmt.ensure_due_date(vuln)
    audit.record(db, actor, "vulnerability.remediation.queued", f"{vuln.vuln_id}@{vuln.device_id}", vuln.tenant_id,
                 mode=the_plan.mode, command=command.id, commandType=command.type, automatic=automatic)
    _note(db, vuln, f"Fix queued by {actor}: {the_plan.description}.")
    return command


def on_command_complete(db: Session, command: Command) -> None:
    """Record the agent's result on each vulnerability the command was remediating."""
    ids = (command.payload or {}).get("vulnerabilityIds") or []
    for vuln_id in ids[:50]:
        vuln = db.get(Vulnerability, vuln_id)
        if vuln is None or vuln.device_id != command.device_id:
            continue
        record = dict(vuln.remediation or {})
        if record.get("commandId") != command.id:
            continue
        record["status"] = command.status
        record["finishedAt"] = utcnow().isoformat() + "Z"
        if command.status != "completed":
            record["error"] = str((command.result or {}).get("error") or command.status)[:300]
            _note(db, vuln, f"The fix failed: {record['error']}. The vulnerability is open and the ticket stays open.")
            if vuln.status == "patching" and record.get("mode") == "update":
                vuln.status = "open"  # the install failed: the exposure is untreated again
                vuln.status_changed_at = utcnow()
        else:
            record["awaitingVerification"] = True
            _note(db, vuln, "The agent applied the fix. A rescan will confirm it; the ticket resolves when it does.")
            # A fresh software inventory lets the next scan see the new version (or the removal) straight away.
            device = db.get(Device, vuln.device_id)
            if device is not None and not record.get("inventoryRefresh"):
                try:
                    refresh = services.enqueue_command(db, device, "inventory.refresh", "system:remediation",
                                                       reason=f"Confirm the fix for {vuln.vuln_id}")
                    record["inventoryRefresh"] = refresh.id
                except services.CommandError:
                    pass
        vuln.remediation = record


# --------------------------------------------------------------------------- automatic remediation


def auto_settings(tenant: Tenant | None) -> dict:
    return {**DEFAULT_AUTO, **((tenant.settings or {}).get("autoRemediation") or {})} if tenant else dict(DEFAULT_AUTO)


def _recently_tried(vuln: Vulnerability) -> bool:
    queued = (vuln.remediation or {}).get("queuedAt")
    if not queued:
        return False
    from datetime import datetime

    try:
        at = datetime.fromisoformat(queued.rstrip("Z"))
    except ValueError:
        return False
    return utcnow() - at < RETRY_AFTER


def candidates(db: Session, tenant: Tenant, settings: dict) -> list[Vulnerability]:
    rows = db.execute(select(Vulnerability).where(Vulnerability.tenant_id == tenant.id, Vulnerability.status == "open")).scalars().all()
    devices = {d.id: d for d in db.execute(select(Device).where(Device.tenant_id == tenant.id)).scalars()}
    wanted = set(settings.get("priorities") or ["P1"])
    floor = float(settings.get("minEpss") or 0.0)
    out = []
    for vuln in rows:
        device = devices.get(vuln.device_id)
        if device is None or not device.approved or _recently_tried(vuln):
            continue
        if vulnmgmt.priority(vuln, elevated=vulnmgmt.device_elevated(device)) not in wanted:
            continue
        if floor and not vuln.known_exploited and (vuln.epss or 0.0) < floor:
            continue
        out.append(vuln)
    out.sort(key=lambda v: (-vulnmgmt.risk_score(v, devices[v.device_id].criticality), v.id))
    return out


def tick(db: Session) -> int:
    """Queue silent updates for customers that turned automatic remediation on. Never uninstalls."""
    queued = 0
    for tenant in db.execute(select(Tenant)).scalars():
        settings = auto_settings(tenant)
        if not settings.get("enabled"):
            continue
        budget = max(1, min(int(settings.get("maxPerRun") or 25), 200))
        for vuln in candidates(db, tenant, settings):
            if budget <= 0:
                break
            try:
                if settings.get("requireApproval"):
                    if (vuln.remediation or {}).get("status") == "awaiting-approval":
                        continue
                    propose(db, vuln, "system:auto-remediation", "update")
                else:
                    execute(db, vuln, "system:auto-remediation", "update", automatic=True)
            except RemediationError as exc:
                vuln.remediation = {**(vuln.remediation or {}), "status": "no-plan", "error": str(exc)[:300],
                                    "queuedAt": utcnow().isoformat() + "Z", "automatic": True}
                continue
            budget -= 1
            queued += 1
    return queued


# --------------------------------------------------------------------------- verification


def _parse(value) -> object:
    from datetime import datetime

    try:
        return datetime.fromisoformat(str(value).rstrip("Z"))
    except ValueError:
        return None


def verify_tick(db: Session, now=None) -> dict:
    """Confirm fixes the agents applied. Linux/macOS devices are rescanned (OSV) shortly after their fix; Windows
    findings are rechecked by the device's own Windows Update scan and the background program scan. A fix still
    unconfirmed after VERIFY_WITHIN is reported on the ticket and the finding returns to open."""
    from . import exposure

    now = now or utcnow()
    rows = db.execute(select(Vulnerability).where(Vulnerability.status == "patching")).scalars().all()
    pending = [v for v in rows if (v.remediation or {}).get("awaitingVerification")]
    rescanned: set[str] = set()
    out = {"rescanned": 0, "unconfirmed": 0}
    for vuln in pending:
        record = dict(vuln.remediation or {})
        finished = _parse(record.get("finishedAt"))
        if finished is None:
            continue
        if now - finished > VERIFY_WITHIN:
            record.update(awaitingVerification=False, status="unconfirmed",
                          error="A rescan still finds the vulnerability a day after the fix was applied.")
            vuln.remediation = record
            _note(db, vuln, "Not confirmed: a day after the fix, scans still find the vulnerability. It is open again; "
                            "check the device (a reboot may be pending, or the update did not take).")
            vuln.status, vuln.status_changed_at = "open", now  # after the note: opening a ticket marks it patching
            audit.record(db, "system:remediation", "vulnerability.remediation.unconfirmed", f"{vuln.vuln_id}@{vuln.device_id}",
                         vuln.tenant_id)
            out["unconfirmed"] += 1
            continue
        device = db.get(Device, vuln.device_id)
        if (device is None or device.platform == "windows" or device.id in rescanned or now - finished < RESCAN_AFTER
                or len(rescanned) >= RESCANS_PER_PASS or record.get("rescannedAt")):
            continue
        rescanned.add(device.id)
        try:
            exposure.scan_device(db, device)
        except Exception as exc:  # noqa: BLE001 - network dependent; the daily limit above still reports it
            services.log.warning("rescan of %s after a fix failed: %s", device.hostname, exc)
            continue
        for row in pending:
            if row.device_id == device.id and row.status == "patching":
                row.remediation = {**(row.remediation or {}), "rescannedAt": now.isoformat() + "Z"}
        out["rescanned"] += 1
    return out
