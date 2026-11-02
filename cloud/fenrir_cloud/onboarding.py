"""Customer onboarding (FLOW-01): one checklist per customer, computed from what really exists, so it is resumable by
nature (leave it and come back; nothing is stored that can drift from reality) and every step shows real failures
(a Microsoft 365 connection that does not sync, a backup that failed, agents waiting for approval) with where to fix
them.

Steps: the customer's details (primary contact and site), an agreement, staff access, protection policy, agent
enrolment, agents reporting, Microsoft 365, backups, vulnerability scanning, monitoring and the compliance programme.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import presence
from .models import (BackupPlan, BackupRun, Contact, Contract, Device, EnrollmentToken, GrcAdoption, M365Connection, MonitorCondition,
                     Policy, Site, Tenant, User, VulnScan, utcnow)

DONE, TODO, FAILED, OPTIONAL = "done", "todo", "failed", "optional"


def _step(key: str, title: str, status: str, detail: str, link: str, required: bool = True) -> dict:
    return {"key": key, "title": title, "status": status, "detail": detail, "link": link, "required": required}


def _ancestors(db: Session, tenant: Tenant) -> list[str]:
    out, current = [], tenant
    while current is not None and current.parent_id:
        out.append(current.parent_id)
        current = db.get(Tenant, current.parent_id)
    return out


def checklist(db: Session, tenant: Tenant) -> dict:
    now = utcnow()
    tid = tenant.id
    steps: list[dict] = []

    contact = db.execute(select(Contact).where(Contact.account_tenant_id == tid).order_by(Contact.is_primary.desc())).scalars().first()
    site = db.execute(select(Site).where(Site.account_tenant_id == tid)).scalars().first()
    missing = [w for w, ok in (("a primary contact", contact is not None), ("a site address", site is not None)) if not ok]
    steps.append(_step("details", "Customer details", DONE if not missing else TODO,
                       f"{contact.name} ({contact.email or 'no email'}); {site.name}" if not missing
                       else "Add " + " and ".join(missing) + " so tickets, quotes and invoices reach the right person.",
                       f"/crm/accounts/{tid}"))

    contract = db.execute(select(Contract).where(Contract.account_tenant_id == tid, Contract.active.is_(True))).scalars().first()
    steps.append(_step("agreement", "Agreement", DONE if contract else TODO,
                       f"{contract.name} ({contract.plan})" if contract else "Create the support agreement: what is covered, SLA and billing.",
                       "/billing"))

    users = db.execute(select(User).where(User.active.is_(True))).scalars().all()
    named = [u for u in users if u.assigned_tenant_ids and tid in u.assigned_tenant_ids]
    everyone = [u for u in users if u.assigned_tenant_ids is None and u.role != "client"]
    steps.append(_step("staff", "Staff access", DONE if named else OPTIONAL if everyone else TODO,
                       f"Assigned to {', '.join(u.name or u.email for u in named[:5])}" if named
                       else f"{len(everyone)} staff can work on every customer; assign named technicians if this customer needs them."
                       if everyone else "Nobody can work on this customer yet: give a technician access.",
                       "/settings", required=not everyone))

    policy = db.get(Policy, tenant.default_policy_id) if tenant.default_policy_id else None
    steps.append(_step("policy", "Protection policy", DONE if policy else TODO,
                       f"New devices get '{policy.name}'" + (f" ({policy.template} template)" if policy.template else "")
                       if policy else "Choose the protection policy this customer's devices start with.", "/policies"))

    devices = [d for d in db.execute(select(Device).where(Device.tenant_id == tid)).scalars() if d.api_key_hash != f"retired-{d.id}"]
    approved = [d for d in devices if d.approved]
    waiting = [d for d in devices if not d.approved]
    token = db.execute(select(EnrollmentToken).where(EnrollmentToken.tenant_id == tid, EnrollmentToken.revoked.is_(False),
                                                     or_(EnrollmentToken.expires_at.is_(None), EnrollmentToken.expires_at > now))
                       ).scalars().first()
    steps.append(_step("enrolment", "Agent installer", DONE if token or approved else TODO,
                       f"Enrolment token '{token.label}' ({token.uses} use(s))" if token
                       else "Devices are enrolled" if approved else "Create an enrolment token or download this customer's installer.",
                       "/deploy"))

    online = [d for d in approved if presence.is_up(d, now)]
    silent = [d for d in approved if d.last_seen_at and now - d.last_seen_at > timedelta(days=7)]
    if waiting:
        status, detail = TODO, f"{len(waiting)} device(s) are waiting for approval: {', '.join(d.hostname for d in waiting[:5])}."
    elif not approved:
        status, detail = TODO, "No agent has enrolled yet. Run the installer on the customer's devices."
    elif silent:
        status, detail = FAILED, f"{len(silent)} device(s) have not reported for over 7 days: {', '.join(d.hostname for d in silent[:5])}."
    else:
        status, detail = DONE, f"{len(approved)} device(s), {len(online)} online."
    steps.append(_step("agents", "Agents reporting", status, detail, "/agent-health"))

    connections = db.execute(select(M365Connection).where(M365Connection.tenant_id == tid)).scalars().all()
    broken = [c for c in connections if c.status == "error" or c.last_error]
    if broken:
        status, detail = FAILED, f"{broken[0].name}: {broken[0].last_error or 'the connection is failing'}"
    elif connections and any(c.synced_at for c in connections):
        status, detail = DONE, f"{connections[0].tenant_name or connections[0].name}, synced {connections[0].synced_at:%d %b %H:%M}"
    elif connections:
        status, detail = TODO, "Connected; waiting for the first sync."
    else:
        status, detail = OPTIONAL, "Connect the customer's Microsoft 365 tenant (skip if they do not use it)."
    steps.append(_step("m365", "Microsoft 365", status, detail, "/m365", required=False))

    plans = db.execute(select(BackupPlan).where(BackupPlan.tenant_id == tid)).scalars().all()
    if plans:
        last = db.execute(select(BackupRun).where(BackupRun.tenant_id == tid).order_by(BackupRun.completed_at.desc())).scalars().first()
        if last is None:
            status, detail = TODO, f"{len(plans)} backup plan(s); no backup has reported yet."
        elif last.status not in ("success", "succeeded", "completed", "ok", "warning"):
            status, detail = FAILED, f"The last backup ({last.completed_at:%d %b %H:%M}) reported {last.status}."
        else:
            status, detail = DONE, f"{len(plans)} plan(s); last backup {last.completed_at:%d %b %H:%M}: {last.status}."
    else:
        status, detail = TODO, "Record what is backed up and connect its reports, so failures raise tickets."
    steps.append(_step("backup", "Backups", status, detail, "/backup"))

    scans = db.execute(select(func.count()).select_from(VulnScan).where(VulnScan.tenant_id == tid)).scalar() or 0
    auto = ((tenant.settings or {}).get("autoRemediation") or {}).get("enabled")
    steps.append(_step("vulnerabilities", "Vulnerability scanning", DONE if scans else TODO if approved else TODO,
                       f"{scans} scan(s) run" + ("; automatic remediation is on" if auto else "; automatic remediation is off")
                       if scans else "Run the first vulnerability scan once agents report.", "/vulnerabilities"))

    owners = [tid, *_ancestors(db, tenant)]
    monitors = db.execute(select(func.count()).select_from(MonitorCondition).where(
        MonitorCondition.enabled.is_(True), or_(MonitorCondition.tenant_id.in_(owners), MonitorCondition.tenant_id.is_(None)))).scalar() or 0
    steps.append(_step("monitoring", "Monitoring", DONE if monitors else TODO,
                       f"{monitors} monitor(s) apply (disk, services, offline and more)." if monitors
                       else "No monitor covers this customer: add monitors (or MSP-wide ones).", "/monitoring"))

    adoptions = db.execute(select(GrcAdoption).where(GrcAdoption.tenant_id == tid)).scalars().all()
    continuous = ((tenant.settings or {}).get("grcAutomation") or {}).get("enabled")
    if adoptions and continuous:
        status, detail = DONE, f"{', '.join(a.framework_key for a in adoptions[:4])}; evidence is collected automatically."
    elif adoptions:
        status, detail = TODO, f"{', '.join(a.framework_key for a in adoptions[:4])} adopted; turn on continuous compliance to collect evidence."
    else:
        status, detail = OPTIONAL, "Adopt a framework (Cyber Essentials, ISO 27001...) if the customer needs compliance reporting."
    steps.append(_step("compliance", "Compliance programme", status, detail, "/governance", required=False))

    required = [s for s in steps if s["required"]]
    done = [s for s in required if s["status"] == DONE]
    failed = [s for s in steps if s["status"] == FAILED]
    return {"tenantId": tid, "name": tenant.name, "steps": steps, "done": len(done), "total": len(required),
            "failed": len(failed), "ready": len(done) == len(required) and not failed}
