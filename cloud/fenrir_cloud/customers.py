"""Customer (tenant) management: edit, archive and restore, and permanent deletion.

**Archive** is reversible. An archived customer is hidden from customer lists and pickers, cannot enrol new devices,
and keeps every record. **Restore** undoes it.

**Delete** is permanent. A customer is deleted only when it has no sub-customers and is not the MSP itself or the
Unassigned holding area. It works in this order:

1. Decommission every device that still has a live agent key: end remote sessions, cancel commands, revoke the key.
   The agents stop reporting. They stay installed until someone uninstalls them on the machine.
2. Remove every record that belongs to the customer: every table with a ``tenant_id`` or ``account_tenant_id`` of
   this customer, the tables keyed only by its devices or users, and the files those records point to. This includes
   tickets, invoices and contracts the MSP holds about the customer.
3. Keep the audit log. Its rows are hash-chained, so removing some would break the integrity check for everything
   after them. The deletion itself is the last audit entry about the customer.

``deletion_report`` shows what step 2 will remove before anything happens.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from . import audit
from .config import get_settings
from .models import Base, Device, DeviceArtifact, GrcEvidence, Tenant, User, utcnow

KEEP = {"audit_log", "tenants"}
TENANT_COLUMNS = ("tenant_id", "account_tenant_id")
LABELS = {
    "devices": "Devices", "users": "Customer portal users", "psa_tickets": "Tickets", "psa_time_entries": "Time entries",
    "billing_invoices": "Invoices", "billing_contracts": "Contracts", "crm_contacts": "Contacts", "crm_opportunities": "Opportunities",
    "crm_projects": "Projects", "crm_activities": "Activities and tasks", "psa_quotes": "Quotes", "psa_configurations": "Configuration items",
    "psa_sites": "Sites", "alerts": "Alerts", "incidents": "Incidents", "events": "Telemetry events", "m365_connections": "Microsoft 365 connections",
    "policies": "Policies", "documents": "Documents", "vault_credentials": "Stored passwords", "device_artifacts": "Uploaded files",
    "grc_evidence": "Compliance evidence", "backup_plans": "Backup plans", "network_monitors": "Network monitors",
    "m365_log_entries": "Microsoft 365 log records", "vulnerabilities": "Vulnerabilities", "software_items": "Software inventory",
}


class CustomerError(Exception):
    pass


def archived(tenant: Tenant) -> bool:
    return bool((tenant.settings or {}).get("archived"))


def set_archived(db: Session, tenant: Tenant, archive: bool, actor: str) -> Tenant:
    if tenant.kind != "customer":
        raise CustomerError("Only customers can be archived.")
    settings = dict(tenant.settings or {})
    if archive:
        settings["archived"] = {"at": utcnow().isoformat() + "Z", "by": actor}
    else:
        settings.pop("archived", None)
    tenant.settings = settings
    audit.record(db, actor, "tenant.archived" if archive else "tenant.restored", tenant.name, tenant.id)
    return tenant


def _tables():
    """(table, how it links to a customer): tenant columns, or device_id / user_id for the tables keyed only by those."""
    for table in reversed(Base.metadata.sorted_tables):  # dependants before what they point at
        if table.name in KEEP:
            continue
        cols = [c for c in TENANT_COLUMNS if c in table.c]
        if cols:
            yield table, ("tenant", cols)
        elif "device_id" in table.c:
            yield table, ("device", ["device_id"])
        elif "user_id" in table.c:
            yield table, ("user", ["user_id"])


def _condition(table, link, tenant_id: str, device_ids: list[str], user_ids: list[str]):
    kind, cols = link
    if kind == "tenant":
        clauses = [table.c[c] == tenant_id for c in cols]
        return clauses[0] if len(clauses) == 1 else clauses[0] | clauses[1]
    ids = device_ids if kind == "device" else user_ids
    return table.c[cols[0]].in_(ids) if ids else None


def _blockers(db: Session, tenant: Tenant, actor_tenant_id: str | None) -> list[str]:
    out = []
    if tenant.kind != "customer":
        out.append("The MSP itself and the Unassigned area cannot be deleted.")
    if actor_tenant_id == tenant.id:
        out.append("You cannot delete the customer your own account belongs to.")
    children = db.scalar(select(func.count()).select_from(Tenant).where(Tenant.parent_id == tenant.id)) or 0
    if children:
        out.append(f"It has {children} sub-customer(s). Delete or move them first.")
    return out


def deletion_report(db: Session, tenant: Tenant, actor_tenant_id: str | None = None) -> dict:
    device_ids = list(db.scalars(select(Device.id).where(Device.tenant_id == tenant.id)))
    user_ids = list(db.scalars(select(User.id).where(User.tenant_id == tenant.id)))
    counts: dict[str, int] = {}
    for table, link in _tables():
        condition = _condition(table, link, tenant.id, device_ids, user_ids)
        if condition is None:
            continue
        n = db.scalar(select(func.count()).select_from(table).where(condition)) or 0
        if n:
            counts[table.name] = n
    live = sum(1 for ident, key in db.execute(select(Device.id, Device.api_key_hash).where(Device.tenant_id == tenant.id))
               if key != f"retired-{ident}")
    summary = [{"label": LABELS[name], "count": n} for name, n in counts.items() if name in LABELS]
    summary.sort(key=lambda r: -r["count"])
    other = sum(n for name, n in counts.items() if name not in LABELS)
    if other:
        summary.append({"label": "Other records", "count": other})
    return {"id": tenant.id, "name": tenant.name, "blockers": _blockers(db, tenant, actor_tenant_id), "liveDevices": live,
            "summary": summary, "tables": counts, "total": sum(counts.values()),
            "keeps": "The audit log keeps its entries about this customer, so its integrity check still holds."}


def delete_customer(db: Session, tenant: Tenant, actor: str, actor_tenant_id: str | None = None) -> dict:
    """Decommission live devices, then remove everything the customer owns. Commits; returns what was removed."""
    from . import remote
    from .routers import fleet

    blockers = _blockers(db, tenant, actor_tenant_id)
    if blockers:
        raise CustomerError(" ".join(blockers))
    ended = []
    for device in db.execute(select(Device).where(Device.tenant_id == tenant.id).with_for_update()).scalars().all():
        if device.api_key_hash != f"retired-{device.id}":
            _, sessions = fleet.retire(db, device, actor)
            ended += sessions
    db.flush()
    # Files on disk that the records point at.
    files: list[Path] = []
    root = get_settings().artifact_dir
    files += [root / name for name in db.scalars(select(DeviceArtifact.storage_name).where(DeviceArtifact.tenant_id == tenant.id)) if name]
    files += [root / "grc-evidence" / name for name in db.scalars(select(GrcEvidence.storage_name).where(GrcEvidence.tenant_id == tenant.id)) if name]

    name, tenant_id = tenant.name, tenant.id
    device_ids = list(db.scalars(select(Device.id).where(Device.tenant_id == tenant_id)))
    user_ids = list(db.scalars(select(User.id).where(User.tenant_id == tenant_id)))
    if "device_groups" in Base.metadata.tables:
        groups = Base.metadata.tables["device_groups"]
        db.execute(update(groups).where(groups.c.tenant_id == tenant_id).values(parent_id=None))  # self-reference
    removed: dict[str, int] = {}
    for table, link in _tables():
        condition = _condition(table, link, tenant_id, device_ids, user_ids)
        if condition is None:
            continue
        n = db.execute(delete(table).where(condition)).rowcount or 0
        if n:
            removed[table.name] = n
    db.delete(tenant)
    audit.record(db, actor, "tenant.deleted", name, tenant_id, removed=sum(removed.values()), devicesDecommissioned=len(device_ids))
    db.commit()
    for session in ended:
        remote.notify_session_end(session.id, actor)
    for path in files:
        path.unlink(missing_ok=True)
    return {"ok": True, "name": name, "removed": removed, "total": sum(removed.values())}
