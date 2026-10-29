"""Entra ID reconciliation: does Fenrir's view of a customer match their Microsoft directory?

Compares the last Microsoft 365 sync of each connection with Fenrir's records for that customer:

- **People**: enabled member accounts with a licence but no PSA/CRM contact (new starters to add), and contacts at
  the customer's verified domains whose account is gone or disabled (leavers to retire).
- **Licences**: disabled accounts still holding licences (cost to reclaim).
- **MFA**: enabled members not registered for MFA, admins first.
- **Devices**: Intune-managed devices with no Fenrir agent (matched by serial number, then name), and Intune
  devices reported non-compliant.

Applying the report only touches Fenrir records (adds contacts, marks leavers' contacts). Directory changes
(licence removal, sign-in blocks) stay with the reviewed Microsoft action workflow.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, services
from .models import Contact, Device, M365Connection, Tenant

LEAVER_NOTE = "[left: no longer in the Microsoft 365 directory]"


def _norm(value) -> str:
    return str(value or "").strip().lower()


def report(db: Session, tenant: Tenant) -> dict:
    connections = db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant.id)).scalars().all()
    synced = [c for c in connections if c.snapshot and c.snapshot.get("users") is not None]
    users, mfa, intune, domains = {}, {}, [], set()
    intune_known = mfa_known = domains_known = False
    for connection in synced:
        snap = connection.snapshot
        for user in snap.get("users") or []:
            for key in {_norm(user.get("userPrincipalName")), _norm(user.get("mail"))} - {""}:
                users[key] = user
        if snap.get("mfaRegistration") is not None:
            mfa_known = True
            mfa.update({_norm(r.get("userPrincipalName")): r for r in snap["mfaRegistration"]})
        if snap.get("managedDevices") is not None:
            intune_known = True
            intune.extend(snap["managedDevices"])
        if snap.get("domains") is not None:
            domains_known = True
            domains.update(_norm(d.get("id")) for d in snap["domains"] if d.get("isVerified"))
    owner = services.msp_tenant_id(db, tenant.id)
    contacts = db.execute(select(Contact).where(Contact.tenant_id == owner, Contact.account_tenant_id == tenant.id)).scalars().all()
    contact_emails = {_norm(c.email) for c in contacts if c.email}
    members = {id(u): u for u in users.values()}.values()

    new_starters = sorted(({"userPrincipalName": u.get("userPrincipalName"), "displayName": u.get("displayName"), "jobTitle": u.get("jobTitle")}
                           for u in members if u.get("accountEnabled") is not False and u.get("userType", "Member") == "Member"
                           and u.get("assignedLicenses") and not ({_norm(u.get("userPrincipalName")), _norm(u.get("mail"))} & contact_emails)),
                          key=lambda x: _norm(x["userPrincipalName"]))
    leavers = []
    for contact in contacts:
        email = _norm(contact.email)
        if not email or LEAVER_NOTE in (contact.notes or ""):
            continue
        domain = email.rpartition("@")[2]
        if domains_known and domain not in domains:
            continue  # an external address: the directory cannot speak for it
        user = users.get(email)
        if user is None or user.get("accountEnabled") is False:
            leavers.append({"contactId": contact.id, "name": contact.name, "email": contact.email,
                            "reason": "account disabled" if user is not None else "no account in the directory"})
    disabled_licensed = sorted(u.get("userPrincipalName") for u in members if u.get("accountEnabled") is False and u.get("assignedLicenses"))
    no_mfa = sorted(({"userPrincipalName": r.get("userPrincipalName"), "admin": bool(r.get("isAdmin"))}
                     for key, r in mfa.items() if not r.get("isMfaRegistered") and users.get(key, {}).get("accountEnabled") is not False),
                    key=lambda x: (not x["admin"], _norm(x["userPrincipalName"])))
    devices = db.execute(select(Device).where(Device.tenant_id == tenant.id)).scalars().all()
    by_serial = {_norm(d.serial_number or (d.inventory or {}).get("serialNumber")): d for d in devices}
    by_serial.pop("", None)
    by_name = {_norm(d.hostname): d for d in devices}
    unmanaged, noncompliant = [], []
    for item in intune:
        serial, name = _norm(item.get("serialNumber")), _norm(item.get("deviceName"))
        agent = by_serial.get(serial) if serial else None
        agent = agent or by_name.get(name)
        entry = {"deviceName": item.get("deviceName"), "serialNumber": item.get("serialNumber"), "os": item.get("operatingSystem"),
                 "user": item.get("userPrincipalName"), "complianceState": item.get("complianceState"),
                 "fenrirDeviceId": agent.id if agent else None}
        if agent is None and str(item.get("operatingSystem") or "").lower() in ("windows", "macos", "linux"):
            unmanaged.append(entry)
        if str(item.get("complianceState") or "").lower() == "noncompliant":
            noncompliant.append(entry)
    return {"tenantId": tenant.id, "connections": len(connections), "synced": len(synced),
            "coverage": {"mfa": mfa_known, "intune": intune_known, "domains": domains_known},
            "newStarters": new_starters, "leavers": leavers, "disabledLicensed": disabled_licensed, "withoutMfa": no_mfa,
            "devicesWithoutAgent": unmanaged, "noncompliantDevices": noncompliant,
            "summary": {"newStarters": len(new_starters), "leavers": len(leavers), "disabledLicensed": len(disabled_licensed),
                        "withoutMfa": len(no_mfa), "adminsWithoutMfa": sum(1 for x in no_mfa if x["admin"]),
                        "devicesWithoutAgent": len(unmanaged), "noncompliantDevices": len(noncompliant)}}


def apply(db: Session, tenant: Tenant, actor: str, add_contacts: list[str], retire_contacts: list[str]) -> dict:
    """Add contacts for chosen new starters and mark chosen leavers. Only items in the current report qualify."""
    current = report(db, tenant)
    starters = {_norm(s["userPrincipalName"]): s for s in current["newStarters"]}
    leavers = {item["contactId"]: item for item in current["leavers"]}
    owner = services.msp_tenant_id(db, tenant.id)
    added, retired = [], []
    for upn in add_contacts:
        item = starters.get(_norm(upn))
        if item is None:
            continue
        db.add(Contact(tenant_id=owner, account_tenant_id=tenant.id, name=item.get("displayName") or item["userPrincipalName"],
                       email=item["userPrincipalName"], title=str(item.get("jobTitle") or "")[:120],
                       notes="Added from Microsoft 365 reconciliation"))
        added.append(item["userPrincipalName"])
    for contact_id in retire_contacts:
        if contact_id not in leavers:
            continue
        contact = db.get(Contact, contact_id)
        contact.notes = ((contact.notes or "") + "\n" + LEAVER_NOTE).strip()
        contact.is_primary = False
        retired.append(contact.email)
    audit.record(db, actor, "entra.reconciled", tenant.name, tenant.id, added=len(added), retired=len(retired))
    return {"added": added, "retired": retired}
