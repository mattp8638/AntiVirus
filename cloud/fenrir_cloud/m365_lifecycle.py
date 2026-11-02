"""Guided Microsoft 365 offboarding, onboarding and bulk user import, plus the expiry of temporary admin roles.

A workflow is planned (read-only: Fenrir looks at the user and shows every change it will make), reviewed, then run.
Running works through the steps in order and records each one's outcome before moving on:

- ``done`` / ``skipped``: finished.
- ``failed``: Microsoft refused; running again retries it (every step is safe to repeat, except creating a user,
  which checks first that the user does not exist yet).
- ``unknown``: Fenrir lost the answer (timeout, crash). It is never run again by itself: a technician checks Microsoft
  and marks it done, to retry or skipped.

A run stops starting new steps after ``RUN_BUDGET`` seconds and reports ``more``, so the console calls it again; long
bulk imports therefore never hold one web request open. Passwords Fenrir makes for new users come back in the run that
made them and are never stored.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from time import monotonic
from uuid import UUID
from urllib.parse import quote

import httpx
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from . import audit, crypto, events, hybrid_identity, m365, m365_admin, services
from .entra_reconcile import LEAVER_NOTE
from .models import Alert, Command, Contact, Device, M365Action, M365Connection, M365Workflow, utcnow

log = logging.getLogger("fenrir.m365.lifecycle")

RUN_BUDGET = 40.0
PLAN_VALID = timedelta(minutes=30)
STALE_RUN = timedelta(minutes=10)
BULK_MAX = 200


class PlanError(Exception):
    pass


# Steps carried out in Fenrir itself (no Microsoft or domain controller call).
FENRIR_STEPS = ("mark_contact", "add_contact", "open_ticket", "review_devices", "flag_credentials", "billing_effect")
CREDENTIAL_FLAG = "Belonged to a leaver: rotate this credential"


def _leaver_names(person: dict, upn: str) -> set[str]:
    """Ways the leaver's account appears on devices and in stored credentials."""
    names = {upn.lower(), upn.split("@")[0].lower()}
    for key in ("mail", "mailNickname", "onPremisesSamAccountName"):
        if person.get(key):
            names.add(str(person[key]).lower())
            names.add(str(person[key]).split("@")[0].lower())
    return {n for n in names if len(n) >= 2}


def _devices_used_by(db: Session, tenant_id: str, names: set[str]) -> list[Device]:
    out = []
    for device in db.execute(select(Device).where(Device.tenant_id == tenant_id, Device.approved.is_(True))).scalars():
        metrics = device.metrics or {}
        seen = [str(metrics.get("loggedOnUser") or "")] + [str(u) for u in metrics.get("users") or []]
        accounts = {a.lower().split("\\")[-1].split("@")[0] for a in seen if a}
        if accounts & names:
            out.append(device)
    return out


def _credentials_of(db: Session, tenant_id: str, names: set[str]) -> list:
    from .models import VaultCredential

    rows = db.execute(select(VaultCredential).where(VaultCredential.tenant_id == tenant_id, VaultCredential.archived.is_(False))).scalars()
    return [c for c in rows if c.username and (c.username.lower() in names or c.username.lower().split("\\")[-1].split("@")[0] in names)]


def _billing_lines(db: Session, tenant_id: str) -> list[str]:
    """Agreement lines counted from Microsoft 365 licences or users: they follow on the next invoice by themselves."""
    from .models import Contract

    lines = []
    for contract in db.execute(select(Contract).where(Contract.account_tenant_id == tenant_id, Contract.active.is_(True))).scalars():
        for addition in contract.additions or []:
            auto = str(addition.get("autoCount") or "")
            if auto.startswith("m365"):
                lines.append(f"{contract.name}: {addition.get('product') or auto} (counted from {auto})")
    return lines


def _step(key: str, title: str, detail: str, items: list | None = None, warning: str = "", where: str = "") -> dict:
    where = where or ("ad" if key.startswith("ad_") else "fenrir" if key in FENRIR_STEPS else "m365")
    return {"key": key, "title": title, "detail": detail, "items": items or [], "warning": warning, "status": "pending",
            "result": "", "at": None, "where": where}


AD_WAIT = timedelta(hours=1)  # how long a new AD user may take to appear in Microsoft 365


def _skus(client, headers) -> dict[str, str]:
    return {s.get("skuId"): s.get("skuPartNumber") or s.get("skuId") for s in
            m365.collect(client, m365.GRAPH + "/subscribedSkus", headers["Authorization"][7:])}


def _contacts(db: Session, tenant_id: str, *emails: str) -> list[Contact]:
    wanted = {e.strip().lower() for e in emails if e}
    if not wanted:
        return []
    return list(db.execute(select(Contact).where(Contact.account_tenant_id == tenant_id, func.lower(Contact.email).in_(wanted))).scalars())


# --- Planning ---------------------------------------------------------------------------------------------------

def plan_offboard(db: Session, connection: M365Connection, user_id: str, options: dict) -> tuple[str, list[dict]]:
    with m365_admin.session(connection) as (client, headers):
        token = headers["Authorization"][7:]
        try:
            person = m365_admin.request(client, headers, "GET", f"/users/{UUID(user_id)}?$select={m365_admin.USER_FIELDS},licenseAssignmentStates")
        except httpx.HTTPStatusError as exc:
            raise PlanError("Could not read the user." + m365_admin.microsoft_said(exc.response)) from None
        if person.get("userType") != "Member":
            raise PlanError("Offboarding is for member users of this directory.")
        upn = person.get("userPrincipalName") or user_id
        steps: list[dict] = []
        if person.get("onPremisesSyncEnabled"):
            steps += _hybrid_offboard_steps(db, connection, person, options)
        else:
            if options.get("blockSignIn"):
                steps.append(_step("block_signin", "Block sign-in", "The account can no longer sign in."))
            if options.get("resetPassword"):
                steps.append(_step("reset_password", "Reset the password", "Sets a random password nobody is told."))
        if options.get("revokeSessions"):
            steps.append(_step("revoke_sessions", "Sign out everywhere", "Ends existing sessions on every device (takes a few minutes)."))
        if options.get("removeMfa"):
            try:
                found = m365_admin.methods(client, headers, user_id)
                steps.append(_step("remove_mfa", "Remove MFA methods", ", ".join(m["label"] for m in found) or "None registered",
                                   [{"id": m["id"], "label": m["label"], "detail": m["detail"]} for m in found]))
            except httpx.HTTPStatusError as exc:
                steps.append(_step("remove_mfa", "Remove MFA methods", "Could not list them now; the step tries again when it runs.",
                                   warning="Microsoft refused to list sign-in methods." + m365_admin.microsoft_said(exc.response)))
        if options.get("outOfOffice"):
            message = str(options.get("outOfOfficeMessage") or "").strip()
            steps.append(_step("out_of_office", "Set an out-of-office reply", message[:200] or "(empty message)"))
        if options.get("removeGroups"):
            try:
                groups = m365.collect(client, m365.GRAPH + f"/users/{UUID(user_id)}/memberOf/microsoft.graph.group?$select={m365_admin.GROUP_FIELDS}&$top=999", token)
            except httpx.HTTPStatusError as exc:
                raise PlanError("Could not list the user's groups." + m365_admin.microsoft_said(exc.response)) from None
            removable, kept = [], []
            for g in groups:
                reason = m365_admin.group_restriction(g)
                (kept if reason else removable).append({"id": g.get("id"), "label": g.get("displayName") or g.get("id"), "reason": reason})
            steps.append(_step("remove_groups", "Remove from groups", f"{len(removable)} groups" + (f"; {len(kept)} left as they are" if kept else ""),
                               [{**g, "status": "pending"} for g in removable],
                               warning="Not removed: " + "; ".join(f"{g['label']} ({g['reason']})" for g in kept[:20]) if kept else ""))
        if options.get("removeRoles"):
            try:
                rows = m365_admin.request(client, headers, "GET", "/roleManagement/directory/roleAssignments?$expand=roleDefinition&$filter=" +
                                          quote(f"principalId eq '{UUID(user_id)}'", safe="="))
                roles = [{"id": r.get("id"), "label": (r.get("roleDefinition") or {}).get("displayName") or r.get("roleDefinitionId"),
                          "status": "pending"} for r in rows.get("value") or []]
                steps.append(_step("remove_roles", "Remove admin roles", ", ".join(r["label"] for r in roles) or "No admin roles", roles))
            except httpx.HTTPStatusError as exc:
                raise PlanError("Could not list the user's admin roles." + m365_admin.microsoft_said(exc.response)) from None
        if options.get("convertToShared") or options.get("mailboxDelegate") or options.get("forwardTo"):
            # Before any licence is removed: a shared mailbox keeps the mail without a licence.
            mailbox = person.get("mail") or upn
            parts = (["convert to a shared mailbox"] if options.get("convertToShared") else []) + \
                    ([f"full access for {options['mailboxDelegate']}"] if options.get("mailboxDelegate") else []) + \
                    ([f"forward new mail to {options['forwardTo']}"] if options.get("forwardTo") else [])
            steps.append(_step("mailbox_handover", "Hand over the mailbox", f"{mailbox}: " + ", ".join(parts),
                               [{"mailbox": mailbox, "convert": bool(options.get("convertToShared")),
                                 "delegate": options.get("mailboxDelegate") or None, "forwardTo": options.get("forwardTo") or None}]))
        if options.get("onedriveDelegate"):
            steps.append(_step("onedrive_handover", "Share their OneDrive", f"Edit access for {options['onedriveDelegate']} to move what "
                               "must be kept before the licence's 30-day grace period ends", [{"delegate": options["onedriveDelegate"]}]))
        if options.get("removeLicences"):
            names = _skus(client, headers)
            direct, inherited = [], []
            for state in person.get("licenseAssignmentStates") or []:
                entry = {"id": state.get("skuId"), "label": names.get(state.get("skuId"), state.get("skuId"))}
                (inherited if state.get("assignedByGroup") else direct).append(entry)
            if not person.get("licenseAssignmentStates"):
                direct = [{"id": l.get("skuId"), "label": names.get(l.get("skuId"), l.get("skuId"))} for l in person.get("assignedLicenses") or []]
            steps.append(_step("remove_licences", "Remove licences", ", ".join(d["label"] for d in direct) or "No directly assigned licences",
                               direct, warning=("Removing the licence deletes OneDrive after 30 days; the mailbox is kept because it "
                               "is converted to shared first." if options.get("convertToShared") else
                               "Removing the licence deletes the mailbox and OneDrive after 30 days. Tick 'Convert the mailbox to "
                               "shared' if its mail must be kept.")
                               + (" Licences from groups: " + ", ".join(i["label"] for i in inherited) + " (they go when the user leaves those groups)."
                                  if inherited else "")))
    if options.get("markContact"):
        found = _contacts(db, connection.tenant_id, upn, person.get("mail") or "")
        steps.append(_step("mark_contact", "Mark the Fenrir contact as left", ", ".join(c.name for c in found) or "No matching contact",
                           [{"id": c.id, "label": c.name} for c in found]))
    if options.get("reviewEstate", True):
        names = _leaver_names(person, upn)
        devices = _devices_used_by(db, connection.tenant_id, names)
        steps.append(_step("review_devices", "Devices they used", ", ".join(d.hostname for d in devices) or "No managed device shows them signed in",
                           [{"id": d.id, "label": d.hostname} for d in devices],
                           warning="Collect these, or reassign or wipe them (from each device's page); they are listed on the ticket."
                           if devices else ""))
        credentials = _credentials_of(db, connection.tenant_id, names)
        steps.append(_step("flag_credentials", "Flag their stored credentials for rotation",
                           ", ".join(c.name for c in credentials) or "No credential in the vault uses their account",
                           [{"id": c.id, "label": c.name} for c in credentials]))
        billing = _billing_lines(db, connection.tenant_id)
        steps.append(_step("billing_effect", "Billing", "; ".join(billing) if billing else
                           "No agreement line is counted from Microsoft 365 licences; nothing changes on invoices",
                           [{"label": line} for line in billing]))
    if options.get("openTicket"):
        steps.append(_step("open_ticket", "Record it on a ticket", "Opens a ticket with what was done and what is left to do by hand."))
    if not steps:
        raise PlanError("Choose at least one step.")
    return f"{person.get('displayName') or upn} ({upn})", steps


def _hybrid_offboard_steps(db: Session, connection: M365Connection, person: dict, options: dict) -> list[dict]:
    """A user synced from Active Directory: the account itself is changed in AD on the domain controller, then synced."""
    sam = person.get("onPremisesSamAccountName") or (person.get("onPremisesUserPrincipalName") or "").split("@")[0]
    ctx = hybrid_identity.context(db, connection.tenant_id)
    dc = ctx["controller"]
    options["adIdentity"] = sam
    if not dc or not sam:
        reason = ("no domain controller with the Fenrir agent is known for this customer" if not dc else
                  "Microsoft did not say which AD account this is")
        manual = _step("ad_manual", "Disable the account in Active Directory", f"Do this by hand: {reason}.", where="ad",
                       warning="This user is synced from Active Directory, so Microsoft refuses to block sign-in or reset the "
                               "password in the cloud. Disable the account and reset its password in Active Directory Users "
                               "and Computers; Entra Connect carries it to Microsoft 365.")
        manual.update(status="skipped", result="Needs doing by hand in Active Directory")
        return [manual]
    on = f"on {dc['hostname']}" + ("" if dc["online"] else " (its agent is offline now: the step waits for it)")
    steps = [_step("ad_disable", "Disable the account in Active Directory", f"{sam} {on}", items=[{"deviceId": dc["deviceId"]}])]
    if options.get("resetPassword", True):
        steps.append(_step("ad_scramble", "Set a random AD password", "Generated on the domain controller; nobody is told it.",
                           items=[{"deviceId": dc["deviceId"]}]))
    if options.get("removeGroups", True):
        steps.append(_step("ad_remove_groups", "Remove from Active Directory groups", "Every group except the primary one (Domain Users)",
                           items=[{"deviceId": dc["deviceId"]}]))
    if options.get("adMoveOu"):
        steps.append(_step("ad_move", "Move to the leavers OU", str(options["adMoveOu"])[:300], items=[{"deviceId": dc["deviceId"]}]))
    if options.get("hideFromAddressBook"):
        steps.append(_step("ad_hide_gal", "Hide from the address book", "Only where AD has Exchange attributes",
                           items=[{"deviceId": dc["deviceId"]}]))
    steps.append(_step("ad_describe", "Note the leaving date on the account", "In the account's description",
                       items=[{"deviceId": dc["deviceId"]}]))
    sync = ctx["syncServer"]
    if sync:
        steps.append(_step("ad_sync", "Sync to Microsoft 365 now", f"Entra Connect delta sync on {sync['hostname']}",
                           items=[{"deviceId": sync["deviceId"]}]))
    else:
        note = _step("ad_sync", "Sync to Microsoft 365", "Entra Connect syncs by itself within 30 minutes", where="ad",
                     warning="Fenrir has not found the server running Entra Connect (it needs the Fenrir agent), so it cannot "
                             "start the sync early.")
        note.update(status="skipped", result="Entra Connect syncs within 30 minutes")
        steps.append(note)
    return steps


def plan_onboard(db: Session, connection: M365Connection, options: dict) -> tuple[str, list[dict]]:
    if options.get("createIn") == "ad":
        return _plan_hybrid_onboard(db, connection, options)
    profile = options["profile"]
    with m365_admin.session(connection) as (client, headers):
        try:
            m365_admin.validate_new_user(client, headers, profile)
        except m365_admin.ProviderError as exc:
            raise PlanError(str(exc)) from None
        steps = [_step("create_user", "Create the user", f"{profile['displayName']} ({profile['userPrincipalName']}), usage location "
                       f"{profile['usageLocation']}. Fenrir makes a temporary password and shows it once.")]
        if options.get("managerId"):
            manager = m365_admin.user(client, headers, options["managerId"])
            steps.append(_step("set_manager", "Set their manager", manager.get("displayName") or manager.get("userPrincipalName") or "",
                               [{"id": manager.get("id"), "label": manager.get("userPrincipalName")}]))
        if options.get("skuIds"):
            names = _skus(client, headers)
            missing = [s for s in options["skuIds"] if s not in names]
            if missing:
                raise PlanError("A chosen licence is not in this tenant.")
            steps.append(_step("assign_licences", "Assign licences", ", ".join(names[s] for s in options["skuIds"]),
                               [{"id": s, "label": names[s]} for s in options["skuIds"]]))
        if options.get("groupIds"):
            items = []
            for gid in options["groupIds"]:
                try:
                    g = m365_admin.group(client, headers, gid)
                except m365_admin.ProviderError as exc:
                    raise PlanError(str(exc)) from None
                items.append({"id": g.get("id"), "label": g.get("displayName"), "status": "pending"})
            steps.append(_step("add_groups", "Add to groups", ", ".join(i["label"] for i in items), items))
    if options.get("addContact"):
        steps.append(_step("add_contact", "Add a Fenrir contact", f"{profile['displayName']} for this customer"))
    if options.get("openTicket"):
        steps.append(_step("open_ticket", "Record it on a ticket", "Opens a ticket with what was done."))
    return f"{profile['displayName']} ({profile['userPrincipalName']})", steps


def _plan_hybrid_onboard(db: Session, connection: M365Connection, options: dict) -> tuple[str, list[dict]]:
    """A new starter created in Active Directory, synced by Entra Connect, then licensed in Microsoft 365."""
    profile, ad = options["profile"], options.get("ad") or {}
    ctx = hybrid_identity.context(db, connection.tenant_id)
    dc = ctx["controller"]
    if not dc:
        raise PlanError("No domain controller with the Fenrir agent is known for this customer, so the user cannot be created in AD.")
    upn = profile["userPrincipalName"]
    suffixes = [str(x).lower() for x in ((ctx.get("options") or {}).get("upnSuffixes") or [])]
    if suffixes and upn.rsplit("@", 1)[1].lower() not in suffixes:
        raise PlanError(f"{upn.rsplit('@', 1)[1]} is not a UPN suffix of this Active Directory ({', '.join(suffixes)}).")
    with m365_admin.session(connection) as (client, headers):
        try:
            m365_admin.request(client, headers, "GET", "/users/" + quote(upn, safe="") + "?$select=id")
            raise PlanError(f"{upn} already exists in Microsoft 365.")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise PlanError("Could not check the sign-in name." + m365_admin.microsoft_said(exc.response)) from None
        manager_sam, manager_cloud = "", None
        if options.get("managerId"):
            manager = m365_admin.user(client, headers, options["managerId"])
            if manager.get("onPremisesSyncEnabled") and manager.get("onPremisesSamAccountName"):
                manager_sam = manager["onPremisesSamAccountName"]
            else:
                manager_cloud = manager
        names = _skus(client, headers) if options.get("skuIds") else {}
        if any(s not in names for s in options.get("skuIds") or []):
            raise PlanError("A chosen licence is not in this tenant.")
        groups = []
        for gid in options.get("groupIds") or []:
            try:
                g = m365_admin.group(client, headers, gid)
            except m365_admin.ProviderError as exc:
                raise PlanError(str(exc)) from None
            groups.append({"id": g.get("id"), "label": g.get("displayName"), "status": "pending"})
    sam = (ad.get("sam") or upn.split("@")[0])[:20]
    options["adIdentity"] = sam
    options["adManager"] = manager_sam
    ad_groups = [str(g) for g in ad.get("groups") or []][:50]
    where = ad.get("ou") or (ctx.get("options") or {}).get("usersContainer") or "the default Users container"
    steps = [_step("ad_create", "Create the account in Active Directory",
                   f"{profile['displayName']} ({sam}, {upn}) in {where} on {dc['hostname']}" +
                   (f"; groups: {', '.join(g.split(',')[0].removeprefix('CN=') for g in ad_groups)}" if ad_groups else "") +
                   ("; manager " + manager_sam if manager_sam else "") + ". Fenrir makes a temporary password and shows it once.",
                   items=[{"deviceId": dc["deviceId"]}])]
    sync = ctx["syncServer"]
    if sync:
        steps.append(_step("ad_sync", "Sync to Microsoft 365 now", f"Entra Connect delta sync on {sync['hostname']}",
                           items=[{"deviceId": sync["deviceId"]}]))
    steps.append(_step("wait_cloud", "Wait for the user in Microsoft 365", "Entra Connect brings the account across "
                       + ("in a minute or two" if sync else "within 30 minutes (Fenrir cannot start the sync: no agent on the Entra Connect server)")))
    steps.append(_step("set_usage_location", "Set the usage location", profile["usageLocation"]))
    if manager_cloud:
        steps.append(_step("set_manager", "Set their manager", manager_cloud.get("displayName") or "",
                           [{"id": manager_cloud.get("id"), "label": manager_cloud.get("userPrincipalName")}],
                           warning="The manager is a cloud-only user, so Microsoft may refuse this for a synced account."))
    if options.get("skuIds"):
        steps.append(_step("assign_licences", "Assign licences", ", ".join(names[s] for s in options["skuIds"]),
                           [{"id": s, "label": names[s]} for s in options["skuIds"]]))
    if groups:
        steps.append(_step("add_groups", "Add to Microsoft 365 groups", ", ".join(i["label"] for i in groups), groups))
    if options.get("addContact"):
        steps.append(_step("add_contact", "Add a Fenrir contact", f"{profile['displayName']} for this customer"))
    if options.get("openTicket"):
        steps.append(_step("open_ticket", "Record it on a ticket", "Opens a ticket with what was done."))
    return f"{profile['displayName']} ({upn})", steps


def plan_bulk(db: Session, connection: M365Connection, options: dict) -> tuple[str, list[dict]]:
    rows = options["rows"]
    if not rows or len(rows) > BULK_MAX:
        raise PlanError(f"Import 1 to {BULK_MAX} users at a time.")
    steps: list[dict] = []
    seen: set[str] = set()
    with m365_admin.session(connection) as (client, headers):
        domains: dict[str, str] = {}
        names = _skus(client, headers) if options.get("skuIds") else {}
        if any(s not in names for s in options.get("skuIds") or []):
            raise PlanError("A chosen licence is not in this tenant.")
        for gid in options.get("groupIds") or []:
            try:
                m365_admin.group(client, headers, gid)
            except m365_admin.ProviderError as exc:
                raise PlanError(str(exc)) from None
        for row in rows:
            upn = row["userPrincipalName"]
            step = _step("create_user", row["displayName"], upn, [{"profile": row}])
            domain = upn.rsplit("@", 1)[1].lower()
            reason = ""
            if upn.lower() in seen:
                reason = "This sign-in name appears twice in the file."
            seen.add(upn.lower())
            if not reason:
                if domain not in domains:
                    try:
                        info = m365_admin.request(client, headers, "GET", "/domains/" + quote(domain, safe=""))
                        domains[domain] = "" if info.get("isVerified") and info.get("authenticationType") == "Managed" else \
                            "The domain is not a verified managed domain in this tenant."
                    except httpx.HTTPStatusError:
                        domains[domain] = "The domain is not in this tenant."
                reason = domains[domain]
            if not reason:
                try:
                    m365_admin.request(client, headers, "GET", "/users/" + quote(upn, safe="") + "?$select=id")
                    reason = "A user with this sign-in name already exists."
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code != 404:
                        reason = "Could not check this sign-in name." + m365_admin.microsoft_said(exc.response)
            if reason:
                step.update(status="skipped", result=reason)
            steps.append(step)
    if all(s["status"] == "skipped" for s in steps):
        raise PlanError("None of the rows can be imported: " + "; ".join(f"{s['detail']}: {s['result']}" for s in steps[:5]))
    ready = sum(1 for s in steps if s["status"] == "pending")
    return f"{ready} new users", steps


PLANNERS = {"offboard": plan_offboard, "onboard": plan_onboard, "bulk_create": plan_bulk}


def plan(db: Session, connection: M365Connection, kind: str, target_id: str | None, options: dict, actor: str) -> M365Workflow:
    if kind == "offboard":
        name, steps = plan_offboard(db, connection, target_id, options)
    else:
        name, steps = PLANNERS[kind](db, connection, options)
    flow = M365Workflow(tenant_id=connection.tenant_id, connection_id=connection.id, kind=kind, target_id=target_id or "",
                        target_name=name[:320], options=options, steps=steps, requested_by=actor)
    db.add(flow)
    db.flush()
    audit.record(db, actor, "m365.workflow_planned", flow.id, connection.tenant_id, kind=kind, targetName=flow.target_name)
    return flow


# --- Running ----------------------------------------------------------------------------------------------------

class StepResult(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _call(client, headers, method, path, body=None, tolerate=()):
    try:
        return m365_admin.request(client, headers, method, path, body)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in tolerate:
            return {}
        uncertain = exc.response.status_code >= 500 or exc.response.status_code == 408
        raise StepResult("unknown" if uncertain else "failed", "Microsoft refused." + m365_admin.microsoft_said(exc.response)) from None
    except (httpx.RequestError, ValueError):
        raise StepResult("unknown", "No answer from Microsoft; check the tenant before marking this step.") from None


def _items(step: dict, client, headers, action) -> str:
    """Run ``action`` for each item not done yet; the step fails if any item fails (and retries only those)."""
    failed = []
    for item in step["items"]:
        if item.get("status") == "done":
            continue
        try:
            action(item)
            item["status"] = "done"
        except StepResult as exc:
            item["status"], item["reason"] = exc.status, exc.message
            failed.append(item)
    if failed:
        status = "unknown" if any(i["status"] == "unknown" for i in failed) else "failed"
        raise StepResult(status, f"{len(failed)} of {len(step['items'])} not done: " + "; ".join(f"{i['label']}: {i['reason']}" for i in failed[:5]))
    return f"{len(step['items'])} done"


def _summary(flow: M365Workflow) -> str:
    lines = [f"Microsoft 365 {flow.kind.replace('_', ' ')}: {flow.target_name}", ""]
    for step in flow.steps:
        if step["key"] == "open_ticket":
            continue
        lines.append(f"- {step['title']}: {step['status']}" + (f" ({step['result']})" if step.get("result") else ""))
    if flow.kind == "offboard":
        devices = next((s for s in flow.steps if s["key"] == "review_devices"), None)
        lines += ["", "Left to do by hand:",
                  "- Collect, reassign or wipe their devices: " + (", ".join(i["label"] for i in devices["items"]) or "none found")
                  if devices else "- Collect the user's devices, or wipe them (Devices).",
                  "- Rotate any stored credential flagged for them (Credential vault).",
                  *([] if any(s["key"] == "mailbox_handover" for s in flow.steps)
                    else ["- Convert the mailbox to shared and give access to whoever needs it (Exchange)."]),
                  "- Move OneDrive files that must be kept before the licence's 30-day grace period ends"
                  + (" (shared with the colleague named in the plan)." if any(s["key"] == "onedrive_handover" for s in flow.steps) else ".")]
    return "\n".join(lines)



def _handover(m365_exchange, connection, item: dict, done: list) -> None:
    """Offboarding's mailbox hand-over, recording each part as it completes."""
    with m365_exchange.session(connection) as (exo_client, token):
        if item.get("convert"):
            m365_exchange.invoke(exo_client, connection, token, "Set-Mailbox", {"Identity": item["mailbox"], "Type": "Shared"})
            done.append("converted to shared")
        if item.get("delegate"):
            m365_exchange.invoke(exo_client, connection, token, "Add-MailboxPermission",
                                 {"Identity": item["mailbox"], "User": item["delegate"], "AccessRights": ["FullAccess"],
                                  "AutoMapping": True, "InheritanceType": "All"})
            done.append(f"full access for {item['delegate']}")
        if item.get("forwardTo"):
            m365_exchange.invoke(exo_client, connection, token, "Set-Mailbox",
                                 {"Identity": item["mailbox"], "ForwardingSmtpAddress": "smtp:" + item["forwardTo"],
                                  "DeliverToMailboxAndForward": True})
            done.append(f"forwarded to {item['forwardTo']}")

def run_step(db: Session, connection: M365Connection, flow: M365Workflow, step: dict, client, headers, secrets_out: list) -> str:
    key, uid = step["key"], flow.target_id
    if key == "block_signin":
        _call(client, headers, "PATCH", f"/users/{UUID(uid)}", {"accountEnabled": False})
        return "Sign-in blocked"
    if key == "revoke_sessions":
        _call(client, headers, "POST", f"/users/{UUID(uid)}/revokeSignInSessions")
        return "Sessions revoked"
    if key == "reset_password":
        _call(client, headers, "PATCH", f"/users/{UUID(uid)}",
              {"passwordProfile": {"password": m365_admin.new_password(20), "forceChangePasswordNextSignIn": True}})
        return "Password changed to a random one"
    if key == "remove_mfa":
        try:
            status, result = m365_admin.reset_mfa(connection, uid)
        except m365_admin.ProviderError as exc:
            if "no MFA methods" in str(exc):
                return "No MFA methods registered"
            raise StepResult("unknown" if exc.uncertain else "failed", str(exc)) from None
        if status != "succeeded":
            raise StepResult("failed", "Kept: " + "; ".join(f"{f['label']} ({f['reason']})" for f in result["failed"]))
        return "Removed: " + (", ".join(result["removed"]) or "nothing registered")
    if key == "out_of_office":
        message = str(flow.options.get("outOfOfficeMessage") or "")
        _call(client, headers, "PATCH", f"/users/{UUID(uid)}/mailboxSettings",
              {"automaticRepliesSetting": {"status": "alwaysEnabled", "externalAudience": "all",
                                           "internalReplyMessage": message, "externalReplyMessage": message}})
        return "Out-of-office reply on"
    if key == "remove_groups":
        return _items(step, client, headers, lambda item: _call(
            client, headers, "DELETE", f"/groups/{UUID(item['id'])}/members/{UUID(uid)}/$ref", tolerate=(404,)))
    if key == "remove_roles":
        return _items(step, client, headers, lambda item: _call(
            client, headers, "DELETE", "/roleManagement/directory/roleAssignments/" + quote(str(item["id"]), safe=""), tolerate=(404,)))
    if key == "remove_licences":
        if not step["items"]:
            return "No directly assigned licences"
        current = {l.get("skuId") for l in _call(client, headers, "GET", f"/users/{UUID(uid)}?$select=assignedLicenses").get("assignedLicenses") or []}
        remove = [i["id"] for i in step["items"] if i["id"] in current]
        if remove:
            _call(client, headers, "POST", f"/users/{UUID(uid)}/assignLicense", {"addLicenses": [], "removeLicenses": remove})
        return "Removed: " + ", ".join(i["label"] for i in step["items"])
    if key == "mark_contact":
        for item in step["items"]:
            contact = db.get(Contact, item["id"])
            if contact is not None and LEAVER_NOTE not in (contact.notes or ""):
                contact.notes = ((contact.notes or "") + "\n" + LEAVER_NOTE).strip()
                contact.is_primary = False
        return f"{len(step['items'])} contact(s) marked" if step["items"] else "No matching contact"
    if key == "mailbox_handover":
        from . import m365_exchange

        item = step["items"][0]
        done = []
        try:
            _handover(m365_exchange, connection, item, done)
        except m365_exchange.ExchangeError as exc:
            if exc.uncertain:
                raise
            raise StepResult("failed", (("Done before it stopped: " + ", ".join(done) + ". ") if done else "") + str(exc)) from None
        return "Mailbox " + ", ".join(done)
    if key == "onedrive_handover":
        from . import m365_collaboration

        try:
            link = m365_collaboration.share_onedrive(client, headers, uid, step["items"][0]["delegate"], flow.target_name)
        except m365_collaboration.CollaborationError as exc:
            raise StepResult("failed", str(exc)) from None
        return f"OneDrive shared with {step['items'][0]['delegate']}" + (f": {link}" if link else "")
    if key == "review_devices":
        return (f"{len(step['items'])} device(s) to collect, reassign or wipe: " + ", ".join(i["label"] for i in step["items"])
                if step["items"] else "No managed device to collect")
    if key == "flag_credentials":
        from .models import VaultCredential

        flagged = 0
        for item in step["items"]:
            credential = db.get(VaultCredential, item["id"])
            if credential is not None and CREDENTIAL_FLAG not in (credential.notes or ""):
                credential.notes = ((credential.notes or "") + f"\n{CREDENTIAL_FLAG} ({flow.target_name}, {utcnow():%d %b %Y}).").strip()
                credential.updated_by = flow.executed_by or "system:offboarding"
                flagged += 1
        return f"{flagged} credential(s) flagged for rotation" if step["items"] else "Nothing to flag"
    if key == "billing_effect":
        return ("The next invoice counts the licences and users then assigned; issued invoices are not changed"
                if step["items"] else "No change to billing")
    if key == "add_contact":
        profile = flow.options["profile"]
        if not _contacts(db, connection.tenant_id, profile["userPrincipalName"]):
            db.add(Contact(tenant_id=services.msp_tenant_id(db, connection.tenant_id), account_tenant_id=connection.tenant_id,
                           name=profile["displayName"], email=profile["userPrincipalName"], title=str(profile.get("jobTitle") or "")[:120],
                           notes="Added by Microsoft 365 onboarding"))
        return "Contact added"
    if key == "open_ticket":
        if flow.ticket_id:
            return "Ticket already opened"
        title = {"offboard": "Offboarding", "onboard": "New starter", "bulk_create": "New users"}[flow.kind]
        ticket = services.open_ticket(db, connection.tenant_id, f"{title}: {flow.target_name}"[:300], _summary(flow), source="microsoft-365",
                                      requester=flow.executed_by or flow.requested_by)
        flow.ticket_id = ticket.id
        return f"Ticket #{ticket.number} opened"
    if key == "create_user":
        profile = (step["items"][0]["profile"] if flow.kind == "bulk_create" else flow.options["profile"])
        return _create(client, headers, flow, step, profile, secrets_out)
    if key == "set_usage_location":
        _retry_new_user(lambda: _call(client, headers, "PATCH", f"/users/{UUID(uid)}", {"usageLocation": flow.options["profile"]["usageLocation"]}))
        return "Usage location set"
    if key == "set_manager":
        _call(client, headers, "PUT", f"/users/{UUID(uid)}/manager/$ref", {"@odata.id": m365.GRAPH + "/users/" + str(UUID(step["items"][0]["id"]))})
        return "Manager set"
    if key == "assign_licences":
        _retry_new_user(lambda: _call(client, headers, "POST", f"/users/{UUID(uid)}/assignLicense",
                                      {"addLicenses": [{"skuId": i["id"], "disabledPlans": []} for i in step["items"]], "removeLicenses": []}))
        return "Licences assigned"
    if key == "add_groups":
        return _items(step, client, headers, lambda item: _add_member(client, headers, item["id"], uid))
    raise StepResult("failed", "Unknown step")


def _add_member(client, headers, group_id, user_id):
    try:
        _retry_new_user(lambda: m365_admin.request(client, headers, "POST", f"/groups/{UUID(group_id)}/members/$ref",
                                                   {"@odata.id": m365.GRAPH + "/directoryObjects/" + str(UUID(user_id))}))
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 400 and "already exist" in exc.response.text:
            return
        raise StepResult("failed", "Microsoft refused." + m365_admin.microsoft_said(exc.response)) from None
    except httpx.RequestError:
        raise StepResult("unknown", "No answer from Microsoft.") from None


def _retry_new_user(call, attempts: int = 4):
    """A user Microsoft has only just created can be briefly invisible to other calls."""
    for attempt in range(attempts):
        try:
            return call()
        except (StepResult, httpx.HTTPStatusError) as exc:
            missing = (isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 404) or \
                (isinstance(exc, StepResult) and "Request_ResourceNotFound" in exc.message)
            if not missing or attempt == attempts - 1:
                raise
            time.sleep(2 * (attempt + 1))


def _create(client, headers, flow, step, profile, secrets_out) -> str:
    upn = profile["userPrincipalName"]
    try:
        existing = m365_admin.request(client, headers, "GET", "/users/" + quote(upn, safe="") + "?$select=id")
        raise StepResult("failed", f"{upn} already exists (id {existing.get('id')}). If Fenrir made it in an earlier run, mark this step "
                                   "done; its password must be reset, as Fenrir does not keep it.")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code != 404:
            raise StepResult("failed", "Could not check the sign-in name." + m365_admin.microsoft_said(exc.response)) from None
    password = m365_admin.new_password()
    body = {**{k: v for k, v in profile.items() if v not in ("", None)}, "accountEnabled": True,
            "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": True}}
    created = _call(client, headers, "POST", "/users", body)
    if not created.get("id"):
        raise StepResult("unknown", "Microsoft did not return the new user's ID.")
    if flow.kind == "bulk_create":
        step["items"][0]["userId"] = created["id"]
        _bulk_extras(client, headers, flow, step, created["id"])
    else:
        flow.target_id = created["id"]
    secrets_out.append({"userPrincipalName": upn, "displayName": profile.get("displayName", ""), "password": password})
    extras = step["items"][0].get("extras") if flow.kind == "bulk_create" else ""
    return "Created" + (f"; {extras}" if extras else "")


def _bulk_extras(client, headers, flow, step, user_id):
    """Licences and groups for one imported user. Failures are noted on the row, not retried (the user exists)."""
    notes = []
    if flow.options.get("skuIds"):
        try:
            _retry_new_user(lambda: _call(client, headers, "POST", f"/users/{UUID(user_id)}/assignLicense",
                                          {"addLicenses": [{"skuId": s, "disabledPlans": []} for s in flow.options["skuIds"]], "removeLicenses": []}))
            notes.append("licensed")
        except StepResult as exc:
            notes.append("licence not assigned: " + exc.message)
    for gid in flow.options.get("groupIds") or []:
        try:
            _add_member(client, headers, gid, user_id)
        except StepResult as exc:
            notes.append("a group was not added: " + exc.message)
    if flow.options.get("groupIds") and not any(n.startswith("a group") for n in notes):
        notes.append("added to groups")
    step["items"][0]["extras"] = "; ".join(notes)[:500]


def _depends_on_user(flow: M365Workflow) -> bool:
    return flow.kind == "onboard" and not flow.target_id


# Steps that do not need the Microsoft 365 user to exist yet.
NO_USER_NEEDED = {"create_user", "add_contact", "open_ticket", "ad_create", "ad_sync", "wait_cloud", "review_devices", "flag_credentials",
                  "billing_effect"}
EXTERNAL = {"wait_cloud"}  # steps that wait on something other than Microsoft Graph


def _ad_request(flow: M365Workflow, key: str, actor: str) -> tuple[str, dict, str | None]:
    """The ad.directory operation, parameters and one-time secret for an AD step."""
    sam = flow.options.get("adIdentity") or ""
    if key == "ad_disable":
        return "disable", {"identity": sam}, None
    if key == "ad_scramble":
        return "scramble", {"identity": sam}, None
    if key == "ad_remove_groups":
        return "remove_groups", {"identity": sam}, None
    if key == "ad_move":
        return "move", {"identity": sam, "ou": flow.options.get("adMoveOu") or ""}, None
    if key == "ad_hide_gal":
        return "hide_gal", {"identity": sam}, None
    if key == "ad_describe":
        return "describe", {"identity": sam, "text": f"Left {utcnow():%d %b %Y}; offboarded by {actor} with Fenrir"}, None
    if key == "ad_sync":
        return "sync", {}, None
    if key == "ad_create":
        profile, ad = flow.options["profile"], flow.options.get("ad") or {}
        params = {"sam": sam, "upn": profile["userPrincipalName"], "givenName": profile.get("givenName", ""),
                  "surname": profile.get("surname", ""), "displayName": profile["displayName"], "ou": ad.get("ou") or "",
                  "title": profile.get("jobTitle", ""), "department": profile.get("department", ""),
                  "manager": flow.options.get("adManager") or "", "groups": ad.get("groups") or [], "mustChange": True}
        return "create", params, m365_admin.new_password()
    raise StepResult("failed", "Unknown Active Directory step")


def _ad_message(key: str, result: dict) -> str:
    if key == "ad_remove_groups":
        removed, kept = result.get("removed") or [], result.get("kept") or []
        return ("Removed: " + (", ".join(removed) or "no groups")) + (f"; kept: {'; '.join(kept)}" if kept else "")
    if key == "ad_create":
        user = result.get("user") or {}
        notes = result.get("notes") or []
        return f"Created {user.get('sam')} in {user.get('ou')}" + (f"; {'; '.join(notes)}" if notes else "")
    if result.get("skipped"):
        return str(result["skipped"])
    return {"ad_disable": "Account disabled in Active Directory", "ad_scramble": "Random password set in Active Directory",
            "ad_move": "Moved", "ad_hide_gal": "Hidden from the address book", "ad_describe": "Leaving date noted",
            "ad_sync": "Entra Connect delta sync started"}.get(key, "Done")


def _external(db: Session, connection: M365Connection, flow: M365Workflow, step: dict, actor: str, client, headers,
              secrets_out: list) -> tuple[str, str, dict]:
    """Advance a step that waits on a domain controller or on Entra Connect: (waiting | done | failed, message, step changes)."""
    key = step["key"]
    if key == "wait_cloud":
        upn = flow.options["profile"]["userPrincipalName"]
        try:
            found = m365_admin.request(client, headers, "GET", "/users/" + quote(upn, safe="") + "?$select=id,onPremisesSyncEnabled")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                return "failed", "Could not look the user up." + m365_admin.microsoft_said(exc.response), {}
            since = step.get("since") or utcnow().isoformat() + "Z"
            started = datetime.fromisoformat(since.removesuffix("Z"))
            if utcnow() - started > AD_WAIT:
                return "failed", ("The user has not appeared in Microsoft 365 after an hour. Check that Entra Connect syncs this OU "
                                  "(Synchronization Service Manager), then retry this step."), {}
            return "waiting", "Waiting for Entra Connect to bring the user into Microsoft 365", {"since": since}
        flow.target_id = found.get("id") or ""
        return "done", "The user is in Microsoft 365", {}
    # An Active Directory step: send it once, then wait for the server's answer.
    if step.get("commandId"):
        state, result = hybrid_identity.outcome(db.get(Command, step["commandId"]))
        if state == "waiting":
            return "waiting", step.get("result") or "Waiting for the server", {}
        command = db.get(Command, step["commandId"])
        if command is not None and (command.payload or {}).get("secretEnvelope"):
            command.payload = {k: v for k, v in command.payload.items() if k != "secretEnvelope"}  # never released: drop it
        if state == "done":
            return "done", _ad_message(key, result), {"commandId": None}
        return "failed", "The server said: " + str(result.get("error") or "unknown error"), {"commandId": None}
    device_id = (step.get("items") or [{}])[0].get("deviceId")
    operation, params, secret = _ad_request(flow, key, actor)
    try:
        command = hybrid_identity.send(db, flow.tenant_id, device_id, operation, params, actor, secret=secret,
                                       reason=f"Microsoft 365 {flow.kind.replace('_', ' ')}: {flow.target_name}")
    except hybrid_identity.HybridError as exc:
        return "failed", str(exc), {}
    if secret:
        profile = flow.options["profile"]
        secrets_out.append({"userPrincipalName": profile["userPrincipalName"], "displayName": profile.get("displayName", ""),
                            "password": secret, "where": "Active Directory"})
    device = db.get(Device, device_id)
    return "waiting", f"Sent to {device.hostname if device else 'the server'}; waiting for its answer", {"commandId": command.id}


def run(db: Session, connection: M365Connection, flow: M365Workflow, actor: str) -> dict:
    """Run pending and failed steps until done or out of time. The workflow must already be claimed (status running)."""
    secrets_out: list[dict] = []
    started = monotonic()
    more, ran, waiting = False, 0, ""
    try:
        with m365_admin.session(connection) as (client, headers):
            for index, step in enumerate(flow.steps):
                if step["status"] not in ("pending", "failed", "waiting"):
                    continue
                if ran and monotonic() - started > RUN_BUDGET:
                    more = True
                    break
                if step["key"] not in NO_USER_NEEDED and _depends_on_user(flow):
                    continue  # the user was not created; these wait
                if step["key"] == "open_ticket" and any(s["status"] in ("pending", "failed", "waiting") for s in flow.steps[:index]):
                    continue  # the ticket records the outcome, so it goes last
                ran += 1
                if step["key"].startswith("ad_") or step["key"] in EXTERNAL:
                    status, message, changes = _external(db, connection, flow, step, actor, client, headers, secrets_out)
                    steps = [dict(x) for x in flow.steps]
                    steps[index] = {**step, **changes, "status": status, "result": message[:1000], "at": utcnow().isoformat() + "Z"}
                    flow.steps = steps
                    if status != "waiting":
                        audit.record(db, actor, "m365.workflow_step", flow.id, flow.tenant_id, step=step["key"], status=status)
                    db.commit()
                    if status == "waiting":
                        waiting, more = message, True
                        break  # later steps follow on from this one
                    continue
                _mark(db, flow, index, "running", "")
                try:
                    message = run_step(db, connection, flow, step, client, headers, secrets_out)
                    _mark(db, flow, index, "done", message)
                except StepResult as exc:
                    _mark(db, flow, index, exc.status, exc.message[:1000])
                except Exception as exc:  # noqa: BLE001 - the outcome is not known; never replay it
                    log.warning("M365 workflow %s step %s: %s", flow.id, step["key"], exc)
                    _mark(db, flow, index, "unknown", "Fenrir stopped before Microsoft answered; check the tenant before marking this step.")
                audit.record(db, actor, "m365.workflow_step", flow.id, flow.tenant_id, step=step["key"], status=flow.steps[index]["status"])
                db.commit()
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError):
        _finish(db, flow, actor)
        raise
    _finish(db, flow, actor, more)
    return {"workflow": flow, "secrets": secrets_out, "more": more, "waiting": waiting}


def _mark(db: Session, flow: M365Workflow, index: int, status: str, message: str) -> None:
    steps = [dict(s) for s in flow.steps]
    steps[index] = {**flow.steps[index], "status": status, "result": message, "at": utcnow().isoformat() + "Z"}
    flow.steps = steps
    if status == "running":
        db.commit()  # durable before Microsoft is asked: a crash leaves "running", which becomes "unknown"


def _finish(db: Session, flow: M365Workflow, actor: str, more: bool = False) -> None:
    open_steps = [s for s in flow.steps if s["status"] not in ("done", "skipped")]
    flow.status = "completed" if not open_steps else "partial"
    flow.completed_at = utcnow() if not open_steps else None
    if not more:
        audit.record(db, actor, "m365.workflow_run", flow.id, flow.tenant_id, status=flow.status)
        events.publish(db, "m365.workflow_finished", {"workflowId": flow.id, "status": flow.status, "kind": flow.kind}, flow.tenant_id,
                       key=f"m365-workflow:{flow.id}:{utcnow().isoformat()}")
    db.commit()


def claim(db: Session, flow: M365Workflow, actor: str) -> bool:
    """Take the workflow for one run. A run that died long ago is taken over; its in-flight step becomes unknown."""
    now = utcnow()
    if flow.status == "prepared" and now - flow.created_at > PLAN_VALID:
        return False
    claimed = db.execute(update(M365Workflow).where(
        M365Workflow.id == flow.id,
        (M365Workflow.status.in_(("prepared", "partial"))) | ((M365Workflow.status == "running") & (M365Workflow.started_at < now - STALE_RUN)))
        .values(status="running", started_at=now, executed_by=actor).execution_options(synchronize_session=False)).rowcount
    if not claimed:
        db.rollback()
        return False
    db.commit()
    db.refresh(flow)
    if any(s["status"] == "running" for s in flow.steps):
        flow.steps = [{**s, "status": "unknown", "result": "Fenrir stopped while this step ran; check the tenant before marking it."}
                      if s["status"] == "running" else s for s in flow.steps]
        db.commit()
    return True


def resolve(db: Session, flow: M365Workflow, index: int, outcome: str, actor: str) -> M365Workflow:
    if not 0 <= index < len(flow.steps):
        raise PlanError("No such step.")
    step = flow.steps[index]
    allowed = {"unknown": {"done", "retry", "skip"}, "failed": {"done", "retry", "skip"}, "pending": {"skip"}, "waiting": {"skip"}}
    if outcome not in allowed.get(step["status"], set()):
        raise PlanError("That step cannot be changed now.")
    if flow.status == "running":
        raise PlanError("Wait for the current run to finish.")
    status = {"done": "done", "retry": "pending", "skip": "skipped"}[outcome]
    steps = [dict(s) for s in flow.steps]
    steps[index] = {**step, "status": status, "result": f"Marked {outcome} by {actor}" if outcome != "retry" else step.get("result", ""),
                    "at": utcnow().isoformat() + "Z"}
    if outcome == "done" and step["key"] == "create_user" and flow.kind == "onboard" and not flow.target_id:
        raise PlanError("Fenrir does not know the new user's ID; check the tenant and start a new onboarding for the remaining steps.")
    flow.steps = steps
    open_steps = [s for s in flow.steps if s["status"] not in ("done", "skipped")]
    flow.status = "completed" if not open_steps else "partial"
    audit.record(db, actor, "m365.workflow_step_resolved", flow.id, flow.tenant_id, step=step["key"], outcome=outcome)
    return flow


# --- Continuing in the background -------------------------------------------------------------------------------

def advance_waiting(db: Session) -> int:
    """Every minute: carry on workflows that wait on a domain controller or on Entra Connect, so nobody has to keep the
    page open. Only steps the technician already confirmed run; nothing new is planned."""
    advanced = 0
    flows = db.execute(select(M365Workflow).where(M365Workflow.status == "partial")).scalars().all()
    for flow in flows:
        if not any(s.get("status") == "waiting" for s in flow.steps or []):
            continue
        connection = db.get(M365Connection, flow.connection_id)
        if connection is None:
            continue
        person = (flow.executed_by or flow.requested_by or "").removesuffix(" (continued by Fenrir)")
        actor = f"{person} (continued by Fenrir)"
        if not claim(db, flow, actor):
            continue
        try:
            run(db, connection, flow, actor)
            advanced += 1
        except Exception as exc:  # noqa: BLE001 - one workflow must not stop the others
            log.warning("M365 workflow %s could not continue: %s", flow.id, exc)
            db.rollback()
            flow = db.get(M365Workflow, flow.id)
            if flow is not None and flow.status == "running":
                flow.status = "partial"
                db.commit()
    return advanced


# --- Temporary admin expiry ---------------------------------------------------------------------------------------

def expire_temp_admins(db: Session) -> int:
    """Remove temporary admin roles whose time is up (runs every minute). A removal that keeps failing raises an alert."""
    now = utcnow()
    removed = 0
    rows = db.execute(select(M365Action).where(M365Action.operation == "user.temp_admin", M365Action.status.like("succeeded%"),
                                               M365Action.completed_at >= now - timedelta(days=4))).scalars().all()
    for job in rows:
        result = dict(job.result or {})
        expires = result.get("expiresAt")
        if not result.get("assignmentId") or result.get("removedAt") or not expires:
            continue
        try:
            due = expires.replace("Z", "") <= now.isoformat()
        except AttributeError:
            continue
        if not due:
            continue
        connection = db.get(M365Connection, job.connection_id)
        try:
            if connection is None:
                raise m365_admin.ProviderError("The Microsoft 365 connection was removed.")
            outcome = m365_admin.end_temp_admin(connection, result["assignmentId"])
            job.result = {**result, "removedAt": now.isoformat() + "Z", "removedBy": "system:expiry", "removal": outcome}
            audit.record(db, "system:m365-temp-admin", "m365.temp_admin_expired", job.id, job.tenant_id, roleId=result.get("roleId"))
            removed += 1
        except (m365_admin.ProviderError, httpx.HTTPError, ValueError, KeyError, crypto.VaultError) as exc:
            failures = int(result.get("removeFailures") or 0) + 1
            job.result = {**result, "removeFailures": failures, "removeError": str(exc)[:300]}
            if failures == 5:
                db.add(Alert(tenant_id=job.tenant_id, rule_id=f"m365:temp-admin:{job.id}"[:64], severity="high",
                             title=f"Temporary admin role was not removed: {result.get('roleName') or result.get('roleId')}"[:300],
                             mitre=["T1098"], event_ids=[],
                             details={"source": "Microsoft 365", "actionId": job.id, "user": (job.preview or {}).get("user", {}).get("userPrincipalName"),
                                      "error": str(exc)[:300], "fix": "Remove the role in Entra (Roles and administrators) and check Fenrir's "
                                                                       "RoleManagement.ReadWrite.Directory permission."}))
        db.commit()
    return removed
