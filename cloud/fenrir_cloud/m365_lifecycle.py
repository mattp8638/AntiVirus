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
from datetime import timedelta
from time import monotonic
from uuid import UUID
from urllib.parse import quote

import httpx
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from . import audit, crypto, events, m365, m365_admin, services
from .entra_reconcile import LEAVER_NOTE
from .models import Alert, Contact, M365Action, M365Connection, M365Workflow, utcnow

log = logging.getLogger("fenrir.m365.lifecycle")

RUN_BUDGET = 40.0
PLAN_VALID = timedelta(minutes=30)
STALE_RUN = timedelta(minutes=10)
BULK_MAX = 200


class PlanError(Exception):
    pass


def _step(key: str, title: str, detail: str, items: list | None = None, warning: str = "") -> dict:
    return {"key": key, "title": title, "detail": detail, "items": items or [], "warning": warning, "status": "pending",
            "result": "", "at": None}


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
        if options.get("blockSignIn"):
            steps.append(_step("block_signin", "Block sign-in", "The account can no longer sign in."))
        if options.get("revokeSessions"):
            steps.append(_step("revoke_sessions", "Sign out everywhere", "Ends existing sessions on every device (takes a few minutes)."))
        if options.get("resetPassword"):
            steps.append(_step("reset_password", "Reset the password", "Sets a random password nobody is told."))
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
        if options.get("removeLicences"):
            names = _skus(client, headers)
            direct, inherited = [], []
            for state in person.get("licenseAssignmentStates") or []:
                entry = {"id": state.get("skuId"), "label": names.get(state.get("skuId"), state.get("skuId"))}
                (inherited if state.get("assignedByGroup") else direct).append(entry)
            if not person.get("licenseAssignmentStates"):
                direct = [{"id": l.get("skuId"), "label": names.get(l.get("skuId"), l.get("skuId"))} for l in person.get("assignedLicenses") or []]
            steps.append(_step("remove_licences", "Remove licences", ", ".join(d["label"] for d in direct) or "No directly assigned licences",
                               direct, warning="Removing the licence deletes the mailbox and OneDrive after 30 days. Convert the mailbox "
                               "to shared first if its mail must be kept (Exchange batch; until then, do it in the Exchange admin centre)."
                               + (" Licences from groups: " + ", ".join(i["label"] for i in inherited) + " (they go when the user leaves those groups)."
                                  if inherited else "")))
    if options.get("markContact"):
        found = _contacts(db, connection.tenant_id, upn, person.get("mail") or "")
        steps.append(_step("mark_contact", "Mark the Fenrir contact as left", ", ".join(c.name for c in found) or "No matching contact",
                           [{"id": c.id, "label": c.name} for c in found]))
    if options.get("openTicket"):
        steps.append(_step("open_ticket", "Record it on a ticket", "Opens a ticket with what was done and what is left to do by hand."))
    if not steps:
        raise PlanError("Choose at least one step.")
    return f"{person.get('displayName') or upn} ({upn})", steps


def plan_onboard(db: Session, connection: M365Connection, options: dict) -> tuple[str, list[dict]]:
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
        lines += ["", "Left to do by hand:", "- Collect the user's devices, or wipe them (Devices).",
                  "- Convert the mailbox to shared and give access to whoever needs it (Exchange).",
                  "- Move OneDrive files that must be kept before the licence's 30-day grace period ends."]
    return "\n".join(lines)


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


def run(db: Session, connection: M365Connection, flow: M365Workflow, actor: str) -> dict:
    """Run pending and failed steps until done or out of time. The workflow must already be claimed (status running)."""
    secrets_out: list[dict] = []
    started = monotonic()
    more, ran = False, 0
    try:
        with m365_admin.session(connection) as (client, headers):
            for index, step in enumerate(flow.steps):
                if step["status"] not in ("pending", "failed"):
                    continue
                if ran and monotonic() - started > RUN_BUDGET:
                    more = True
                    break
                if step["key"] != "create_user" and step["key"] not in ("add_contact", "open_ticket") and _depends_on_user(flow):
                    continue  # the user was not created; these wait
                if step["key"] == "open_ticket" and any(s["status"] in ("pending", "failed") for s in flow.steps[:index]):
                    continue  # the ticket records the outcome, so it goes last
                ran += 1
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
    return {"workflow": flow, "secrets": secrets_out, "more": more}


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
    allowed = {"unknown": {"done", "retry", "skip"}, "failed": {"done", "retry", "skip"}, "pending": {"skip"}}
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
