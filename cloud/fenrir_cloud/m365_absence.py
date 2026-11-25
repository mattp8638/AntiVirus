"""Scheduled absences of Microsoft 365 users (M365-09): out-of-office replies, forwarding and calendar delegation.

An absence is scheduled for one user, from a start time to an end time. At the start, Fenrir captures what is there
now, then switches on:

* automatic replies (mailbox settings), using Microsoft's own scheduled window, so the replies start and stop on
  time even if Fenrir is unreachable;
* forwarding, as an inbox rule Fenrir names and records, optionally keeping a copy;
* calendar delegation: read or write permission on the user's calendar for each delegate.

At the end, Fenrir reverts each change it made, and only those: it puts the captured reply settings back, deletes the
rule it created and removes the permissions it added. A permission or rule that existed before is left alone.

A step that fails is retried on the next passes (``MAX_ATTEMPTS``). After that the absence becomes ``revert_failed``
(or ``start_failed``), with an alert in the operator's queue saying exactly what is still in place, because
forwarding left on after an absence is a data-leak risk. Every step is logged on the absence and in the audit log.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, m365
from .models import Alert, M365Absence, M365Connection, utcnow

log = logging.getLogger("fenrir.m365.absence")

RULE_NAME = "Fenrir: absence forwarding"
MAX_ATTEMPTS = 5
ALERT_RULE = "m365.absence_revert_failed"
MAX_LENGTH = timedelta(days=366)


class AbsenceError(Exception):
    pass


def validate(settings: dict, starts_at: datetime, ends_at: datetime) -> dict:
    if ends_at <= starts_at:
        raise AbsenceError("The absence must end after it starts")
    if ends_at - starts_at > MAX_LENGTH:
        raise AbsenceError("An absence can last at most a year")
    if ends_at <= utcnow():
        raise AbsenceError("The absence has already ended")
    out: dict = {}
    reply = settings.get("autoReply")
    if reply:
        internal = str(reply.get("internal") or "").strip()
        if not internal or len(internal) > 4000:
            raise AbsenceError("Write the automatic reply (up to 4000 characters)")
        audience = reply.get("externalAudience", "all")
        if audience not in ("none", "contactsOnly", "all"):
            raise AbsenceError("External audience must be none, contactsOnly or all")
        out["autoReply"] = {"internal": internal, "external": str(reply.get("external") or internal)[:4000], "externalAudience": audience}
    forward = settings.get("forwardTo")
    if forward:
        address = str(forward).strip()
        if "@" not in address or len(address) > 254 or " " in address:
            raise AbsenceError("Forward to a valid email address")
        out["forwardTo"] = address
        out["keepCopy"] = bool(settings.get("keepCopy", True))
    delegates = settings.get("delegates") or []
    if len(delegates) > 10:
        raise AbsenceError("At most ten calendar delegates")
    out["delegates"] = []
    for d in delegates:
        address, role = str(d.get("email") or "").strip(), d.get("role", "read")
        if "@" not in address or role not in ("read", "write"):
            raise AbsenceError("Each delegate needs an email address and read or write access")
        out["delegates"].append({"email": address, "role": role})
    if not (out.get("autoReply") or out.get("forwardTo") or out["delegates"]):
        raise AbsenceError("Choose at least one of: automatic replies, forwarding, calendar delegation")
    return out


def _iso(value: datetime) -> dict:
    return {"dateTime": value.replace(microsecond=0).isoformat(), "timeZone": "UTC"}


def _log(absence: M365Absence, step: str, ok: bool, message: str = "") -> None:
    absence.log = [*(absence.log or []), {"at": utcnow().isoformat() + "Z", "step": step, "ok": ok, "message": message[:300]}]


class _Graph:
    def __init__(self, client: httpx.Client, token: str, user_id: str):
        self.client, self.headers, self.base = client, {"Authorization": "Bearer " + token}, m365.GRAPH + f"/users/{user_id}"

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        r = self.client.request(method, self.base + path, headers=self.headers, **({"json": body} if body is not None else {}))
        if r.status_code == 404 and method == "DELETE":
            return {}  # already gone: the revert's goal is met
        if r.status_code >= 400:
            try:
                err = (r.json().get("error") or {})
                said = f": {err.get('code')} {err.get('message', '')}".rstrip()
            except ValueError:
                said = ""
            raise AbsenceError(f"Microsoft answered HTTP {r.status_code} to {method} {path}{said[:200]}")
        return r.json() if r.content else {}


def _client() -> httpx.Client:
    return httpx.Client(timeout=20, follow_redirects=False)


def start(db: Session, absence: M365Absence, conn: M365Connection) -> None:
    """Capture what is there, then apply each part. Parts already applied (on a retry) are not applied twice."""
    s, applied = absence.settings, dict(absence.applied or {})
    try:
        _apply(absence, conn, s, applied)
    finally:
        absence.applied = dict(applied)  # progress survives a failure, so a retry never repeats a step


def _apply(absence: M365Absence, conn: M365Connection, s: dict, applied: dict) -> None:
    with _client() as client:
        g = _Graph(client, m365.access_token(client, conn), absence.user_id)
        if "previous" not in applied:
            settings = g.call("GET", "/mailboxSettings")
            absence.previous = {"automaticRepliesSetting": settings.get("automaticRepliesSetting") or {"status": "disabled"}}
            existing = g.call("GET", "/calendar/calendarPermissions").get("value", [])
            absence.previous["calendarPermissions"] = [{"email": ((p.get("emailAddress") or {}).get("address") or "").lower(),
                                                        "role": p.get("role")} for p in existing]
            applied["previous"] = True
            _log(absence, "capture", True, "Captured the current automatic replies and calendar permissions")
        if s.get("autoReply") and "autoReply" not in applied:
            r = s["autoReply"]
            g.call("PATCH", "/mailboxSettings", {"automaticRepliesSetting": {
                "status": "scheduled", "scheduledStartDateTime": _iso(absence.starts_at), "scheduledEndDateTime": _iso(absence.ends_at),
                "internalReplyMessage": r["internal"], "externalReplyMessage": r["external"], "externalAudience": r["externalAudience"]}})
            applied["autoReply"] = True
            _log(absence, "auto-reply", True, "Automatic replies scheduled for the absence")
        if s.get("forwardTo") and "ruleId" not in applied:
            rule = g.call("POST", "/mailFolders/inbox/messageRules", {
                "displayName": RULE_NAME, "sequence": 1, "isEnabled": True,
                "actions": {"forwardTo": [{"emailAddress": {"address": s["forwardTo"]}}], "stopProcessingRules": False,
                            **({} if s.get("keepCopy", True) else {"delete": True})}})
            applied["ruleId"] = rule.get("id")
            _log(absence, "forwarding", True, f"Forwarding to {s['forwardTo']}" + ("" if s.get("keepCopy", True) else " without keeping a copy"))
        already = {p["email"] for p in absence.previous.get("calendarPermissions", [])}
        granted = dict(applied.get("permissions") or {})
        for d in s.get("delegates", []):
            if d["email"].lower() in granted:
                continue
            if d["email"].lower() in already:
                _log(absence, "delegation", True, f"{d['email']} already had calendar access; left as it was")
                granted[d["email"].lower()] = None  # nothing of ours to remove later
                applied["permissions"] = dict(granted)
                continue
            p = g.call("POST", "/calendar/calendarPermissions", {"emailAddress": {"address": d["email"]}, "role": d["role"],
                                                                 "isInsideOrganization": True})
            granted[d["email"].lower()] = p.get("id")
            applied["permissions"] = dict(granted)
            _log(absence, "delegation", True, f"{d['email']} can {d['role']} the calendar")
        applied["permissions"] = granted


def revert(db: Session, absence: M365Absence, conn: M365Connection) -> None:
    """Undo only what Fenrir applied. Each part is removed from ``applied`` once it is reverted."""
    applied = dict(absence.applied or {})
    with _client() as client:
        g = _Graph(client, m365.access_token(client, conn), absence.user_id)
        if applied.get("ruleId"):
            g.call("DELETE", f"/mailFolders/inbox/messageRules/{applied['ruleId']}")
            applied.pop("ruleId")
            _log(absence, "revert forwarding", True, "Forwarding rule removed")
            absence.applied = applied
        permissions = dict(applied.get("permissions") or {})
        for email, pid in list(permissions.items()):
            if pid:
                g.call("DELETE", f"/calendar/calendarPermissions/{pid}")
                _log(absence, "revert delegation", True, f"{email} no longer has the calendar access Fenrir granted")
            permissions.pop(email)
            applied["permissions"] = permissions
            absence.applied = applied
        if applied.get("autoReply"):
            previous = (absence.previous or {}).get("automaticRepliesSetting") or {"status": "disabled"}
            if previous.get("status") == "scheduled" and _ended(previous):
                previous = {**previous, "status": "disabled"}  # a schedule that has passed is not brought back
            g.call("PATCH", "/mailboxSettings", {"automaticRepliesSetting": previous})
            applied.pop("autoReply")
            _log(absence, "revert auto-reply", True, f"Automatic replies set back to {previous.get('status', 'disabled')}")
    absence.applied = applied


def _ended(setting: dict) -> bool:
    end = (setting.get("scheduledEndDateTime") or {}).get("dateTime")
    try:
        return bool(end) and datetime.fromisoformat(end.replace("Z", "")[:19]) <= utcnow()
    except ValueError:
        return False


def still_in_place(absence: M365Absence) -> list[str]:
    applied = absence.applied or {}
    out = []
    if applied.get("ruleId"):
        out.append(f"forwarding to {absence.settings.get('forwardTo')}")
    out += [f"calendar access for {e}" for e, pid in (applied.get("permissions") or {}).items() if pid]
    if applied.get("autoReply"):
        out.append("automatic replies")
    return out


def _alert(db: Session, absence: M365Absence, phase: str, error: str) -> None:
    key = f"absence:{absence.id}:{phase}"
    open_ = db.scalars(select(Alert).where(Alert.tenant_id == absence.tenant_id, Alert.rule_id == ALERT_RULE,
                                           Alert.status.in_(("new", "triaged")))).all()
    if any((a.details or {}).get("key") == key for a in open_):
        return
    left = still_in_place(absence)
    title = (f"Absence of {absence.user_label} could not be reverted" if phase == "revert"
             else f"Absence of {absence.user_label} could not be started")
    db.add(Alert(tenant_id=absence.tenant_id, rule_id=ALERT_RULE, title=title[:300], severity="high" if phase == "revert" else "medium",
                 mitre=[], event_ids=[], details={"category": "m365", "source": "Microsoft 365 absences", "key": key,
                                                  "description": (f"Still in place: {', '.join(left)}. " if left else "") + f"Last error: {error}",
                                                  "link": "/m365", "absenceId": absence.id}))


def _step(db: Session, absence: M365Absence, phase: str) -> None:
    conn = db.get(M365Connection, absence.connection_id)
    try:
        if conn is None:
            raise AbsenceError("The Microsoft 365 connection was removed")
        (start if phase == "start" else revert)(db, absence, conn)
    except (AbsenceError, httpx.HTTPError, ValueError, KeyError) as exc:
        absence.attempts += 1
        message = str(exc) if isinstance(exc, AbsenceError) else f"{type(exc).__name__}: {str(exc)[:200]}"
        _log(absence, phase, False, message)
        if absence.attempts >= MAX_ATTEMPTS:
            absence.status = "revert_failed" if phase == "revert" else "start_failed"
            _alert(db, absence, phase, message)
            audit.record(db, "system:m365-absence", f"m365.absence_{phase}_failed", absence.id, absence.tenant_id,
                         stillInPlace=still_in_place(absence), error=message)
        db.commit()
        return
    absence.attempts = 0
    if phase == "start":
        absence.status = "active"
        audit.record(db, "system:m365-absence", "m365.absence_started", absence.id, absence.tenant_id, user=absence.user_label)
    else:
        absence.status = "ended"
        audit.record(db, "system:m365-absence", "m365.absence_reverted", absence.id, absence.tenant_id, user=absence.user_label)
    db.commit()


def tick(db: Session) -> int:
    """Every minute: start absences that are due, revert those that have ended (or were cancelled while active)."""
    now, worked = utcnow(), 0
    due_start = db.scalars(select(M365Absence).where(M365Absence.status == "scheduled", M365Absence.starts_at <= now,
                                                     M365Absence.ends_at > now)).all()
    for a in due_start:
        _step(db, a, "start")
        worked += 1
    missed = db.scalars(select(M365Absence).where(M365Absence.status == "scheduled", M365Absence.ends_at <= now)).all()
    for a in missed:  # the whole window passed without starting (server down): nothing was applied
        a.status = "ended"
        _log(a, "start", False, "The absence ended before Fenrir could start it; nothing was changed")
        db.commit()
    due_end = db.scalars(select(M365Absence).where(M365Absence.status.in_(("active", "start_failed")), M365Absence.ends_at <= now)).all()
    for a in due_end:
        _step(db, a, "revert")
        worked += 1
    return worked


def end_now(db: Session, absence: M365Absence, actor: str) -> M365Absence:
    """Cancel a scheduled absence, or end an active one early (reverting straight away)."""
    if absence.status == "scheduled":
        absence.status = "cancelled"
        audit.record(db, actor, "m365.absence_cancelled", absence.id, absence.tenant_id)
        db.commit()
        return absence
    if absence.status not in ("active", "start_failed", "revert_failed"):
        raise AbsenceError("This absence has already ended")
    absence.ends_at = min(absence.ends_at, utcnow())
    absence.attempts = 0
    audit.record(db, actor, "m365.absence_ended_early", absence.id, absence.tenant_id)
    db.commit()
    if absence.status == "revert_failed":
        absence.status = "active"  # the operator asked to try again; the scheduler keeps retrying if this fails
    _step(db, absence, "revert")
    return absence
