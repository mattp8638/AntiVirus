"""Microsoft 365 reports (AdminDroid-style) for a connection, read live from Microsoft Graph.

Each report is a table (columns and rows) with a one-line summary, downloadable as CSV and schedulable by email to the
customer's contacts or the MSP (``Tenant.settings["m365Reports"]``: ``[{report, every: weekly|monthly, to: [...]}]``).

``inactive-users``   enabled licensed members who have not signed in for 30+ days (needs Entra ID P1 for sign-in
                     activity; without it the report says so)
``licences``         every subscription: bought, assigned, free, and licences held by disabled or inactive users
``mfa``              each user's MFA registration and methods, admins first
``mailboxes``        mailbox sizes and last activity (Microsoft's usage report, last 7 days)
``onedrive``         OneDrive storage and last activity (last 30 days)
``guests``           guest accounts, when invited and their last sign-in
``admins``           who holds each directory admin role
Microsoft may conceal user names in usage reports (Microsoft 365 admin centre > Settings > Org settings > Reports);
the report then says so.
"""
from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timedelta

import httpx

from . import m365
from .m365_admin import microsoft_said, session
from .models import utcnow

log = logging.getLogger("fenrir.m365.reports")

REPORTS = {
    "inactive-users": "Inactive licensed users",
    "licences": "Licences and waste",
    "mfa": "MFA registration",
    "mailboxes": "Mailbox sizes",
    "onedrive": "OneDrive usage",
    "guests": "Guest users",
    "admins": "Admin roles",
}
INACTIVE_DAYS = 30


class ReportError(Exception):
    pass


def _all(client, headers, path: str, limit: int = 20000) -> list[dict]:
    rows, url = [], m365.GRAPH + path
    while url and len(rows) < limit:
        response = client.get(url, headers={**headers, "ConsistencyLevel": "eventual"})
        if response.status_code >= 400:
            raise ReportError(_refused(response))
        data = response.json()
        rows += data.get("value") or []
        url = data.get("@odata.nextLink")
    return rows


def _refused(response: httpx.Response) -> str:
    if response.status_code in (401, 403):
        return "Microsoft refused: the connection needs Reports.Read.All, AuditLog.Read.All and UserAuthenticationMethod.Read.All." + microsoft_said(response)
    if "Premium" in response.text or "P1" in response.text:
        return "This report needs Entra ID P1 in the customer's tenant." + microsoft_said(response)
    return f"Microsoft refused the request (HTTP {response.status_code})." + microsoft_said(response)


def _csv_report(client, headers, function: str) -> list[dict]:
    response = client.get(m365.GRAPH + f"/reports/{function}", headers=headers, follow_redirects=True)
    if response.status_code >= 400:
        raise ReportError(_refused(response))
    text = response.content.decode("utf-8-sig", errors="replace")
    return list(csv.DictReader(io.StringIO(text)))


def _when(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None) if value else None
    except ValueError:
        return None


def _days(value) -> int | None:
    when = _when(value)
    return (utcnow() - when).days if when else None


def _mb(value) -> float | None:
    try:
        return round(int(value) / 1_048_576, 1)
    except (TypeError, ValueError):
        return None


def build(connection, key: str) -> dict:
    if key not in REPORTS:
        raise ReportError("Unknown report.")
    with session(connection) as (client, headers):
        rows, columns, summary = BUILDERS[key](client, headers)
    return {"report": key, "title": REPORTS[key], "generatedAt": utcnow().isoformat() + "Z", "columns": columns, "rows": rows,
            "summary": summary}


def _inactive(client, headers):
    try:
        users = _all(client, headers, "/users?$select=displayName,userPrincipalName,accountEnabled,assignedLicenses,userType,"
                                      "signInActivity,createdDateTime&$top=999")
    except ReportError as exc:
        if "signInActivity" in str(exc) or "P1" in str(exc) or "Premium" in str(exc):
            raise ReportError("Sign-in activity needs Entra ID P1 in the customer's tenant.") from None
        raise
    rows = []
    for u in users:
        if u.get("userType") != "Member" or not u.get("accountEnabled") or not u.get("assignedLicenses"):
            continue
        activity = u.get("signInActivity") or {}
        last = max(filter(None, [_when(activity.get("lastSignInDateTime")), _when(activity.get("lastNonInteractiveSignInDateTime"))]), default=None)
        idle = (utcnow() - last).days if last else _days(u.get("createdDateTime"))
        if idle is not None and idle >= INACTIVE_DAYS:
            rows.append({"user": u.get("displayName"), "signIn": u.get("userPrincipalName"),
                         "lastSignIn": last.isoformat() + "Z" if last else "never", "daysInactive": idle,
                         "licences": len(u.get("assignedLicenses") or [])})
    rows.sort(key=lambda r: -(r["daysInactive"] or 0))
    return rows, ["user", "signIn", "lastSignIn", "daysInactive", "licences"], \
        f"{len(rows)} licensed user(s) have not signed in for {INACTIVE_DAYS}+ days."


def _licences(client, headers):
    skus = _all(client, headers, "/subscribedSkus")
    try:
        users = _all(client, headers, "/users?$select=accountEnabled,assignedLicenses,signInActivity&$top=999")
    except ReportError:  # no Entra ID P1: count disabled users only
        users = _all(client, headers, "/users?$select=accountEnabled,assignedLicenses&$top=999")
    held_by_idle: dict[str, int] = {}
    for u in users:
        activity = u.get("signInActivity") or {}
        last = _when(activity.get("lastSignInDateTime"))
        idle = not u.get("accountEnabled") or (last is not None and (utcnow() - last).days >= INACTIVE_DAYS)
        if idle:
            for lic in u.get("assignedLicenses") or []:
                held_by_idle[lic.get("skuId")] = held_by_idle.get(lic.get("skuId"), 0) + 1
    rows, unused = [], 0
    for sku in skus:
        bought = int((sku.get("prepaidUnits") or {}).get("enabled") or 0)
        if bought == 0 or bought >= 10000:  # free and trial SKUs have no or huge counts
            continue
        assigned = int(sku.get("consumedUnits") or 0)
        free = max(0, bought - assigned)
        unused += free + held_by_idle.get(sku.get("skuId"), 0)
        rows.append({"licence": sku.get("skuPartNumber"), "bought": bought, "assigned": assigned, "free": free,
                     "heldByDisabledOrInactive": held_by_idle.get(sku.get("skuId"), 0)})
    rows.sort(key=lambda r: -(r["free"] + r["heldByDisabledOrInactive"]))
    return rows, ["licence", "bought", "assigned", "free", "heldByDisabledOrInactive"], \
        f"{unused} licence(s) unassigned or held by disabled or inactive users."


def _mfa(client, headers):
    rows = []
    for r in _all(client, headers, "/reports/authenticationMethods/userRegistrationDetails?$top=999"):
        if r.get("userType") not in (None, "member"):
            continue
        rows.append({"user": r.get("userDisplayName"), "signIn": r.get("userPrincipalName"), "admin": bool(r.get("isAdmin")),
                     "mfaRegistered": bool(r.get("isMfaRegistered")), "methods": ", ".join(r.get("methodsRegistered") or []),
                     "passwordless": bool(r.get("isPasswordlessCapable"))})
    rows.sort(key=lambda r: (r["mfaRegistered"], not r["admin"], str(r["user"]).lower()))
    missing = sum(1 for r in rows if not r["mfaRegistered"])
    admins = sum(1 for r in rows if r["admin"] and not r["mfaRegistered"])
    return rows, ["user", "signIn", "admin", "mfaRegistered", "methods", "passwordless"], \
        f"{missing} of {len(rows)} user(s) have no MFA registered" + (f", {admins} of them admins." if admins else ".")


def _concealed(rows: list[dict], field: str) -> bool:
    return bool(rows) and all(len(str(r.get(field) or "")) == 32 and "@" not in str(r.get(field) or "") for r in rows[:20])


def _mailboxes(client, headers):
    raw = _csv_report(client, headers, "getMailboxUsageDetail(period='D7')")
    rows = [{"mailbox": r.get("Display Name"), "address": r.get("User Principal Name"), "sizeMB": _mb(r.get("Storage Used (Byte)")),
             "items": r.get("Item Count"), "quotaWarningMB": _mb(r.get("Issue Warning Quota (Byte)")),
             "lastActivity": r.get("Last Activity Date") or "never", "deleted": r.get("Is Deleted") == "True"} for r in raw]
    rows.sort(key=lambda r: -(r["sizeMB"] or 0))
    note = " (names are hidden by the tenant's report privacy setting)" if _concealed(rows, "address") else ""
    near = sum(1 for r in rows if r["sizeMB"] and r["quotaWarningMB"] and r["sizeMB"] >= 0.9 * r["quotaWarningMB"])
    return rows, ["mailbox", "address", "sizeMB", "items", "quotaWarningMB", "lastActivity", "deleted"], \
        f"{len(rows)} mailbox(es); {near} near their quota{note}."


def _onedrive(client, headers):
    raw = _csv_report(client, headers, "getOneDriveUsageAccountDetail(period='D30')")
    rows = [{"owner": r.get("Owner Display Name"), "address": r.get("Owner Principal Name"), "usedMB": _mb(r.get("Storage Used (Byte)")),
             "files": r.get("File Count"), "lastActivity": r.get("Last Activity Date") or "never", "deleted": r.get("Is Deleted") == "True"}
            for r in raw]
    rows.sort(key=lambda r: -(r["usedMB"] or 0))
    note = " (names are hidden by the tenant's report privacy setting)" if _concealed(rows, "address") else ""
    total = sum(r["usedMB"] or 0 for r in rows)
    return rows, ["owner", "address", "usedMB", "files", "lastActivity", "deleted"], \
        f"{len(rows)} OneDrive account(s) using {total / 1024:,.1f} GB{note}."


def _guests(client, headers):
    users = _all(client, headers, "/users?$filter=userType eq 'Guest'&$select=displayName,mail,createdDateTime,externalUserState,signInActivity&$count=true&$top=999")
    rows = []
    for u in users:
        last = _when((u.get("signInActivity") or {}).get("lastSignInDateTime"))
        rows.append({"guest": u.get("displayName"), "email": u.get("mail"), "invited": u.get("createdDateTime"),
                     "state": u.get("externalUserState"), "lastSignIn": last.isoformat() + "Z" if last else "never",
                     "daysInactive": (utcnow() - last).days if last else _days(u.get("createdDateTime"))})
    rows.sort(key=lambda r: -(r["daysInactive"] or 0))
    stale = sum(1 for r in rows if (r["daysInactive"] or 0) >= 90)
    return rows, ["guest", "email", "invited", "state", "lastSignIn", "daysInactive"], \
        f"{len(rows)} guest(s); {stale} inactive for 90+ days."


def _admins(client, headers):
    rows = []
    for role in _all(client, headers, "/directoryRoles?$expand=members"):
        for member in role.get("members") or []:
            rows.append({"role": role.get("displayName"), "member": member.get("displayName"),
                         "signIn": member.get("userPrincipalName") or member.get("appId") or "",
                         "type": str(member.get("@odata.type", "")).split(".")[-1]})
    rows.sort(key=lambda r: (r["role"] != "Global Administrator", r["role"], str(r["member"])))
    globals_ = sum(1 for r in rows if r["role"] == "Global Administrator")
    return rows, ["role", "member", "signIn", "type"], \
        f"{len(rows)} admin role assignment(s); {globals_} Global Administrator(s)" + \
        (" (Microsoft recommends 2 to 4)." if globals_ > 4 or globals_ < 2 else ".")


BUILDERS = {"inactive-users": _inactive, "licences": _licences, "mfa": _mfa, "mailboxes": _mailboxes, "onedrive": _onedrive,
            "guests": _guests, "admins": _admins}


def to_csv(report: dict) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=report["columns"], extrasaction="ignore")
    writer.writeheader()
    for row in report["rows"]:
        # Never let a cell start a spreadsheet formula.
        writer.writerow({k: ("'" + str(v)) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v for k, v in row.items()})
    return out.getvalue()


# --- schedules ------------------------------------------------------------------------------------------------------

EVERY = {"weekly": timedelta(days=7), "monthly": timedelta(days=30)}


def due(schedule: dict, now: datetime) -> bool:
    last = _when(schedule.get("lastSentAt"))
    return last is None or now - last >= EVERY.get(schedule.get("every"), timedelta(days=7)) - timedelta(hours=1)


def send_schedules(db, now: datetime | None = None) -> int:
    """Daily: email every report whose schedule is due, as CSV attachments, one email per schedule and connection."""
    from sqlalchemy import select

    from . import audit, mailer
    from .models import M365Connection, Tenant

    now = now or utcnow()
    sent = 0
    for tenant in db.execute(select(Tenant)).scalars():
        # Copies: changing the stored dicts in place would leave the database thinking nothing changed.
        schedules = [dict(item) for item in (tenant.settings or {}).get("m365Reports") or []]
        if not schedules:
            continue
        changed = False
        for schedule in schedules:
            if not due(schedule, now) or not schedule.get("to"):
                continue
            for connection in db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant.id)).scalars():
                attachments, lines = [], []
                for key in schedule.get("reports") or []:
                    try:
                        report = build(connection, key)
                    except (ReportError, httpx.HTTPError, ValueError) as exc:
                        lines.append(f"{REPORTS.get(key, key)}: could not be produced ({str(exc)[:150]})")
                        continue
                    lines.append(f"{report['title']}: {report['summary']}")
                    attachments.append((f"{key}-{now:%Y-%m-%d}.csv", "text/csv", to_csv(report).encode("utf-8")))
                body = (f"Microsoft 365 reports for {tenant.name} ({connection.tenant_name or connection.name}), {now:%d %B %Y}.\n\n"
                        + "\n".join(lines) + "\n\nThe full reports are attached as CSV files.")
                for recipient in schedule["to"][:20]:
                    mailer.send(recipient, f"Microsoft 365 reports: {tenant.name}", body, attachments=attachments)
                sent += 1
            schedule["lastSentAt"] = now.isoformat() + "Z"
            changed = True
            audit.record(db, "system:m365-reports", "m365.reports.sent", tenant.name, tenant.id, reports=schedule.get("reports"),
                         recipients=len(schedule["to"]))
        if changed:
            tenant.settings = {**(tenant.settings or {}), "m365Reports": schedules}
    return sent
