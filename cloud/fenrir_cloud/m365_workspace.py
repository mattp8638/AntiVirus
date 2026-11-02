"""Microsoft 365 workspace: background sync, the sign-in and audit log store, and the views across tenants.

- **Sync**: every connection's directory snapshot is refreshed in the background (``FENRIR_M365_SYNC_HOURS``, default
  6), so the overview is current without anyone pressing Sync.
- **Log store**: sign-in and directory audit records are copied into Fenrir every hour and kept for
  ``FENRIR_M365_LOG_RETENTION_DAYS`` (default 730). Microsoft keeps them for 7 days (no Entra ID P1) or 30 days. Each
  run asks for everything since the last record seen, with a three-hour overlap because Microsoft can deliver records
  late; records already stored are skipped by their Microsoft ID.
- A tenant without the licence or permission for a log is marked unavailable and asked again once a day.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from time import monotonic
from urllib.parse import quote, urlparse

import httpx
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from . import audit, crypto, m365
from .models import M365Connection, M365LogEntry, Tenant, utcnow

log = logging.getLogger("fenrir.m365.workspace")

LOG_KINDS = {
    # kind: (Graph path, time field)
    "signin": ("/auditLogs/signIns", "createdDateTime"),
    "audit": ("/auditLogs/directoryAudits", "activityDateTime"),
}
FIRST_WINDOW = timedelta(days=30)  # the most Microsoft keeps
OVERLAP = timedelta(hours=3)  # Microsoft can deliver records late
PER_RUN = 20000  # records per log per run; the rest follows next run
UNAVAILABLE_RETRY = timedelta(hours=24)


class LogError(Exception):
    pass


# --- Sync -------------------------------------------------------------------------------------------------------

def sync_connection(db: Session, row: M365Connection, actor: str) -> M365Connection:
    """Refresh one connection's snapshot. Raises ValueError with a safe message when Microsoft or the credentials fail;
    the previous snapshot is kept."""
    try:
        snapshot = m365.synchronize(row)
    except (httpx.HTTPError, ValueError, KeyError, crypto.VaultError) as exc:
        # Microsoft's own error code and message say what to fix; secrets never appear in them (they travel in request
        # bodies, which are not kept).
        if isinstance(exc, crypto.VaultError):
            reason = "Fenrir could not decrypt this connection's stored secret (was the vault key changed?). Replace the secret."
        elif isinstance(exc, KeyError):
            reason = "Microsoft's answer was missing an expected field."
        else:
            reason = m365.describe_failure(exc)
        log.warning("M365 sync for %s failed: %s", row.id, reason)
        row.status, row.last_error = "failed", ("Sync failed. " + reason)[:300]
        audit.record(db, actor, "m365.sync_failed", row.id, row.tenant_id, reason=reason[:300])
        raise ValueError(row.last_error) from None
    defender = m365.ingest_defender_alerts(db, row, snapshot.pop("defenderAlerts", None))
    snapshot["defenderAlerts"] = defender
    row.snapshot, row.status, row.last_error, row.synced_at = snapshot, "synced", "", utcnow()
    row.granted_permissions = (snapshot.get("permissions") or {}).get("granted") or []
    audit.record(db, actor, "m365.synced", row.id, row.tenant_id, users=len(snapshot["users"]), licenses=len(snapshot["licenses"]))
    return row


# --- Log store --------------------------------------------------------------------------------------------------

def _when(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.replace(tzinfo=None) - (parsed.utcoffset() or timedelta())
    return parsed


def _iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat() + "Z"


def _pages(client: httpx.Client, url: str, token: str, limit: int, deadline: float) -> tuple[list[dict], bool]:
    """Follow Graph paging up to ``limit`` records. Returns (records, stopped early)."""
    rows: list[dict] = []
    seen: set[str] = set()
    while url:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com" or not parsed.path.startswith("/v1.0/"):
            raise LogError("Microsoft returned an invalid paging link.")
        if url in seen:
            raise LogError("Microsoft's paging repeated itself.")
        seen.add(url)
        response = client.get(url, headers={"Authorization": "Bearer " + token})
        response.raise_for_status()
        data = response.json()
        page = data.get("value")
        if not isinstance(page, list):
            raise LogError("Microsoft returned an unexpected log page.")
        rows.extend(r for r in page if isinstance(r, dict))
        url = data.get("@odata.nextLink")
        if url and (len(rows) >= limit or monotonic() >= deadline):
            return rows, True
    return rows, False


def _text(value, size: int) -> str:
    return str(value or "")[:size]


def _signin(item: dict) -> dict:
    status = item.get("status") or {}
    place = item.get("location") or {}
    device = item.get("deviceDetail") or {}
    code = status.get("errorCode")
    result = "success" if code in (0, None) else "interrupted" if code in (50074, 50076, 50079, 50125, 50140, 50158) else "failure"
    return {"at": _when(item.get("createdDateTime")), "actor": _text(item.get("userPrincipalName") or item.get("userDisplayName"), 320),
            "app": _text(item.get("appDisplayName"), 200), "ip": _text(item.get("ipAddress"), 64),
            "location": _text(", ".join(p for p in (place.get("city"), place.get("countryOrRegion")) if p), 160),
            "result": result, "activity": _text(status.get("failureReason") if result != "success" else "Sign-in", 200),
            "target": _text(item.get("resourceDisplayName"), 320),
            "details": {"errorCode": code, "clientApp": item.get("clientAppUsed"), "conditionalAccess": item.get("conditionalAccessStatus"),
                        "interactive": item.get("isInteractive"), "risk": item.get("riskLevelDuringSignIn"), "riskState": item.get("riskState"),
                        "device": device.get("displayName"), "os": device.get("operatingSystem"), "browser": device.get("browser"),
                        "compliant": device.get("isCompliant"), "managed": device.get("isManaged"),
                        "additional": _text(status.get("additionalDetails"), 300), "userId": item.get("userId"),
                        # For sign-in protection (m365_signin_security.py): where it happened.
                        "country": _text(place.get("countryOrRegion"), 8),
                        "lat": (place.get("geoCoordinates") or {}).get("latitude"),
                        "lon": (place.get("geoCoordinates") or {}).get("longitude")}}


def _audit(item: dict) -> dict:
    who = item.get("initiatedBy") or {}
    user = who.get("user") or {}
    app = who.get("app") or {}
    targets = [t for t in item.get("targetResources") or [] if isinstance(t, dict)]
    first = targets[0] if targets else {}
    changes = []
    for target in targets[:3]:
        for prop in (target.get("modifiedProperties") or [])[:10]:
            if isinstance(prop, dict):
                changes.append({"name": _text(prop.get("displayName"), 80), "old": _text(prop.get("oldValue"), 300),
                                "new": _text(prop.get("newValue"), 300)})
    return {"at": _when(item.get("activityDateTime")),
            "actor": _text(user.get("userPrincipalName") or user.get("displayName") or app.get("displayName"), 320),
            "app": _text(item.get("loggedByService"), 200), "ip": _text(user.get("ipAddress"), 64), "location": "",
            "result": _text(item.get("result"), 20), "activity": _text(item.get("activityDisplayName"), 200),
            "target": _text(first.get("userPrincipalName") or first.get("displayName"), 320),
            "details": {"category": item.get("category"), "reason": _text(item.get("resultReason"), 300),
                        "targets": [{"type": t.get("type"), "name": _text(t.get("userPrincipalName") or t.get("displayName"), 200)}
                                    for t in targets[:5]],
                        "changes": changes[:20]}}


MAPPERS = {"signin": _signin, "audit": _audit}


def collect_logs(db: Session, row: M365Connection, kinds: tuple[str, ...] = ("signin", "audit"), force: bool = False,
                 client: httpx.Client | None = None) -> dict:
    """Copy new sign-in and audit records from Microsoft. Returns {kind: {added, available, error, behind}}.

    Microsoft lists records newest first. When a run stops at its limit, the older part it did not reach is remembered
    as a gap and fetched first on the next run, so a busy tenant catches up instead of losing records."""
    state = dict(row.log_state or {})
    now = utcnow()
    out: dict = {}
    own = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=False)
    token: list[str] = []

    def fetch(path: str, field: str, start: datetime, end: datetime | None) -> tuple[list[dict], bool]:
        if not token:
            token.append(m365.access_token(client, row))
        condition = f"{field} ge {_iso(start)}" + (f" and {field} lt {_iso(end)}" if end else "")
        return _pages(client, f"{m365.GRAPH}{path}?$filter={quote(condition, safe='')}&$top=1000", token[0], PER_RUN, monotonic() + 90)

    try:
        for kind in kinds:
            path, field = LOG_KINDS[kind]
            current = dict(state.get(kind) or {})
            last_run = _when(current.get("lastRunAt"))
            if not force and current.get("available") is False and last_run and now - last_run < UNAVAILABLE_RETRY:
                out[kind] = {"added": 0, "available": False, "skipped": True}
                continue
            cursor = _when(current.get("cursor"))
            gaps = [g for g in current.get("gaps") or [] if isinstance(g, dict) and _when(g.get("from")) and _when(g.get("to"))]
            windows = [("gap", _when(gaps[0]["from"]), _when(gaps[0]["to"]))] if gaps else []
            windows.append(("new", (cursor - OVERLAP) if cursor else now - FIRST_WINDOW, None))
            added, failure = 0, None
            for label, start, end in windows:
                try:
                    items, stopped = fetch(path, field, start, end)
                except httpx.HTTPStatusError as exc:
                    code = exc.response.status_code
                    if code in (400, 401, 403, 404):
                        current["available"] = False
                        failure = _unavailable(kind, exc.response)
                    else:
                        failure = ("Microsoft is throttling requests; Fenrir tries again next hour." if code == 429
                                   else f"Microsoft returned HTTP {code}; Fenrir tries again next hour.")
                    break
                except (httpx.HTTPError, LogError, ValueError, KeyError, crypto.VaultError) as exc:
                    failure = str(exc)[:200] if isinstance(exc, LogError) else "Could not reach Microsoft."
                    break
                mapped = []
                for item in items:
                    entry = MAPPERS[kind](item) if item.get("id") else None
                    if entry and entry["at"] is not None:
                        mapped.append((str(item["id"])[:80], entry))
                known = set(db.execute(select(M365LogEntry.external_id).where(
                    M365LogEntry.connection_id == row.id, M365LogEntry.kind == kind,
                    M365LogEntry.at >= start - timedelta(minutes=5))).scalars())
                for external_id, entry in mapped:
                    if external_id not in known:
                        known.add(external_id)
                        db.add(M365LogEntry(tenant_id=row.tenant_id, connection_id=row.id, kind=kind, external_id=external_id, **entry))
                        added += 1
                oldest = min((e["at"] for _, e in mapped), default=None)
                newest = max((e["at"] for _, e in mapped), default=None)
                if label == "gap":
                    gaps = gaps[1:]
                    if stopped and oldest and oldest > start:
                        gaps.insert(0, {"from": _iso(start), "to": _iso(oldest)})  # the rest of this gap, next run
                else:
                    if stopped and oldest and oldest > start:
                        gaps.append({"from": _iso(start), "to": _iso(oldest)})
                    if newest and (cursor is None or newest > cursor):
                        current["cursor"] = _iso(newest)
            current["gaps"] = gaps[:20]
            current.update(lastRunAt=_iso(now), lastAdded=added, error=failure or "")
            if failure is None:
                current["available"] = True
            state[kind] = current
            out[kind] = {"added": added, "available": current.get("available", True), "error": failure or "",
                         "behind": bool(current.get("gaps"))}
    finally:
        if own:
            client.close()
    row.log_state = state
    return out


def _unavailable(kind: str, response: httpx.Response) -> str:
    try:
        error = (response.json().get("error") or {})
        code, message = str(error.get("code") or ""), str(error.get("message") or "")
    except ValueError:
        code, message = "", ""
    if "Premium" in code or "premium" in message.lower() or "license" in message.lower():
        return "This tenant needs Microsoft Entra ID P1 or P2 for Microsoft to provide this log."
    if response.status_code == 403:
        return "Fenrir does not have permission to read this log (AuditLog.Read.All and Directory.Read.All). Update permissions."
    return f"Microsoft would not provide this log (HTTP {response.status_code})."


def purge_logs(db: Session, days: int) -> int:
    if days <= 0:
        return 0
    return db.execute(delete(M365LogEntry).where(M365LogEntry.at < utcnow() - timedelta(days=days))).rowcount or 0


def tick(db: Session) -> None:
    """Hourly: refresh snapshots that are due, collect new log records, drop records past retention."""
    from .config import get_settings

    settings = get_settings()
    now = utcnow()
    for row in db.execute(select(M365Connection)).scalars().all():
        if settings.m365_sync_hours > 0 and (row.synced_at is None or now - row.synced_at >= timedelta(hours=settings.m365_sync_hours)):
            try:
                sync_connection(db, row, "system:m365-sync")
                db.commit()
            except ValueError:
                db.commit()  # the failure is recorded on the connection
            except Exception as exc:  # noqa: BLE001 - one customer must not stop the others
                db.rollback()
                log.warning("M365 sync for %s failed: %s", row.id, exc)
        try:
            collect_logs(db, row)
            db.commit()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            log.warning("M365 log collection for %s failed: %s", row.id, exc)
    removed = purge_logs(db, settings.m365_log_retention_days)
    if removed:
        log.info("M365 log retention removed %s records", removed)


# --- Views ------------------------------------------------------------------------------------------------------

def _missing_features(snapshot: dict | None) -> int | None:
    check = (snapshot or {}).get("permissions")
    if not check:
        return None
    return sum(1 for f in check.get("features") or [] if not f.get("available") and not f.get("unsupported"))


def overview(db: Session, tenant_ids: list[str]) -> dict:
    """One row per connection with what an MSP scans for, plus totals across them."""
    names = {t.id: t.name for t in db.execute(select(Tenant).where(Tenant.id.in_(tenant_ids))).scalars()}
    rows = []
    for row in db.execute(select(M365Connection).where(M365Connection.tenant_id.in_(tenant_ids)).order_by(M365Connection.name)).scalars():
        snap = row.snapshot or {}
        state = row.log_state or {}
        rows.append({"id": row.id, "tenantId": row.tenant_id, "customer": names.get(row.tenant_id, ""), "name": row.name,
                     "tenantName": row.tenant_name or "", "directoryId": row.directory_id, "authMode": row.auth_mode or "app",
                     "consentedBy": row.consented_by or "", "status": row.status, "lastError": row.last_error,
                     "syncedAt": _iso(row.synced_at) if row.synced_at else None, "insights": snap.get("insights") or {},
                     "permissionsMissing": _missing_features(snap),
                     "logs": {k: {"available": (state.get(k) or {}).get("available"), "lastRunAt": (state.get(k) or {}).get("lastRunAt"),
                                  "error": (state.get(k) or {}).get("error", "")} for k in LOG_KINDS}})
    totals = {"tenants": len(rows), "users": 0, "licencesUnused": 0, "adminsWithoutMfa": 0, "serviceIssues": 0, "inactiveLicensed": 0,
              "needsAttention": 0}
    for r in rows:
        i = r["insights"]
        totals["users"] += int(i.get("enabledUsers") or 0)
        totals["licencesUnused"] += int(i.get("licencesUnused") or 0)
        totals["adminsWithoutMfa"] += len(((i.get("mfa") or {}).get("adminsWithoutMfa")) or [])
        totals["serviceIssues"] += int(i.get("serviceIssues") or 0)
        totals["inactiveLicensed"] += int(i.get("inactiveLicensed") or 0)
        if r["status"] == "failed" or (r["permissionsMissing"] or 0) > 0 or ((i.get("mfa") or {}).get("adminsWithoutMfa")):
            totals["needsAttention"] += 1
    return {"rows": rows, "totals": totals}


def workspace(db: Session, row: M365Connection) -> dict:
    snap = row.snapshot or {}
    day = utcnow() - timedelta(hours=24)
    counts = dict(db.execute(select(M365LogEntry.kind, func.count()).where(M365LogEntry.connection_id == row.id)
                             .group_by(M365LogEntry.kind)).all())
    recent = {(k, r): n for k, r, n in db.execute(
        select(M365LogEntry.kind, M365LogEntry.result, func.count()).where(M365LogEntry.connection_id == row.id, M365LogEntry.at >= day)
        .group_by(M365LogEntry.kind, M365LogEntry.result)).all()}
    oldest = db.execute(select(func.min(M365LogEntry.at)).where(M365LogEntry.connection_id == row.id)).scalar()
    org = next((o for o in snap.get("organization") or [] if isinstance(o, dict)), None)
    return {"id": row.id, "name": row.name, "tenantId": row.tenant_id, "tenantName": row.tenant_name or "", "directoryId": row.directory_id,
            "authMode": row.auth_mode or "app", "status": row.status, "lastError": row.last_error,
            "syncedAt": _iso(row.synced_at) if row.synced_at else None, "secretExpiresAt": _iso(row.secret_expires_at) if row.secret_expires_at else None,
            "consentedBy": row.consented_by or "",
            "organization": {k: org.get(k) for k in ("displayName", "countryLetterCode", "createdDateTime", "onPremisesSyncEnabled",
                                                    "onPremisesLastSyncDateTime")} if org else None,
            "domains": snap.get("domains"), "admins": snap.get("admins"), "serviceIssues": snap.get("serviceIssues"),
            "inactiveUsers": snap.get("inactiveUsers"), "insights": snap.get("insights") or {}, "permissions": snap.get("permissions"),
            "unavailable": snap.get("unavailable") or {},
            "logState": row.log_state or {},
            "logCounts": {"stored": {k: counts.get(k, 0) for k in LOG_KINDS}, "oldest": _iso(oldest) if oldest else None,
                          "signins24h": sum(n for (k, _), n in recent.items() if k == "signin"),
                          "signinFailures24h": sum(n for (k, r), n in recent.items() if k == "signin" and r == "failure"),
                          "audit24h": sum(n for (k, _), n in recent.items() if k == "audit")}}


def query_logs(db: Session, row: M365Connection, kind: str, q: str = "", result: str = "", since: datetime | None = None,
               until: datetime | None = None, limit: int = 200, offset: int = 0) -> dict:
    where = [M365LogEntry.connection_id == row.id, M365LogEntry.kind == kind]
    if q:
        like = f"%{q.strip()[:100]}%"
        where.append(or_(M365LogEntry.actor.ilike(like), M365LogEntry.app.ilike(like), M365LogEntry.ip.ilike(like),
                         M365LogEntry.activity.ilike(like), M365LogEntry.target.ilike(like), M365LogEntry.location.ilike(like)))
    if result:
        where.append(M365LogEntry.result == result)
    if since:
        where.append(M365LogEntry.at >= since)
    if until:
        where.append(M365LogEntry.at < until)
    total = db.execute(select(func.count()).select_from(M365LogEntry).where(*where)).scalar() or 0
    entries = db.execute(select(M365LogEntry).where(*where).order_by(M365LogEntry.at.desc()).limit(limit).offset(offset)).scalars()
    return {"total": total, "rows": [{"id": e.id, "at": _iso(e.at), "actor": e.actor, "app": e.app, "ip": e.ip, "location": e.location,
                                      "result": e.result, "activity": e.activity, "target": e.target, "details": e.details or {}}
                                     for e in entries]}
