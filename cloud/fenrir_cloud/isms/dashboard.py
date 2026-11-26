"""ISMS dashboard tiles and email digests (ported from the standalone app's ``packages/programme/src/tiles.ts``).

Each tile answers one question from live data and names the tab that holds the records behind it. People choose and
order tiles for each customer; the same tiles make up their weekly or monthly digest, sent by the hourly maintenance
job. A person only sees the tiles their ISMS role allows, in the digest as on screen. The privacy, continuity and AI
tiles arrive with those modules (plan Phase 6).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import Tenant, User, utcnow
from .access import can
from .domain._js import iso_instant
from .domain.reports import next_digest_at
from .models import IsmsDashboardLayout, IsmsDigestSubscription, IsmsEvidence, IsmsTask, IsmsTenantControl

TILES = (
    {"id": "readiness", "title": "Readiness", "permission": "controls.view",
     "description": "Readiness score for the primary framework", "tab": "Statement of Applicability"},
    {"id": "control_health", "title": "Control health", "permission": "controls.view",
     "description": "Controls evidenced, in progress and not started", "tab": "ISMS controls"},
    {"id": "tasks", "title": "Tasks", "permission": "tasks.complete",
     "description": "Overdue tasks and tasks due this week", "tab": "ISMS tasks"},
    {"id": "evidence", "title": "Evidence", "permission": "evidence.view",
     "description": "Evidence expired or expiring within 30 days", "tab": "ISMS evidence"},
    {"id": "risks", "title": "Risks", "permission": "risks.view",
     "description": "Risks above appetite and reviews overdue", "tab": "ISMS risks"},
    {"id": "improvement", "title": "Nonconformities", "permission": "controls.view",
     "description": "Open, major and overdue nonconformities", "tab": "ISMS improvement"},
    {"id": "documents", "title": "Documents", "permission": "controls.view",
     "description": "Documents out of date or awaiting approval", "tab": "ISMS documents"},
    {"id": "audit", "title": "Next audit", "permission": "controls.view",
     "description": "Days to the next planned audit", "tab": "Internal audit"},
    {"id": "incidents", "title": "Incidents", "permission": "programme.manage",
     "description": "Open incidents and breach deadlines", "tab": "Suppliers and incidents"},
    {"id": "suppliers", "title": "Suppliers", "permission": "programme.manage",
     "description": "Supplier reviews overdue and unassessed suppliers", "tab": "Suppliers and incidents"},
)
TILE_IDS = tuple(t["id"] for t in TILES)
DEFAULT_TILES = ("readiness", "control_health", "tasks", "evidence", "risks", "improvement")


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def allowed_tiles(role: str | None) -> list[dict]:
    return [t for t in TILES if can(role, t["permission"])]


def compute_tiles(db: Session, tenant_id: str, ids: list[str]) -> list[dict]:
    from . import audits, documents, management, operations, programme, risk_register

    today = utcnow().date()
    now = utcnow()
    cache: dict[str, object] = {}

    def once(key, fn):
        if key not in cache:
            cache[key] = fn()
        return cache[key]

    out = []
    for tid in ids:
        d = next((t for t in TILES if t["id"] == tid), None)
        if d is None:
            continue
        base = {"id": tid, "title": d["title"], "tab": d["tab"]}
        if tid == "readiness":
            ready = programme.readiness(db, tenant_id)
            names = {f["framework"]: f["name"] for f in programme.framework_options(db, tenant_id)}
            first = ready[0] if ready else None
            score = first["score"] if first else None
            out.append({**base, "value": "Not started" if score is None else f"{score}%",
                        "detail": names.get(first["framework"], first["framework"]) if first
                        else "No framework selected",
                        "status": "neutral" if score is None else "good" if score >= 80 else
                        "warning" if score >= 50 else "problem"})
        elif tid == "control_health":
            rows = db.execute(select(IsmsTenantControl).where(IsmsTenantControl.tenant_id == tenant_id,
                                                              IsmsTenantControl.state != "not_applicable")).scalars().all()
            count = lambda s: sum(1 for c in rows if c.state == s)  # noqa: E731
            evidenced, in_progress, not_started = count("implemented_evidenced"), count("in_progress"), count("not_started")
            unassigned = sum(1 for c in rows if not c.owner_user_id)
            out.append({**base, "value": f"{evidenced} of {len(rows)}",
                        "detail": f"evidenced; {in_progress} in progress, {not_started} not started, "
                                  f"{unassigned} without an owner",
                        "status": "good" if rows and evidenced == len(rows) else "warning" if not_started else "neutral"})
        elif tid == "tasks":
            rows = db.execute(select(IsmsTask).where(IsmsTask.tenant_id == tenant_id, IsmsTask.status == "open")).scalars().all()
            overdue = sum(1 for t in rows if t.due_on < today)
            week = sum(1 for t in rows if today <= t.due_on <= today + timedelta(days=7))
            out.append({**base, "value": _plural(overdue, "overdue task"),
                        "detail": f"{week} due this week, {len(rows)} open", "status": "problem" if overdue else "good"})
        elif tid == "evidence":
            rows = db.execute(select(IsmsEvidence).where(IsmsEvidence.tenant_id == tenant_id)).scalars().all()
            expired = sum(1 for e in rows if e.valid_until and e.valid_until < today)
            soon = sum(1 for e in rows if e.valid_until and today <= e.valid_until <= today + timedelta(days=30))
            out.append({**base, "value": _plural(expired, "item") + " expired",
                        "detail": f"{soon} expiring within 30 days",
                        "status": "problem" if expired else "warning" if soon else "good"})
        elif tid == "risks":
            rows = [r for r in risk_register.risk_views(db, tenant_id) if r["status"] != "closed"]
            above = sum(1 for r in rows if not r["withinAppetite"] and
                        (r["residualScore"] if r["residualScore"] is not None else r["inherentScore"]) is not None)
            overdue = sum(1 for r in rows if r["reviewOverdue"])
            waiting = sum(1 for r in rows if r["treatment"] and not r["acceptance"])
            out.append({**base, "value": f"{above} above appetite",
                        "detail": f"{overdue} reviews overdue, {waiting} awaiting acceptance, {len(rows)} open",
                        "status": "problem" if above else "warning" if overdue else "good"})
        elif tid == "improvement":
            ncs = [n for n in management.nonconformity_rows(db, tenant_id, "open") if n["kind"] == "nonconformity"]
            major = sum(1 for n in ncs if n["severity"] == "major")
            overdue = sum(1 for n in ncs if n["overdue"])
            ready = sum(1 for n in ncs if n["stage"] == "ready_for_check")
            out.append({**base, "value": f"{len(ncs)} open",
                        "detail": f"{major} major, {overdue} overdue, {ready} ready for an effectiveness check",
                        "status": "problem" if major or overdue else "warning" if ncs else "good"})
        elif tid == "documents":
            rows = once("docs", lambda: documents.document_rows(db, tenant_id))
            stale = sum(1 for r in rows if r["outOfDate"])
            waiting = sum(1 for r in rows if r["latest"] and r["latest"]["state"] in ("in_review", "approved"))
            missing = sum(1 for r in rows if not r["latest"])
            out.append({**base, "value": f"{stale} out of date",
                        "detail": f"{waiting} awaiting approval, {missing} not generated, {len(rows)} in the set",
                        "status": "warning" if stale else "good"})
        elif tid == "audit":
            a = audits.next_audit(db, tenant_id)
            days = (datetime.fromisoformat(a["plannedStart"]).date() - today).days if a else 0
            out.append({**base, "value": _plural(days, "day") if a else "None planned",
                        "detail": f"{a['ref']} {a['title']}" if a else "Plan the internal audit programme",
                        "status": "neutral" if a else "warning"})
        elif tid == "incidents":
            rows = [i for i in operations.incident_rows(db, tenant_id) if i["socStatus"] not in ("resolved", "closed")]
            breaches = [i for i in rows if i["breachDeadline"] and not i["reportedToAuthorityAt"]]
            late = sum(1 for i in breaches if i["breachDeadline"] < iso_instant(now))
            out.append({**base, "value": f"{len(rows)} open",
                        "detail": f"{len(breaches)} personal data breaches not yet reported"
                                  + (f", {late} past the 72 hours" if late else ""),
                        "status": "problem" if late else "warning" if rows else "good"})
        elif tid == "suppliers":
            rows = [s for s in operations.supplier_rows(db, tenant_id) if s["status"] == "active"]
            overdue = sum(1 for s in rows if s["reviewOverdue"])
            unrated = sum(1 for s in rows if s["riskTier"] in ("unrated", "", None))
            out.append({**base, "value": f"{overdue} reviews overdue",
                        "detail": f"{unrated} not assessed, {len(rows)} active",
                        "status": "problem" if overdue else "warning" if unrated else "good"})
    return out


def _clean(ids, role: str | None) -> list[str]:
    allowed = {t["id"] for t in allowed_tiles(role)}
    return [i for i in dict.fromkeys(str(x) for x in ids) if i in allowed][:len(TILES)]


def layout(db: Session, tenant_id: str, user_id: str, role: str | None) -> list[str]:
    row = db.execute(select(IsmsDashboardLayout).where(IsmsDashboardLayout.tenant_id == tenant_id,
                                                       IsmsDashboardLayout.user_id == user_id)).scalar_one_or_none()
    return _clean(row.tiles if row else DEFAULT_TILES, role)


def save_layout(db: Session, tenant_id: str, user_id: str, actor: str, role: str | None, tiles: list[str]) -> list[str]:
    tiles = _clean(tiles, role)
    if not tiles:
        raise _error("Choose at least one tile.")
    row = db.execute(select(IsmsDashboardLayout).where(IsmsDashboardLayout.tenant_id == tenant_id,
                                                       IsmsDashboardLayout.user_id == user_id)).scalar_one_or_none()
    if row is None:
        db.add(IsmsDashboardLayout(tenant_id=tenant_id, user_id=user_id, tiles=tiles, updated_by=actor))
    else:
        row.tiles, row.updated_at, row.updated_by = tiles, utcnow(), actor
    audit.record(db, actor, "isms.dashboard_saved", ",".join(tiles), tenant_id)
    return tiles


def subscription(db: Session, tenant_id: str, user_id: str) -> dict | None:
    row = db.execute(select(IsmsDigestSubscription).where(IsmsDigestSubscription.tenant_id == tenant_id,
                                                          IsmsDigestSubscription.user_id == user_id)).scalar_one_or_none()
    return {"frequency": row.frequency, "enabled": row.enabled, "nextSendAt": iso_instant(row.next_send_at),
            "lastSentAt": iso_instant(row.last_sent_at) if row.last_sent_at else None} if row else None


def save_subscription(db: Session, tenant_id: str, user_id: str, actor: str, frequency: str, enabled: bool) -> None:
    if frequency not in ("weekly", "monthly"):
        raise _error("Choose weekly or monthly.")
    nxt = next_digest_at(utcnow(), frequency).replace(tzinfo=None)
    row = db.execute(select(IsmsDigestSubscription).where(IsmsDigestSubscription.tenant_id == tenant_id,
                                                          IsmsDigestSubscription.user_id == user_id)).scalar_one_or_none()
    if row is None:
        db.add(IsmsDigestSubscription(tenant_id=tenant_id, user_id=user_id, frequency=frequency, enabled=enabled,
                                      next_send_at=nxt, updated_by=actor))
    else:
        row.frequency, row.enabled, row.next_send_at, row.updated_by = frequency, enabled, nxt, actor
    audit.record(db, actor, "isms.digest_saved", frequency, tenant_id, enabled=enabled)


MARK = {"good": "OK", "warning": "ATTENTION", "problem": "ACTION", "neutral": "INFO"}


def digest_text(name: str, organization: str, frequency: str, tiles: list[dict]) -> tuple[str, str]:
    lines = [f"Hello {name},", "", f"Your {frequency} ISMS summary for {organization}:", ""]
    for t in tiles:
        lines.append(f"[{MARK[t['status']]}] {t['title']}: {t['value']} ({t['detail']})")
    lines += ["", "Open Governance in Fenrir for the records behind each figure.",
              "You can change or stop this email on the ISMS dashboard tab."]
    return f"{organization}: your {frequency} ISMS summary", "\n".join(lines)


def send_due_digests(db: Session, now: datetime | None = None) -> int:
    """Sends every enabled digest that is due. Run by the hourly maintenance job. Each person gets only the tiles
    their ISMS role still allows; someone who no longer holds a role gets nothing and their digest stops."""
    from .. import mailer
    from .memberships import active_role

    now = now or utcnow()
    sent = 0
    for s in db.execute(select(IsmsDigestSubscription).where(IsmsDigestSubscription.enabled.is_(True),
                                                             IsmsDigestSubscription.next_send_at <= now)).scalars().all():
        user = db.get(User, s.user_id)
        role = active_role(db, user, s.tenant_id) if user else None
        if role is None:
            s.enabled = False
            continue
        tiles = compute_tiles(db, s.tenant_id, layout(db, s.tenant_id, user.id, role))
        tenant = db.get(Tenant, s.tenant_id)
        subject, body = digest_text(user.name or user.email, tenant.name if tenant else "Your organization",
                                    s.frequency, tiles)
        mailer.send(user.email, subject, body)
        s.last_sent_at = now
        s.next_send_at = next_digest_at(now, s.frequency).replace(tzinfo=None)
        sent += 1
    return sent
