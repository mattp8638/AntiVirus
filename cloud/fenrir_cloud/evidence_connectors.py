"""Continuous evidence connectors (GRC-11), and the signals from Fenrir's own records that were missing.

Connectors: GitHub (branch protection with required reviews on default branches; open critical Dependabot alerts) and
an HR roster (leavers whose accounts are still active). Each run records its success or error. A connector that has
failed, or whose last success is older than its maximum age, gives no verdict: the signal is "unknown" with the
reason, so a control is never shown as met from stale or missing data, or from configured policy alone.

Signals from Fenrir's records: backups (every backed-up machine has a recent backup, and backups are boot-verified),
the risk register (risks recorded and reviewed on time), and policy acknowledgement (people asked have accepted the
current version).
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import crypto
from .models import (BackupBootCheck, BackupImage, GrcConnector, GrcPolicy, GrcRegisterEntry, M365Connection, PolicyAttestation,
                     Tenant, User, utcnow)

GITHUB_API = "https://api.github.com"
BACKUP_MAX_AGE_HOURS = 48
BOOT_FRESH_DAYS = 90
ACK_TARGET = 0.9
M365_MAX_AGE_HOURS = 48
SIGNAL_LABELS = {"backup-protection": "Recent, boot-verified backups", "risk-register": "Risk register reviewed",
                 "policy-acknowledgement": "Policies acknowledged by staff", "dev-branch-protection": "Branch protection (GitHub)",
                 "dev-dependency-alerts": "Critical dependency alerts (GitHub)", "leavers-access-removed": "Leavers' access removed (HR roster)"}


def _aad(c: GrcConnector) -> str:
    return f"grc-connector:{c.tenant_id}:{c.id}"


def set_secret(c: GrcConnector, secret: str) -> None:
    c.secret = crypto.encrypt(secret, _aad(c)) if secret else None


def _secret(c: GrcConnector) -> str:
    return crypto.decrypt_bytes(c.secret, _aad(c)).decode() if c.secret else ""


# --- GitHub --------------------------------------------------------------------------------------------------------

def collect_github(c: GrcConnector, client: httpx.Client | None = None) -> dict:
    org = c.config.get("org", "")
    base = c.config.get("apiBase") or GITHUB_API
    http = client or httpx.Client(timeout=30)
    headers = {"Authorization": f"Bearer {_secret(c)}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

    def get(path: str, ok404: bool = False):
        r = http.get(f"{base}{path}", headers=headers)
        if ok404 and r.status_code == 404:
            return None
        if r.status_code >= 400:
            raise RuntimeError(f"GitHub {path.split('?')[0]}: {r.status_code} {r.text[:200]}")
        return r.json()

    repos, page = [], 1
    while True:
        batch = get(f"/orgs/{org}/repos?per_page=100&page={page}&type=all")
        repos += [r for r in batch if not r.get("archived")]
        if len(batch) < 100 or page >= 20:
            break
        page += 1
    unprotected = []
    for r in repos:
        prot = get(f"/repos/{org}/{r['name']}/branches/{r.get('default_branch') or 'main'}/protection", ok404=True)
        reviews = (prot or {}).get("required_pull_request_reviews") or {}
        if not prot or int(reviews.get("required_approving_review_count") or 0) < 1:
            unprotected.append(r["name"])
    alerts = get(f"/orgs/{org}/dependabot/alerts?state=open&severity=critical&per_page=100", ok404=True)
    return {"repos": len(repos), "unprotected": unprotected,
            "criticalAlerts": None if alerts is None else len(alerts),
            "alertRepos": sorted({(a.get("repository") or {}).get("name", "") for a in alerts or []})}


# --- HR roster -----------------------------------------------------------------------------------------------------

def parse_roster(text: str) -> list[dict]:
    """CSV with email, status (active / leaver) and optionally leave_date."""
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        r = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        if r.get("email"):
            out.append({"email": r["email"].lower(), "status": (r.get("status") or "active").lower(), "leaveDate": r.get("leave_date", "")})
    return out


def collect_hr(db: Session, c: GrcConnector) -> dict:
    roster = c.config.get("roster") or []
    if not roster:
        raise RuntimeError("no roster uploaded")
    today = utcnow().date().isoformat()
    leavers = {r["email"] for r in roster if r["status"] == "leaver" and (not r["leaveDate"] or r["leaveDate"] <= today)}
    active_users = {u.email.lower() for u in db.execute(select(User).where(User.tenant_id == c.tenant_id, User.active.is_(True))).scalars()}
    m365 = set()
    for conn in db.execute(select(M365Connection).where(M365Connection.tenant_id == c.tenant_id)).scalars():
        for u in ((conn.snapshot or {}).get("users") or []):
            if u.get("accountEnabled", True) and (u.get("userPrincipalName") or u.get("mail")):
                m365.add(str(u.get("userPrincipalName") or u.get("mail")).lower())
    still = sorted(leavers & (active_users | m365))
    return {"people": len(roster), "leavers": len(leavers), "stillActive": still,
            "checked": ["Fenrir accounts"] + (["Microsoft 365"] if m365 else []), "uploadedAt": c.config.get("uploadedAt")}


def run(db: Session, c: GrcConnector, client: httpx.Client | None = None) -> None:
    c.last_attempt_at = utcnow()
    try:
        c.result = collect_github(c, client) if c.kind == "github" else collect_hr(db, c)
        c.last_success_at, c.last_error = utcnow(), ""
    except Exception as exc:  # noqa: BLE001 - a connector's failure is recorded and shown, not raised
        c.last_error = str(exc)[:1000]


def run_due(db: Session, tenant: Tenant) -> None:
    for c in db.execute(select(GrcConnector).where(GrcConnector.tenant_id == tenant.id)).scalars():
        if not c.last_attempt_at or utcnow() - c.last_attempt_at > timedelta(hours=1):
            run(db, c)


def freshness(c: GrcConnector) -> str | None:
    """Why the connector's data cannot be used, or None."""
    if c.last_success_at is None:
        return f"{c.name}: never collected" + (f" ({c.last_error})" if c.last_error else "")
    if c.last_error and (c.last_attempt_at or c.last_success_at) > c.last_success_at:
        stale = utcnow() - c.last_success_at > timedelta(hours=c.max_age_hours)
        if stale:
            return f"{c.name}: collection failing since {c.last_success_at.isoformat()[:16]} ({c.last_error})"
    if utcnow() - c.last_success_at > timedelta(hours=c.max_age_hours):
        return f"{c.name}: stale, last collected {c.last_success_at.isoformat()[:16]}"
    return None


# --- signals -------------------------------------------------------------------------------------------------------

def _unknown(*why: str) -> dict:
    return {"passed": None, "evidence": list(why)}


def connector_signals(db: Session, tenant: Tenant) -> dict[str, dict]:
    out: dict[str, dict] = {}
    rows = db.execute(select(GrcConnector).where(GrcConnector.tenant_id == tenant.id)).scalars().all()
    gh = [c for c in rows if c.kind == "github"]
    hr = [c for c in rows if c.kind == "hr_roster"]
    if gh:
        problems = [p for p in (freshness(c) for c in gh) if p]
        if problems:
            out["dev-branch-protection"] = out["dev-dependency-alerts"] = _unknown(*problems)
        else:
            unprot = [f"{c.config.get('org')}/{r}" for c in gh for r in c.result.get("unprotected", [])]
            repos = sum(c.result.get("repos", 0) for c in gh)
            out["dev-branch-protection"] = {"passed": not unprot, "evidence": [f"{repos} repositories checked"] +
                                            [f"{r}: default branch without required review" for r in unprot[:20]]}
            if any(c.result.get("criticalAlerts") is None for c in gh):
                out["dev-dependency-alerts"] = _unknown("Dependabot alerts are not readable with this token")
            else:
                n = sum(c.result.get("criticalAlerts", 0) for c in gh)
                out["dev-dependency-alerts"] = {"passed": n == 0, "evidence": [f"{n} open critical dependency alerts"] +
                                                [f"in {r}" for c in gh for r in c.result.get("alertRepos", [])][:20]}
    if hr:
        problems = [p for p in (freshness(c) for c in hr) if p]
        if problems:
            out["leavers-access-removed"] = _unknown(*problems)
        else:
            still = [e for c in hr for e in c.result.get("stillActive", [])]
            out["leavers-access-removed"] = {"passed": not still, "evidence": [f"{sum(c.result.get('leavers', 0) for c in hr)} leavers checked against "
                                                                               + ", ".join(hr[0].result.get("checked", []))] +
                                             [f"{e}: left but still has an active account" for e in still[:20]]}
    return out


def record_signals(db: Session, tenant: Tenant) -> dict[str, dict]:
    now = utcnow()
    out: dict[str, dict] = {}
    images = db.execute(select(BackupImage).where(BackupImage.tenant_id == tenant.id)).scalars().all()
    if not images:
        out["backup-protection"] = _unknown("No backups are recorded for this customer")
    else:
        newest: dict[str, BackupImage] = {}
        for i in images:
            key = f"{i.agent_id}|{i.vm_name or ''}|{i.machine_id}"
            if key not in newest or i.created_unix > newest[key].created_unix:
                newest[key] = i
        old = [i for i in newest.values() if now.timestamp() - i.created_unix > BACKUP_MAX_AGE_HOURS * 3600]
        verified = db.execute(select(BackupBootCheck).where(BackupBootCheck.tenant_id == tenant.id, BackupBootCheck.outcome == "verified",
                                                            BackupBootCheck.at > now - timedelta(days=BOOT_FRESH_DAYS))).first()
        ev = [f"{len(newest)} backed-up machines or sources; {len(old)} without a backup in {BACKUP_MAX_AGE_HOURS} h"]
        ev += [f"{i.vm_name or i.hostname}: last backup {datetime.utcfromtimestamp(i.created_unix).isoformat()[:16]}" for i in old[:10]]
        ev.append("a backup was boot-verified in the last 90 days" if verified else "no backup boot-verified in the last 90 days")
        out["backup-protection"] = {"passed": not old and bool(verified), "evidence": ev}
    risks = db.execute(select(GrcRegisterEntry).where(GrcRegisterEntry.tenant_id == tenant.id, GrcRegisterEntry.register == "risk",
                                                      GrcRegisterEntry.status != "closed")).scalars().all()
    if not risks:
        out["risk-register"] = _unknown("No business risks are recorded")
    else:
        overdue = [r for r in risks if r.review_due and r.review_due < now]
        unscored = [r for r in risks if not (r.likelihood and r.impact)]
        out["risk-register"] = {"passed": not overdue and not unscored,
                                "evidence": [f"{len(risks)} open risks"] + [f"{r.ref}: review overdue" for r in overdue[:10]] +
                                            [f"{r.ref}: not scored" for r in unscored[:10]]}
    asked = db.execute(select(PolicyAttestation).where(PolicyAttestation.tenant_id == tenant.id,
                                                       PolicyAttestation.removed.is_(False))).scalars().all()
    if not asked:
        out["policy-acknowledgement"] = _unknown("Nobody has been asked to acknowledge policies")
    else:
        pols = {p.id: p for p in db.execute(select(GrcPolicy).where(GrcPolicy.tenant_id == tenant.id)).scalars()}
        current = sum(1 for a in asked if a.policy_id in pols and a.acknowledged_version == pols[a.policy_id].approved_version)
        share = current / len(asked)
        out["policy-acknowledgement"] = {"passed": share >= ACK_TARGET,
                                         "evidence": [f"{current} of {len(asked)} acknowledgements current ({round(share * 100)}%, target {int(ACK_TARGET * 100)}%)"]}
    return out


def m365_fresh(db: Session, tenant: Tenant) -> str | None:
    rows = db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant.id)).scalars().all()
    stale = [r for r in rows if not r.synced_at or utcnow() - r.synced_at > timedelta(hours=M365_MAX_AGE_HOURS)]
    if rows and len(stale) == len(rows):
        last = max((r.synced_at for r in rows if r.synced_at), default=None)
        return f"Microsoft 365 data is stale (last synchronised {last.isoformat()[:16] if last else 'never'})"
    return None
