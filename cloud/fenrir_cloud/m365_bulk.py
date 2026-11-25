"""Cross-tenant Microsoft 365 bulk and scheduled actions (M365-30).

A bulk job runs one operation against many tenants, or many users across tenants. How it works:

* **Fixed targets.** The targets are checked and fixed when the job is created. Each target's tenant must be one the
  technician may manage, its connection must be working, and its last permission check must not show the feature
  missing. The list and its SHA-256 are stored. Nothing can be added to a job afterwards; a different set of targets
  is a new job. Targets that fail a check are recorded with the reason instead of being dropped silently.
* **Per-tenant permission at run time.** Before each item, the creator must still be active, still hold the
  permission and still reach the tenant, and the connection must still exist. Otherwise the item is ``skipped`` with
  the reason, and the other tenants carry on.
* **Throttling.** When Microsoft answers 429 (or 503 on a read) with Retry-After, that tenant waits: the item and the
  tenant's other pending items are not tried again before then. Other tenants keep going. After ``MAX_ATTEMPTS``
  throttled tries, the item fails.
* **Checkpoints.** Each item's outcome is committed before the next item starts, so a restart continues where the job
  stopped.
  * An item found ``running`` after a crash is never sent again: it becomes ``unknown``.
  * ``reconcile`` reads the tenant to settle ``unknown`` items where Microsoft's state shows the answer.
  * Otherwise a technician resolves the item.
* **Cancellation.** Cancelling stops new items from starting. An item already in flight finishes, and the rest become
  ``cancelled``.
* **Partial results.** The job ends as one of:
  * ``completed``: every item succeeded or was skipped as already compliant.
  * ``failed``: nothing succeeded.
  * ``partial``: anything in between.
  * ``cancelled``.
  Counts are kept per status and per tenant.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta
from time import monotonic

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import audit, crypto, events, m365_admin, m365_permissions, m365_standards
from .models import M365BulkItem, M365BulkJob, M365Connection, Tenant, User, utcnow

log = logging.getLogger("fenrir.m365.bulk")

RUN_BUDGET = 40.0
STALE_RUN = timedelta(minutes=10)
MAX_ATTEMPTS = 5
MAX_TARGETS = 1000

# operation -> what it targets, whether it changes the tenant, the console permission it needs, and the feature
# (m365_permissions.FEATURES) a connection's permission check must not show as missing.
OPERATIONS: dict[str, dict] = {
    "standard.evaluate": {"target": "tenant", "write": False, "permission": "configure", "feature": None,
                          "title": "Check a standard"},
    "standard.deploy": {"target": "tenant", "write": True, "permission": "m365_admin", "feature": None,
                        "title": "Deploy a standard"},
    "user.revoke_sessions": {"target": "user", "write": True, "permission": "m365_admin", "feature": "user.revoke_sessions",
                             "title": "Sign users out everywhere"},
    "user.signin": {"target": "user", "write": True, "permission": "m365_admin", "feature": "user.signin",
                    "title": "Block or allow sign-in"},
    "user.update": {"target": "user", "write": True, "permission": "m365_admin", "feature": "user.update",
                    "title": "Update user profile fields"},
}
TERMINAL = ("completed", "partial", "failed", "cancelled")
ITEM_DONE = ("succeeded", "failed", "unknown", "skipped", "cancelled")


class BulkError(Exception):
    pass


def validate_parameters(operation: str, parameters: dict) -> dict:
    if operation not in OPERATIONS:
        raise BulkError("Choose a supported bulk operation")
    p = dict(parameters or {})
    if operation.startswith("standard."):
        if set(p) - {"standard", "options"} or p.get("standard") not in m365_standards.STANDARDS:
            raise BulkError("Choose one of the listed standards")
        if not isinstance(p.get("options", {}), dict):
            raise BulkError("Standard options must be an object")
        return {"standard": p["standard"], "options": p.get("options") or {}}
    if operation == "user.revoke_sessions":
        if p:
            raise BulkError("This action takes no parameters")
        return {}
    if operation == "user.signin":
        if set(p) != {"accountEnabled"} or type(p["accountEnabled"]) is not bool:
            raise BulkError("accountEnabled must be true or false")
        return p
    allowed = {"department", "jobTitle", "usageLocation"}
    if not p or set(p) - allowed or not all(isinstance(v, str) and len(v) <= 128 for v in p.values()):
        raise BulkError("Choose supported profile fields (department, job title, usage location)")
    if "usageLocation" in p and not (len(p["usageLocation"]) == 2 and p["usageLocation"].isalpha() and p["usageLocation"].isupper()):
        raise BulkError("Usage location must be a two-letter uppercase country code")
    return p


def _hash(targets: list[dict]) -> str:
    return hashlib.sha256(json.dumps(targets, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _tenant_names(db: Session, ids) -> dict[str, str]:
    return {t.id: t.name for t in db.scalars(select(Tenant).where(Tenant.id.in_(list(ids))))} if ids else {}


def check_targets(db: Session, principal, operation: str, targets: list[dict]) -> tuple[list[dict], list[dict]]:
    """(eligible, excluded) from [{connectionId, targetId?, label?}]: nothing is written."""
    spec = OPERATIONS[operation]
    if not targets:
        raise BulkError("Choose at least one target")
    if len(targets) > MAX_TARGETS:
        raise BulkError(f"A bulk job takes at most {MAX_TARGETS} targets")
    principal.require(spec["permission"])
    connections = {c.id: c for c in db.scalars(select(M365Connection).where(
        M365Connection.id.in_([str(t.get("connectionId", "")) for t in targets])))}
    names = _tenant_names(db, {c.tenant_id for c in connections.values()})
    eligible, excluded, seen = [], [], set()
    for raw in targets:
        conn = connections.get(str(raw.get("connectionId", "")))
        target_id = str(raw.get("targetId") or "")
        label = str(raw.get("label") or target_id)[:300]
        entry = {"connectionId": str(raw.get("connectionId", "")), "targetId": target_id, "label": label}
        if conn is None or conn.tenant_id not in principal.tenant_ids:
            excluded.append({**entry, "reason": "No such Microsoft 365 connection in a customer you manage"})
            continue
        entry.update(tenantId=conn.tenant_id, tenantName=names.get(conn.tenant_id, ""), directoryId=conn.directory_id)
        if spec["target"] == "user":
            try:
                from uuid import UUID
                entry["targetId"] = str(UUID(target_id))
            except ValueError:
                excluded.append({**entry, "reason": "Not a Microsoft user ID"})
                continue
        else:
            entry["targetId"] = ""
            entry["label"] = entry["label"] or conn.tenant_name or conn.name
        key = (conn.id, entry["targetId"])
        if key in seen:
            excluded.append({**entry, "reason": "Listed twice"})
            continue
        seen.add(key)
        if conn.status in ("error", "disconnected", "revoked"):
            excluded.append({**entry, "reason": f"The connection is not working ({conn.status}): {conn.last_error or 'reconnect it first'}"})
            continue
        if spec["feature"] and m365_permissions.feature_available(conn.snapshot, spec["feature"]) is False:
            excluded.append({**entry, "reason": "The connection's last permission check shows this action is not granted"})
            continue
        eligible.append(entry)
    return eligible, excluded


def create(db: Session, principal, name: str, operation: str, parameters: dict, targets: list[dict],
           scheduled_for: datetime | None = None) -> M365BulkJob:
    parameters = validate_parameters(operation, parameters)
    eligible, excluded = check_targets(db, principal, operation, targets)
    if not eligible:
        raise BulkError("None of the targets can be used: " + "; ".join(sorted({e["reason"] for e in excluded}))[:300])
    now = utcnow()
    job = M365BulkJob(name=name[:200] or OPERATIONS[operation]["title"], operation=operation, parameters=parameters,
                      targets=eligible, targets_hash=_hash(eligible), excluded=excluded,
                      tenant_ids=sorted({t["tenantId"] for t in eligible}),
                      status="scheduled" if scheduled_for and scheduled_for > now else "queued",
                      scheduled_for=scheduled_for, created_by=principal.actor, created_by_user_id=principal.user.id)
    db.add(job)
    db.flush()
    for i, t in enumerate(eligible):
        db.add(M365BulkItem(job_id=job.id, position=i, tenant_id=t["tenantId"], connection_id=t["connectionId"],
                            target_id=t["targetId"], label=t["label"]))
    job.summary = {"counts": {"pending": len(eligible)}, "tenants": {}}
    audit.record(db, principal.actor, "m365.bulk_created", job.id, None, operation=operation, targets=len(eligible),
                 excluded=len(excluded), targetsHash=job.targets_hash, tenants=job.tenant_ids,
                 scheduledFor=scheduled_for.isoformat() if scheduled_for else None)
    return job


def visible(job: M365BulkJob, principal) -> bool:
    return set(job.tenant_ids or []) <= set(principal.tenant_ids)


def items(db: Session, job: M365BulkJob) -> list[M365BulkItem]:
    return list(db.scalars(select(M365BulkItem).where(M365BulkItem.job_id == job.id).order_by(M365BulkItem.position)))


def summarise(db: Session, job: M365BulkJob) -> dict:
    counts: dict[str, int] = {}
    tenants: dict[str, dict] = {}
    names = _tenant_names(db, job.tenant_ids or [])
    for it in items(db, job):
        counts[it.status] = counts.get(it.status, 0) + 1
        row = tenants.setdefault(it.tenant_id, {"name": names.get(it.tenant_id, ""), "counts": {}})
        row["counts"][it.status] = row["counts"].get(it.status, 0) + 1
    job.summary = {"counts": counts, "tenants": tenants, "verified": job.targets_hash == _hash(job.targets or []),
                   **({"error": job.summary["error"]} if (job.summary or {}).get("error") else {})}
    return job.summary


# ---- run-time authority -------------------------------------------------------------------------------------------

def _creator_reach(db: Session, job: M365BulkJob) -> tuple[User | None, set[str], str]:
    """The creator as they are now: (user, tenants they reach, why not) so a revoked technician's job stops."""
    from .deps import tenant_subtree
    from .security import has_permission

    user = db.get(User, job.created_by_user_id) if job.created_by_user_id else None
    if user is None or not user.active:
        return None, set(), "The technician who created this job is no longer active"
    permission = OPERATIONS[job.operation]["permission"]
    if user.role.startswith("custom:"):
        from . import roles

        allowed = permission in roles.permissions_of(db, user.role)
    else:
        allowed = has_permission(user.role, permission)
    if not allowed:
        return None, set(), f"The technician who created this job no longer has the {permission} permission"
    if user.role == "platform_admin":
        return user, {tid for (tid,) in db.execute(select(Tenant.id)).all()}, ""
    scope = tenant_subtree(db, user.tenant_id)
    if user.assigned_tenant_ids:
        assigned: set[str] = set()
        for tid in user.assigned_tenant_ids:
            if tid in scope:
                assigned |= tenant_subtree(db, tid)
        scope &= assigned
    return user, scope, ""


# ---- running --------------------------------------------------------------------------------------------------------

def _throttle(exc: Exception) -> float | None:
    if isinstance(exc, m365_admin.ProviderError):
        return exc.retry_after
    if isinstance(exc, httpx.HTTPStatusError):
        return m365_admin.retry_after(exc.response)
    return None


def _dispatch(conn: M365Connection, job: M365BulkJob, item: M365BulkItem) -> tuple[str, dict]:
    p = job.parameters or {}
    if job.operation == "standard.evaluate":
        out = m365_standards.evaluate(conn, p["standard"], p.get("options"))
        return "succeeded", {"compliance": out.get("status"), "detail": out.get("detail", "")}
    if job.operation == "standard.deploy":
        before = m365_standards.evaluate(conn, p["standard"], p.get("options"))
        if before.get("status") == "compliant":
            return "skipped", {"message": "Already compliant; nothing changed", "detail": before.get("detail", "")}
        out = m365_standards.deploy(conn, p["standard"], p.get("options"))
        return "succeeded", {"message": out.get("detail") or out.get("message") or "Deployed", "deployed": {
            k: v for k, v in out.items() if isinstance(v, (str, int, bool)) or v is None}}
    status, result = m365_admin.execute(conn, job.operation, item.target_id, p)
    result.pop("_secret", None)
    if "user" in result and isinstance(result["user"], dict):
        result["user"] = {k: result["user"].get(k) for k in ("id", "userPrincipalName", "accountEnabled", "department",
                                                             "jobTitle", "usageLocation") if k in result["user"]}
    return ("succeeded" if status.startswith("succeeded") else status), result


def _run_item(db: Session, job: M365BulkJob, item: M365BulkItem, reach: set[str], why_not: str) -> None:
    now = utcnow()
    conn = db.get(M365Connection, item.connection_id)
    reason = why_not or ("" if item.tenant_id in reach else "The creator can no longer manage this customer")
    if not reason and (conn is None or conn.tenant_id != item.tenant_id):
        reason = "The Microsoft 365 connection was removed"
    spec = OPERATIONS[job.operation]
    if not reason and spec["feature"] and m365_permissions.feature_available(conn.snapshot, spec["feature"]) is False:
        reason = "The connection no longer has the permission this action needs"
    if reason:
        item.status, item.result, item.finished_at = "skipped", {"message": reason}, now
        db.commit()
        return
    # Claim the item, then commit: from here a crash leaves it 'running', which is never dispatched again.
    claimed = db.execute(update(M365BulkItem).where(M365BulkItem.id == item.id, M365BulkItem.status == "pending")
                         .values(status="running", started_at=now, attempts=M365BulkItem.attempts + 1)
                         .execution_options(synchronize_session=False)).rowcount
    db.commit()
    if not claimed:
        return
    db.refresh(item)
    try:
        status, result = _dispatch(conn, job, item)
    except Exception as exc:  # noqa: BLE001 - every outcome is recorded on the item
        wait = _throttle(exc)
        uncertain = isinstance(exc, m365_admin.ProviderError) and exc.uncertain
        if wait is not None and not uncertain:
            if item.attempts >= MAX_ATTEMPTS:
                status, result = "failed", {"message": f"Microsoft kept throttling this tenant ({item.attempts} tries)", "throttled": True}
            else:
                until = utcnow() + timedelta(seconds=wait)
                item.status, item.not_before = "pending", until
                item.result = {"message": f"Microsoft throttled this tenant; trying again after {int(wait)} s", "throttled": True}
                # The whole tenant backs off; other tenants are not affected.
                db.execute(update(M365BulkItem).where(M365BulkItem.job_id == job.id, M365BulkItem.tenant_id == item.tenant_id,
                                                      M365BulkItem.status == "pending")
                           .values(not_before=until).execution_options(synchronize_session=False))
                db.commit()
                return
        elif isinstance(exc, m365_admin.ProviderError):
            status, result = ("unknown" if uncertain else "failed"), {"message": str(exc)}
        elif isinstance(exc, (m365_standards.StandardError, crypto.VaultError, ValueError, KeyError)):
            status, result = "failed", {"message": str(exc)[:300] or type(exc).__name__}
        elif isinstance(exc, httpx.HTTPStatusError):
            write = spec["write"] and exc.response.status_code >= 500
            status, result = ("unknown" if write else "failed"), {"message": f"Microsoft answered HTTP {exc.response.status_code}"
                                                                  + m365_admin.microsoft_said(exc.response)}
        elif isinstance(exc, httpx.HTTPError):
            status = "unknown" if spec["write"] else "failed"
            result = {"message": f"No answer from Microsoft ({type(exc).__name__})" + ("; check the tenant before retrying" if spec["write"] else "")}
        else:
            log.exception("bulk item %s failed unexpectedly", item.id)
            status = "unknown" if spec["write"] else "failed"
            result = {"message": f"Unexpected error ({type(exc).__name__}); the outcome must be checked"}
    item.status, item.result, item.finished_at, item.not_before = status, result, utcnow(), None
    db.commit()


def _finish(db: Session, job: M365BulkJob, actor: str) -> None:
    summary = summarise(db, job)
    counts = summary["counts"]
    if any(counts.get(s) for s in ("pending", "running")):
        return
    good = counts.get("succeeded", 0) + sum(1 for it in items(db, job) if it.status == "skipped" and
                                             (it.result or {}).get("message", "").startswith("Already compliant"))
    total = sum(counts.values())
    if job.status == "cancelling" or counts.get("cancelled"):
        job.status = "cancelled"
    elif good == total:
        job.status = "completed"
    elif good == 0 and not counts.get("unknown"):
        job.status = "failed"
    else:
        job.status = "partial"
    job.finished_at = utcnow()
    audit.record(db, actor, "m365.bulk_finished", job.id, None, status=job.status, counts=counts, tenants=job.tenant_ids)
    for tid, row in summary["tenants"].items():  # each customer's own audit shows what the job did to it
        audit.record(db, actor, "m365.bulk_tenant_result", job.id, tid, operation=job.operation, counts=row["counts"])
    events.publish(db, "m365.bulk_finished", {"jobId": job.id, "status": job.status, "counts": counts}, None,
                   key=f"m365-bulk:{job.id}:{job.status}:{sum(counts.values())}:{counts.get('succeeded', 0)}")
    db.commit()


def run(db: Session, job: M365BulkJob, actor: str, budget: float = RUN_BUDGET) -> dict:
    """Work through due items until the budget is used; returns {"more": bool, ...}."""
    if job.status in TERMINAL:
        return {"more": False, "status": job.status}
    if job.status == "scheduled":
        if job.scheduled_for and job.scheduled_for > utcnow():
            return {"more": False, "status": job.status}
        job.status = "queued"
    if _hash(job.targets or []) != job.targets_hash:
        job.status, job.finished_at = "failed", utcnow()
        job.summary = {**(job.summary or {}), "error": "The stored target list does not match its hash; nothing was run"}
        audit.record(db, actor, "m365.bulk_tampered", job.id, None)
        db.commit()
        return {"more": False, "status": job.status}
    _recover_stale(db, job)
    if job.status == "cancelling":
        _cancel_pending(db, job)
        _finish(db, job, actor)
        return {"more": False, "status": job.status}
    if job.status == "queued":
        job.status, job.started_at = "running", job.started_at or utcnow()
        audit.record(db, actor, "m365.bulk_started", job.id, None, operation=job.operation)
        db.commit()
    _user, reach, why_not = _creator_reach(db, job)
    started = monotonic()
    while monotonic() - started < budget:
        db.refresh(job)
        if job.status == "cancelling":
            _cancel_pending(db, job)
            break
        now = utcnow()
        due = db.scalars(select(M365BulkItem).where(M365BulkItem.job_id == job.id, M365BulkItem.status == "pending",
                                                    (M365BulkItem.not_before.is_(None)) | (M365BulkItem.not_before <= now))
                         .order_by(M365BulkItem.position).limit(1)).first()
        if due is None:
            break
        _run_item(db, job, due, reach, why_not)
    _finish(db, job, actor)
    waiting = db.scalars(select(M365BulkItem.not_before).where(M365BulkItem.job_id == job.id, M365BulkItem.status == "pending")).all()
    more = job.status not in TERMINAL and any(w is None or w <= utcnow() for w in waiting)
    return {"more": more, "status": job.status, "waitingUntil": max((w for w in waiting if w), default=None)}


def _recover_stale(db: Session, job: M365BulkJob) -> None:
    """A 'running' item older than STALE_RUN lost its answer (crash): unknown, never sent again."""
    db.execute(update(M365BulkItem).where(M365BulkItem.job_id == job.id, M365BulkItem.status == "running",
                                          M365BulkItem.started_at < utcnow() - STALE_RUN)
               .values(status="unknown", finished_at=utcnow(),
                       result={"message": "Fenrir lost the answer to this item; check the tenant, then resolve it"})
               .execution_options(synchronize_session=False))
    db.commit()


def _cancel_pending(db: Session, job: M365BulkJob) -> None:
    db.execute(update(M365BulkItem).where(M365BulkItem.job_id == job.id, M365BulkItem.status == "pending")
               .values(status="cancelled", finished_at=utcnow(), result={"message": "Cancelled before it started"})
               .execution_options(synchronize_session=False))
    db.commit()


def cancel(db: Session, job: M365BulkJob, actor: str) -> M365BulkJob:
    if job.status in TERMINAL:
        raise BulkError("This job has already finished")
    job.status, job.cancelled_by = "cancelling", actor
    audit.record(db, actor, "m365.bulk_cancelled", job.id, None)
    db.commit()
    _cancel_pending(db, job)
    _finish(db, job, actor)  # finishes now unless an item is in flight; the runner finishes it then
    return job


# ---- reconciliation ---------------------------------------------------------------------------------------------------

def reconcile(db: Session, job: M365BulkJob, actor: str) -> dict:
    """Settle unknown items from the tenant's live state where Microsoft's data answers the question."""
    settled, left = 0, 0
    for it in items(db, job):
        if it.status != "unknown":
            continue
        conn = db.get(M365Connection, it.connection_id)
        verdict = None
        try:
            if conn is not None:
                verdict = _observed(conn, job, it)
        except Exception as exc:  # noqa: BLE001
            it.result = {**(it.result or {}), "reconcileError": f"{type(exc).__name__}: {str(exc)[:200]}"}
        if verdict is None:
            left += 1
            continue
        it.status = "succeeded" if verdict else "failed"
        it.resolved_by = "reconciled"
        it.result = {**(it.result or {}), "reconciled": True, "reconciledAt": utcnow().isoformat() + "Z",
                     "message": "The tenant shows the change in place" if verdict else "The tenant does not show the change; it was not made"}
        settled += 1
    audit.record(db, actor, "m365.bulk_reconciled", job.id, None, settled=settled, unresolved=left)
    db.commit()
    if job.status in TERMINAL:
        job.status = "queued"  # recount
        _finish(db, job, actor)
    return {"settled": settled, "unresolved": left}


def _observed(conn: M365Connection, job: M365BulkJob, it: M365BulkItem) -> bool | None:
    p = job.parameters or {}
    if job.operation.startswith("standard."):
        out = m365_standards.evaluate(conn, p["standard"], p.get("options"))
        return True if out.get("status") == "compliant" else (None if job.operation == "standard.deploy" and out.get("reportOnly") else False)
    if job.operation == "user.revoke_sessions":
        return None  # Microsoft keeps no state that shows a revocation happened
    with m365_admin.session(conn) as (client, headers):
        current = m365_admin.user(client, headers, it.target_id)
    if job.operation == "user.signin":
        return current.get("accountEnabled") is p["accountEnabled"]
    return all((current.get(k) or "") == v for k, v in p.items())


def resolve(db: Session, job: M365BulkJob, item: M365BulkItem, outcome: str, actor: str) -> M365BulkItem:
    """A technician settles an unknown or failed item: succeeded, failed, or retry (failed or unknown only)."""
    if outcome not in ("succeeded", "failed", "retry"):
        raise BulkError("Choose succeeded, failed or retry")
    if item.status not in ("unknown", "failed") or (outcome != "retry" and item.status != "unknown"):
        raise BulkError("Only an unknown item can be marked, and only an unknown or failed one retried")
    if outcome == "retry":
        if job.status == "cancelled":
            raise BulkError("This job was cancelled")
        item.status, item.not_before, item.finished_at = "pending", None, None
        if job.status in TERMINAL:
            job.status, job.finished_at = "running", None
    else:
        item.status, item.finished_at = outcome, utcnow()
    item.resolved_by = actor
    item.result = {**(item.result or {}), "resolution": outcome, "resolvedAt": utcnow().isoformat() + "Z"}
    audit.record(db, actor, "m365.bulk_item_resolved", item.id, item.tenant_id, jobId=job.id, outcome=outcome)
    db.commit()
    if job.status in TERMINAL or outcome != "retry":
        _finish(db, job, actor)
    return item


# ---- scheduler -----------------------------------------------------------------------------------------------------

def tick(db: Session, budget: float = 10.0) -> int:
    """Every pass: start scheduled jobs that are due and continue running ones (shared time budget)."""
    started, worked = monotonic(), 0
    jobs = db.scalars(select(M365BulkJob).where(M365BulkJob.status.in_(("scheduled", "queued", "running", "cancelling")))
                      .order_by(M365BulkJob.created_at)).all()
    for job in jobs:
        left = budget - (monotonic() - started)
        if left <= 0:
            break
        if job.status == "scheduled" and job.scheduled_for and job.scheduled_for > utcnow():
            continue
        try:
            run(db, job, "system:m365-bulk", budget=left)
            worked += 1
        except Exception:  # noqa: BLE001 - one job must not stop the others
            db.rollback()
            log.exception("bulk job %s", job.id)
    return worked
