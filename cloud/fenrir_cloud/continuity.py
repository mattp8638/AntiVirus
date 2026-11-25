"""Business continuity (GRC-17): plans of business services with impact, recovery targets and dependencies, linked
to the backed-up machines and DR runbooks that recover them, and exercises.

What a plan says and what has been shown are kept apart:
  * a plan is a document: drafted, approved (a versioned snapshot), reviewed;
  * the assessment of each service is measured: the age of its newest backup against its RPO, whether its machines'
    backups were boot-verified, and the recovery time measured by DR runbook runs against its RTO;
  * an exercise records what was tested, when, by whom and the result; a technical exercise takes its numbers from a
    DR runbook run, never from what someone typed.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import BackupBootCheck, BackupImage, ContinuityExercise, ContinuityPlan, DrRun, DrRunbook, utcnow

CRITICALITY = ("critical", "high", "medium", "low")
BOOT_FRESH_DAYS = 90
EXERCISE_FRESH_DAYS = 365


def machine_key(i: BackupImage) -> str:
    return f"{i.agent_id or 'host:' + (i.hostname or '')}|{i.vm_name or ''}"


def clean_services(raw, runbooks: set[str]) -> list[dict]:
    """Validated services; raises ValueError with a message for the console."""
    if not isinstance(raw, list) or len(raw) > 200:
        raise ValueError("a plan has up to 200 services")
    out, ids = [], set()
    for s in raw:
        if not isinstance(s, dict):
            raise ValueError("each service is an object")
        sid = str(s.get("id") or uuid.uuid4().hex[:10])[:40]
        name = str(s.get("name") or "").strip()[:200]
        if not name or sid in ids:
            raise ValueError("each service needs a name (and a unique id)")
        ids.add(sid)
        crit = s.get("criticality") or "medium"
        if crit not in CRITICALITY:
            raise ValueError("criticality is critical, high, medium or low")
        rto, rpo = s.get("rtoMinutes"), s.get("rpoMinutes")
        for v, what in ((rto, "recovery time (RTO)"), (rpo, "recovery point (RPO)")):
            if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 60 * 24 * 90:
                raise ValueError(f"{name}: the {what} is a number of minutes, 1 to 129600")
        rb = s.get("runbookId") or None
        if rb is not None and rb not in runbooks:
            raise ValueError(f"{name}: the DR runbook is not one of this customer's")
        out.append({"id": sid, "name": name, "criticality": crit, "rtoMinutes": rto, "rpoMinutes": rpo,
                    "impact": str(s.get("impact") or "")[:4000], "owner": str(s.get("owner") or "")[:200],
                    "dependsOn": [str(d)[:40] for d in s.get("dependsOn") or []][:50],
                    "machines": [str(m)[:300] for m in s.get("machines") or [] if "|" in str(m)][:100],
                    "runbookId": rb, "manualSteps": str(s.get("manualSteps") or "")[:8000]})
    known = {s["id"] for s in out}
    for s in out:
        bad = [d for d in s["dependsOn"] if d not in known or d == s["id"]]
        if bad:
            raise ValueError(f"{s['name']}: depends on an unknown service")
    # No dependency cycles: a cycle has no recovery order.
    graph = {s["id"]: s["dependsOn"] for s in out}
    state: dict[str, int] = {}

    def visit(n: str) -> None:
        if state.get(n) == 1:
            raise ValueError("the services' dependencies form a cycle")
        if state.get(n) == 2:
            return
        state[n] = 1
        for d in graph[n]:
            visit(d)
        state[n] = 2

    for n in graph:
        visit(n)
    return out


def recovery_order(services: list[dict]) -> list[list[str]]:
    """Waves of service ids: each wave depends only on earlier ones."""
    left = {s["id"]: set(s["dependsOn"]) for s in services}
    waves = []
    while left:
        wave = sorted(n for n, deps in left.items() if not deps)
        if not wave:
            break
        waves.append(wave)
        for n in wave:
            del left[n]
        for deps in left.values():
            deps.difference_update(wave)
    return waves


def snapshot(plan: ContinuityPlan) -> dict:
    body = {"name": plan.name, "scope": plan.scope, "owner": plan.owner, "services": plan.services,
            "version": plan.version}
    return {**body, "sha256": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()}


def _unix(dt: datetime) -> int:
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def _run_rto(run: DrRun, machines: list[str]) -> tuple[int | None, list[str]]:
    """Seconds until the last of `machines` was up in `run`, and those not up."""
    items = {i.get("key"): i for i in run.items or []}
    secs, missing = [], []
    for m in machines:
        it = items.get(m)
        if it is None or it.get("seconds") is None or it.get("state") not in ("up", "warning"):
            missing.append(m)
        else:
            secs.append(int(it["seconds"]))
    return (max(secs) if secs and not missing else None), missing


def assess(db: Session, plan: ContinuityPlan) -> dict:
    """Each service measured against its targets from backups, boot checks, DR runs and exercises."""
    now = utcnow()
    images = db.execute(select(BackupImage).where(BackupImage.tenant_id == plan.tenant_id)).scalars().all()
    by_machine: dict[str, list[BackupImage]] = {}
    for i in images:
        by_machine.setdefault(machine_key(i), []).append(i)
    verified = {c.image_id for c in db.execute(select(BackupBootCheck).where(
        BackupBootCheck.tenant_id == plan.tenant_id, BackupBootCheck.outcome == "verified",
        BackupBootCheck.at > now - timedelta(days=BOOT_FRESH_DAYS))).scalars()}
    exercises = db.execute(select(ContinuityExercise).where(ContinuityExercise.plan_id == plan.id)
                           .order_by(ContinuityExercise.held_on.desc())).scalars().all()
    targets = {s["id"]: s for s in plan.services or []}
    out = []
    for s in plan.services or []:
        findings, evidence = [], {}
        # Recovery point: the oldest "newest backup" among the service's machines.
        newest = []
        for m in s["machines"]:
            ims = by_machine.get(m) or []
            if not ims:
                findings.append(f"no backup of {m.split('|')[1] or m.split('|')[0]}")
                newest.append(None)
            else:
                newest.append(max(i.created_unix for i in ims))
        if not s["machines"]:
            findings.append("no machines linked: recovery cannot be measured")
        age = None
        if newest and all(n is not None for n in newest):
            age = (_unix(now) - min(newest)) // 60
            evidence["backupAgeMinutes"] = age
            if age > s["rpoMinutes"]:
                findings.append(f"newest backup is {age} min old, more than the RPO of {s['rpoMinutes']} min")
        boot_ok = bool(s["machines"]) and all(
            any(i.image_id in verified for i in by_machine.get(m) or []) for m in s["machines"])
        evidence["bootVerified"] = boot_ok
        # Recovery time: the latest finished DR run of the service's runbook.
        measured = None
        if s.get("runbookId"):
            run = db.execute(select(DrRun).where(DrRun.runbook_id == s["runbookId"],
                                                 DrRun.state.in_(("succeeded", "warning", "failed")))
                             .order_by(DrRun.started_at.desc()).limit(1)).scalars().first()
            if run is None:
                findings.append("its DR runbook has never been run")
            else:
                secs, missing = _run_rto(run, s["machines"])
                evidence["drRun"] = {"id": run.id, "at": run.started_at.isoformat(), "state": run.state,
                                     "mode": run.mode, "rtoSeconds": secs, "notUp": missing}
                if missing:
                    findings.append(f"{len(missing)} machine(s) did not come up in the last DR run")
                elif secs is not None:
                    measured = secs
                    if secs > s["rtoMinutes"] * 60:
                        findings.append(f"last DR run took {secs // 60} min, more than the RTO of {s['rtoMinutes']} min")
                if now - run.started_at > timedelta(days=EXERCISE_FRESH_DAYS):
                    findings.append("the last DR run is more than a year old")
        else:
            findings.append("no DR runbook: recovery time is not measured")
        # Dependencies must not take longer to recover than the service itself.
        for d in s["dependsOn"]:
            dep = targets.get(d)
            if dep and dep["rtoMinutes"] > s["rtoMinutes"]:
                findings.append(f"depends on {dep['name']}, whose RTO ({dep['rtoMinutes']} min) is longer")
        ex = next((e for e in exercises if s["id"] in (e.services or []) and e.outcome in ("passed", "partial")
                   and now - e.held_on < timedelta(days=EXERCISE_FRESH_DAYS)), None)
        if ex:
            evidence["exercise"] = {"id": ex.id, "kind": ex.kind, "outcome": ex.outcome, "heldOn": ex.held_on.isoformat()}
        technical_ok = bool(ex and ex.kind == "technical" and (ex.results or {}).get(s["id"], {}).get("met"))
        if technical_ok and not findings:
            capability = "exercised"  # a recent technical exercise met the targets, and nothing has slipped since
        elif measured is not None and measured <= s["rtoMinutes"] * 60 and not findings:
            capability = "measured"  # a DR run met the RTO, but no exercise has been recorded against the plan
        elif findings:
            capability = "gap"
        else:
            capability = "planned"
        out.append({"serviceId": s["id"], "name": s["name"], "criticality": s["criticality"],
                    "rtoMinutes": s["rtoMinutes"], "rpoMinutes": s["rpoMinutes"], "measuredRtoSeconds": measured,
                    "capability": capability, "findings": findings, "evidence": evidence})
    return {"planId": plan.id, "planStatus": plan.status, "approvedVersion": plan.approved_version,
            "version": plan.version, "assessedAt": now.isoformat(), "order": recovery_order(plan.services or []),
            "services": out}


def exercise_results(db: Session, plan: ContinuityPlan, run: DrRun, service_ids: list[str]) -> tuple[str, dict]:
    """A technical exercise's outcome from a DR run: each service's measured time against its RTO."""
    results = {}
    for s in plan.services or []:
        if s["id"] not in service_ids:
            continue
        secs, missing = _run_rto(run, s["machines"])
        met = secs is not None and not missing and secs <= s["rtoMinutes"] * 60
        results[s["id"]] = {"name": s["name"], "rtoMinutes": s["rtoMinutes"], "measuredSeconds": secs,
                            "notUp": missing, "met": met}
    if not results or run.state == "failed" or not any(r["met"] for r in results.values()):
        outcome = "failed"
    elif all(r["met"] for r in results.values()):
        outcome = "passed"
    else:
        outcome = "partial"
    return outcome, results


def runbook_ids(db: Session, tenant_id: str) -> set[str]:
    return set(db.execute(select(DrRunbook.id).where(DrRunbook.tenant_id == tenant_id)).scalars())
