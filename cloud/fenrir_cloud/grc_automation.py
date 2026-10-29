"""Continuous GRC: live control signals, a cross-framework control map, automated evidence and compliance drift.

* Signals are live checks over the customer's policy and fleet (compliance.py), Microsoft 365, backups, endpoint
  baselines (grc_baselines.py), third-party risk (tprm.py) and approved policies.
* The crosswalk (grc_library/crosswalk.yml) maps ~20 Fenrir common controls to the requirements they satisfy in every
  framework in the library, so one control, evidenced once, counts for Cyber Essentials, ISO 27001, CIS, NIST CSF,
  Essential Eight, SOC 2, PCI DSS, NIS2, DORA, the NCSC CAF and UK GDPR at once.
* Collection writes an "automated" evidence record per control when its signals change (or daily), hashed and linked
  to every mapped requirement of the customer's adopted frameworks. A signal that goes from passing to failing is
  compliance drift: it is audited, published as ``grc.drift`` and opens a ticket.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import timedelta
from functools import lru_cache

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit, events, grcprogramme as gp, services
from .models import (BackupPlan, BackupRun, GrcAdoption, GrcEvidence, GrcEvidenceLink, GrcPolicy, GrcRequirementState, M365Connection,
                     Tenant, utcnow)

log = logging.getLogger("fenrir.grc")
EVIDENCE_VALID_DAYS = 30
REFRESH_EVIDENCE = timedelta(hours=24)
MFA_TARGET = 95

# Signal key -> compliance.py control results it is made of (framework/control).
COMPLIANCE_SIGNALS = {
    "fleet-reporting": ("cis-v8-ig1/CIS-1",),
    "malware-protection": ("cyber-essentials/CE-4", "iso-27001/A.8.7"),
    "web-filtering": ("iso-27001/A.8.23",),
    "firewall": ("cyber-essentials/CE-1",),
    "secure-configuration": ("cyber-essentials/CE-2",),
    "patching": ("cyber-essentials/CE-5",),
    "vulnerabilities": ("cis-v8-ig1/CIS-7", "nist-csf-2/ID.RA"),
    "least-privilege": ("cyber-essentials/CE-3",),
    "application-control": ("cis-v8-ig1/CIS-2",),
    "monitoring": ("iso-27001/A.8.15", "iso-27001/A.8.16"),
    "incident-response": ("cis-v8-ig1/CIS-17", "nist-csf-2/RS.MI"),
}
SIGNAL_LABELS = {
    "fleet-reporting": "Devices reporting", "malware-protection": "Malware protection", "web-filtering": "Web and DNS filtering",
    "firewall": "Firewall policy", "secure-configuration": "Secure configuration policy", "patching": "Automatic patching",
    "vulnerabilities": "Exploitable vulnerabilities", "least-privilege": "Least privilege", "application-control": "Application control",
    "monitoring": "Logging and monitoring", "incident-response": "Incident response", "m365-mfa": "Microsoft 365 MFA",
    "backup": "Backups", "third-party-risk": "Third-party risk", "policies-approved": "Approved security policies",
}


@lru_cache(maxsize=1)
def crosswalk() -> list[dict]:
    doc = yaml.safe_load((gp.LIBRARY / "crosswalk.yml").read_text(encoding="utf-8"))
    return [{**c, "maps": {k: [str(i) for i in ids] for k, ids in (c.get("maps") or {}).items()}, "signals": c.get("signals") or []}
            for c in doc["controls"]]


def controls_for(framework_key: str, requirement_id: str) -> list[dict]:
    return [c for c in crosswalk() if requirement_id in c["maps"].get(framework_key, [])]


# --------------------------------------------------------------------------- signals


def _mfa(db: Session, tenant: Tenant) -> dict:
    rows = db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant.id)).scalars().all()
    figures = [((r.snapshot or {}).get("insights") or {}).get("mfa") or {} for r in rows]
    figures = [f for f in figures if f.get("percent") is not None]
    if not figures:
        return {"passed": None, "evidence": ["No Microsoft 365 tenant with MFA data is connected"]}
    worst = min(float(f["percent"]) for f in figures)
    return {"passed": worst >= MFA_TARGET,
            "evidence": [f"{r.tenant_name or r.name}: {((r.snapshot or {}).get('insights') or {}).get('mfa', {}).get('percent', '-')}% "
                         f"of users registered for MFA (target {MFA_TARGET}%)" for r in rows]}


def _backup(db: Session, tenant: Tenant) -> dict:
    plans = db.execute(select(BackupPlan).where(BackupPlan.tenant_id == tenant.id)).scalars().all()
    if not plans:
        return {"passed": None, "evidence": ["No backup plans are recorded for this customer"]}
    now, evidence, ok = utcnow(), [], True
    for plan in plans:
        last = db.scalar(select(func.max(BackupRun.completed_at)).where(BackupRun.plan_id == plan.id, BackupRun.status == "success"))
        allowed = timedelta(hours=max(24, 2 * (plan.rpo_hours or 24)))
        fresh = bool(last and now - last <= allowed)
        ok &= fresh
        evidence.append(f"{plan.name}: last successful backup {last.strftime('%Y-%m-%d %H:%M') + ' UTC' if last else 'never'}"
                        + ("" if fresh else f" (older than {int(allowed.total_seconds() // 3600)} h)"))
    return {"passed": ok, "evidence": evidence}


def _policies(db: Session, tenant: Tenant) -> dict:
    rows = db.execute(select(GrcPolicy).where(GrcPolicy.tenant_id == tenant.id, GrcPolicy.status != "retired")).scalars().all()
    if not rows:
        return {"passed": None, "evidence": ["No security policies are recorded"]}
    now = utcnow()
    approved = [p for p in rows if p.status == "approved"]
    overdue = [p for p in approved if p.review_due and p.review_due < now]
    return {"passed": bool(approved) and not overdue,
            "evidence": [f"{len(approved)} of {len(rows)} policies approved"] + [f"{p.title}: review overdue" for p in overdue]}


def signals(db: Session, tenant: Tenant) -> dict[str, dict]:
    """Every live signal: {key: {"passed": True|False|None (no data), "evidence": [str]}}."""
    from . import compliance, grc_baselines, tprm

    results = {f"{fw['framework']}/{c['id']}": c for fw in compliance.evaluate(db, tenant) for c in fw["controls"]}
    out: dict[str, dict] = {}
    for key, refs in COMPLIANCE_SIGNALS.items():
        found = [results[r] for r in refs if r in results]
        out[key] = {"passed": all(c["passed"] for c in found) if found else None,
                    "evidence": [e for c in found for e in c["evidence"]]}
    out["m365-mfa"] = _mfa(db, tenant)
    out["backup"] = _backup(db, tenant)
    out["policies-approved"] = _policies(db, tenant)
    out["third-party-risk"] = tprm.signal(db, tenant)
    for control in crosswalk():
        for key in control["signals"]:
            if key.startswith("baseline:"):
                out[key] = grc_baselines.signal(db, tenant, key.split(":", 1)[1])
    return out


def label(key: str) -> str:
    if key.startswith("baseline:"):
        control = next((c for c in crosswalk() if c["id"] == key.split(":", 1)[1]), None)
        return f"Endpoint baseline ({control['title'] if control else key})"
    return SIGNAL_LABELS.get(key, key)


# --------------------------------------------------------------------------- crosswalk status


def _adopted(db: Session, tenant: Tenant) -> set[str]:
    return set(db.execute(select(GrcAdoption.framework_key).where(GrcAdoption.tenant_id == tenant.id,
                                                                   GrcAdoption.status == "active")).scalars())


def control_status(sigs: list[dict]) -> str:
    evaluated = [s for s in sigs if s["passed"] is not None]
    if not evaluated:
        return "manual"
    return "passing" if all(s["passed"] for s in evaluated) else "failing"


def status(db: Session, tenant: Tenant) -> list[dict]:
    """Each common control: its live signals, and the requirements it covers in each framework with their status."""
    frameworks = gp.frameworks_for(db, tenant.id)
    adopted = _adopted(db, tenant)
    states = {(s.framework_key, s.requirement_id): s.status for s in db.execute(
        select(GrcRequirementState).where(GrcRequirementState.tenant_id == tenant.id)).scalars()}
    sig = signals(db, tenant)
    out = []
    for control in crosswalk():
        sigs = [{"key": k, "label": label(k), **sig.get(k, {"passed": None, "evidence": []})} for k in control["signals"]]
        mappings = []
        for key, ids in control["maps"].items():
            framework = frameworks.get(key)
            if framework is None:
                continue
            titles = {r["id"]: r["title"] for r in gp.requirements(framework)}
            for rid in ids:
                mappings.append({"framework": key, "frameworkName": framework["short"] or framework["name"], "requirementId": rid,
                                 "title": titles.get(rid, rid), "adopted": key in adopted,
                                 "status": states.get((key, rid), "not_started")})
        covered = [m for m in mappings if m["adopted"]]
        out.append({"id": control["id"], "title": control["title"], "description": control["description"], "signals": sigs,
                    "automated": control_status(sigs), "mappings": mappings,
                    "adoptedRequirements": len(covered),
                    "implemented": sum(1 for m in covered if m["status"] in ("implemented", "not_applicable"))})
    return out


# --------------------------------------------------------------------------- evidence and drift


def _fingerprint(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def collect(db: Session, tenant: Tenant, actor: str = "system:grc", force: bool = False) -> dict:
    """Write automated evidence for controls whose signals changed (or daily) and raise drift for newly failing signals."""
    sig = signals(db, tenant)
    adopted = _adopted(db, tenant)
    now = utcnow()
    created = []
    for control in crosswalk():
        captured = {k: sig[k] for k in control["signals"] if k in sig and sig[k]["passed"] is not None}
        if not captured:
            continue
        fingerprint = _fingerprint(captured)
        previous = db.execute(select(GrcEvidence).where(GrcEvidence.tenant_id == tenant.id, GrcEvidence.kind == "automated",
                                                        GrcEvidence.control_id == control["id"])
                              .order_by(GrcEvidence.created_at.desc()).limit(1)).scalar_one_or_none()
        if (not force and previous is not None and (previous.data or {}).get("fingerprint") == fingerprint
                and now - previous.created_at < REFRESH_EVIDENCE):
            continue
        state = control_status([{"passed": v["passed"]} for v in captured.values()])
        data = {"control": control["id"], "title": control["title"], "capturedAt": now.isoformat() + "Z", "status": state,
                "fingerprint": fingerprint, "signals": {k: {"label": label(k), **v} for k, v in captured.items()}}
        body = json.dumps(data, sort_keys=True, separators=(",", ":"))
        lines = [f"{'PASS' if v['passed'] else 'FAIL'} {label(k)}: " + "; ".join(v["evidence"][:4]) for k, v in captured.items()]
        row = GrcEvidence(tenant_id=tenant.id, title=f"{control['title']}: automated evidence ({state})", kind="automated",
                          description="\n".join(lines), content_type="application/json", size=len(body), data=data,
                          sha256=hashlib.sha256(body.encode()).hexdigest(), control_id=control["id"],
                          valid_until=now + timedelta(days=EVIDENCE_VALID_DAYS), uploaded_by=actor)
        db.add(row)
        db.flush()
        for key, ids in control["maps"].items():
            if key in adopted:
                for rid in ids:
                    db.add(GrcEvidenceLink(evidence_id=row.id, tenant_id=tenant.id, framework_key=key, requirement_id=rid))
        created.append(control["id"])
    settings = dict((tenant.settings or {}).get("grcAutomation") or {})
    last = settings.get("lastSignals") or {}
    drift = [k for k, v in sig.items() if last.get(k) is True and v["passed"] is False]
    for key in drift:
        _raise_drift(db, tenant, key, sig[key])
    settings.update(lastSignals={k: v["passed"] for k, v in sig.items()}, lastCollectedAt=now.isoformat())
    tenant.settings = {**(tenant.settings or {}), "grcAutomation": settings}
    if created:
        audit.record(db, actor, "grc.evidence.collected", tenant.name, tenant.id, controls=created)
    return {"evidenceCreated": created, "drift": drift}


def _raise_drift(db: Session, tenant: Tenant, key: str, signal: dict) -> None:
    controls = [c["id"] for c in crosswalk() if key in c["signals"]]
    subject = f"Compliance drift: {label(key)} is now failing"
    description = ("A control that was passing is now failing. Affected common controls: " + ", ".join(controls) + ".\n\n"
                   + "\n".join(signal["evidence"][:10]))
    ticket = services.open_ticket(db, tenant.id, subject, description, priority="P2", source="compliance")
    audit.record(db, "system:grc", "grc.drift", label(key), tenant.id, signal=key, controls=controls, ticket=ticket.id)
    events.publish(db, "grc.drift", {"tenantId": tenant.id, "signal": key, "controls": controls, "ticketId": ticket.id}, tenant.id,
                   key=f"grc.drift:{tenant.id}:{key}:{utcnow().strftime('%Y%m%d%H')}")


def tick(db: Session) -> None:
    """Hourly for customers with continuous compliance turned on."""
    for tenant in db.execute(select(Tenant).where(Tenant.kind == "customer")).scalars().all():
        if not ((tenant.settings or {}).get("grcAutomation") or {}).get("enabled"):
            continue
        try:
            collect(db, tenant)
            db.commit()
        except Exception as exc:  # noqa: BLE001 - one customer's failure must not stop the others
            db.rollback()
            log.warning("compliance collection failed for %s: %s", tenant.name, exc)


# --------------------------------------------------------------------------- cross-framework propagation


def propagate(db: Session, tenant: Tenant, framework_key: str, requirement_id: str, actor: str) -> list[dict]:
    """Carry an implemented requirement, and its evidence, to the requirements the same common control covers in the
    customer's other adopted frameworks. Requirements already implemented, not applicable or needing review stay as they are."""
    source = db.execute(select(GrcRequirementState).where(GrcRequirementState.tenant_id == tenant.id,
                                                          GrcRequirementState.framework_key == framework_key,
                                                          GrcRequirementState.requirement_id == requirement_id)).scalar_one_or_none()
    if source is None or source.status != "implemented":
        raise ValueError("Only an implemented requirement can be carried across frameworks")
    controls = controls_for(framework_key, requirement_id)
    if not controls:
        return []
    adopted = _adopted(db, tenant)
    frameworks = gp.frameworks_for(db, tenant.id)
    evidence_ids = list(db.execute(select(GrcEvidenceLink.evidence_id).where(
        GrcEvidenceLink.tenant_id == tenant.id, GrcEvidenceLink.framework_key == framework_key,
        GrcEvidenceLink.requirement_id == requirement_id)).scalars())
    updated = []
    for control in controls:
        for key, ids in control["maps"].items():
            if key not in adopted or key not in frameworks:
                continue
            reqs = {r["id"]: r for r in gp.requirements(frameworks[key])}
            for rid in ids:
                if (key, rid) == (framework_key, requirement_id) or rid not in reqs:
                    continue
                state = db.execute(select(GrcRequirementState).where(GrcRequirementState.tenant_id == tenant.id,
                                                                     GrcRequirementState.framework_key == key,
                                                                     GrcRequirementState.requirement_id == rid)).scalar_one_or_none()
                if state is not None and state.status in ("implemented", "not_applicable"):
                    continue
                if state is None:
                    state = GrcRequirementState(tenant_id=tenant.id, framework_key=key, requirement_id=rid)
                    db.add(state)
                note = f"Implemented through common control {control['id']} ({control['title']}), carried from {framework_key} {requirement_id}."
                state.status, state.updated_by, state.updated_at = "implemented", actor, utcnow()
                state.notes = (state.notes + "\n" if state.notes else "") + note
                state.requirement_hash, state.requirement_text = gp.requirement_hash(reqs[rid]), gp.requirement_wording(reqs[rid])
                present = set(db.execute(select(GrcEvidenceLink.evidence_id).where(
                    GrcEvidenceLink.tenant_id == tenant.id, GrcEvidenceLink.framework_key == key,
                    GrcEvidenceLink.requirement_id == rid)).scalars())
                for evidence_id in evidence_ids:
                    if evidence_id not in present:
                        db.add(GrcEvidenceLink(evidence_id=evidence_id, tenant_id=tenant.id, framework_key=key, requirement_id=rid))
                updated.append({"framework": key, "requirementId": rid, "control": control["id"]})
    if updated:
        audit.record(db, actor, "grc.crosswalk.propagated", f"{framework_key} {requirement_id}", tenant.id, updated=len(updated))
    return updated
