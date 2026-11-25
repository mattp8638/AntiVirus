"""An incident's full record, and its governance evidence (FLOW-03).

The report brings together what happened (the alerts, from endpoints, Microsoft 365, backups and other sources, in
one timeline), what was done (each response command: who issued it, any two-person approval behind it, and the
result the device reported), the restoration (recorded steps and the backup restores and recoveries of the incident's
devices since it began), the playbook checklist and the evidence attached. When the incident is closed the report is
kept as governance evidence for the incident-response control, linked to the matching requirements of the customer's
adopted frameworks, with its SHA-256.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import grc_automation
from .models import (Alert, ApprovalRequest, BackupAgent, BackupJob, Command, GrcEvidence, GrcEvidenceLink, Incident,
                     IncidentEvidence, Tenant, utcnow)

CONTROL = "FC-INCIDENT"
RESTORE_KINDS = ("restore", "restore_files", "restore_app", "boot_check", "restore_saas", "restore_kubernetes")


def report(db: Session, inc: Incident) -> dict:
    alerts = db.execute(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.created_at)).scalars().all()
    commands = db.execute(select(Command).where(Command.incident_id == inc.id).order_by(Command.created_at)).scalars().all()
    devices = sorted({d for d in [inc.device_id, *[a.device_id for a in alerts], *[c.device_id for c in commands]] if d})
    approvals = db.execute(select(ApprovalRequest).where(ApprovalRequest.tenant_id == inc.tenant_id,
                                                         ApprovalRequest.requested_at >= inc.created_at)).scalars().all()

    def approval_for(c: Command) -> dict | None:
        a = next((a for a in approvals if c.device_id in (a.device_ids or []) and a.kind and c.type.startswith(a.kind.split(".")[0])
                  and a.status in ("approved", "executed")), None)
        return {"id": a.id, "requestedBy": a.requested_by, "decidedBy": a.decided_by,
                "decidedAt": a.decided_at.isoformat() if a.decided_at else None} if a else None

    agents = [a.id for a in db.execute(select(BackupAgent).where(BackupAgent.device_id.in_(devices or [""]))).scalars()]
    restores = db.execute(select(BackupJob).where(BackupJob.tenant_id == inc.tenant_id,
                                                  BackupJob.created_at >= inc.created_at)).scalars().all()
    restores = [j for j in restores if (j.kind or {}).get("type") in RESTORE_KINDS
                and (j.agent_id in agents or (j.requested_by or "") == f"incident:{inc.id}")]
    attached = db.execute(select(IncidentEvidence).where(IncidentEvidence.incident_id == inc.id)
                          .order_by(IncidentEvidence.created_at)).scalars().all()
    sources = sorted({(a.details or {}).get("category") or a.rule_id.split(".")[0] for a in alerts})
    return {
        "format": "fenrir-incident-report", "version": 1, "generatedAt": utcnow().isoformat(),
        "incident": {"id": inc.id, "title": inc.title, "severity": inc.severity, "status": inc.status, "playbook": inc.playbook,
                     "createdAt": inc.created_at.isoformat(), "updatedAt": inc.updated_at.isoformat(), "mitre": inc.mitre},
        "sources": sources, "devices": devices,
        "alerts": [{"at": a.created_at.isoformat(), "rule": a.rule_id, "title": a.title, "severity": a.severity,
                    "source": (a.details or {}).get("category") or a.rule_id.split(".")[0], "status": a.status} for a in alerts],
        "response": [{"at": c.created_at.isoformat(), "action": c.type, "device": c.device_id, "by": c.issued_by,
                      "status": c.status, "result": c.result, "completedAt": c.completed_at.isoformat() if c.completed_at else None,
                      "approval": approval_for(c)} for c in commands],
        "restoration": {"steps": [t for t in inc.timeline or [] if t.get("kind") == "restoration"],
                        "backupJobs": [{"id": j.id, "type": j.kind.get("type"), "state": j.state, "by": j.requested_by,
                                        "createdAt": j.created_at.isoformat(),
                                        "finishedAt": j.finished_at.isoformat() if j.finished_at else None} for j in restores]},
        "checklist": inc.checklist or [],
        "timeline": inc.timeline or [],
        "evidence": [{"name": e.name, "sha256": e.sha256, "author": e.author, "at": e.created_at.isoformat()} for e in attached],
    }


def to_governance(db: Session, inc: Incident, actor: str) -> GrcEvidence:
    """Keep the report as evidence for the incident-response control, linked to the adopted frameworks."""
    doc = report(db, inc)
    body = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
    sha = hashlib.sha256(body.encode()).hexdigest()
    lines = [f"{len(doc['alerts'])} alerts from {', '.join(doc['sources']) or 'no source'}",
             f"{len(doc['response'])} response actions ({sum(1 for r in doc['response'] if r['approval'])} with two-person approval)",
             f"{len(doc['restoration']['steps'])} restoration steps, {len(doc['restoration']['backupJobs'])} backup restores or recoveries",
             f"checklist {sum(1 for c in doc['checklist'] if c.get('done'))}/{len(doc['checklist'])} done"]
    ev = GrcEvidence(tenant_id=inc.tenant_id, title=f"Incident record: {inc.title}", kind="automated", control_id=CONTROL,
                     description="\n".join(lines), content_type="application/json", size=len(body), data=doc, sha256=sha,
                     uploaded_by=actor)
    db.add(ev)
    db.flush()
    tenant = db.get(Tenant, inc.tenant_id)
    adopted = grc_automation._adopted(db, tenant) if tenant else set()
    control = next((c for c in grc_automation.crosswalk() if c["id"] == CONTROL), None)
    for fw, ids in (control or {}).get("maps", {}).items():
        if fw in adopted:
            for rid in ids:
                db.add(GrcEvidenceLink(evidence_id=ev.id, tenant_id=inc.tenant_id, framework_key=fw, requirement_id=rid))
    db.add(IncidentEvidence(incident_id=inc.id, tenant_id=inc.tenant_id, name="Incident record (governance evidence)",
                            content=f"Kept as compliance evidence {ev.id}, SHA-256 {sha}", sha256=sha, author=actor))
    inc.timeline = (inc.timeline or []) + [{"at": utcnow().isoformat(), "kind": "governance",
                                            "text": f"Incident record kept as compliance evidence (SHA-256 {sha[:16]}…)"}]
    return ev
