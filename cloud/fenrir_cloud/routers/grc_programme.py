"""Compliance programmes per customer (frameworks, requirements, answers), policies and evidence."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import secrets
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import audit, crypto, grcprogramme as gp
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import (GrcAdoption, GrcAssessmentSnapshot, GrcEvidence, GrcEvidenceLink, GrcFramework, GrcPolicy, GrcPolicyVersion, GrcRequirementState,
                      Tenant, utcnow)
from ..serialize import to_dict

router = APIRouter(prefix="/api/console/grc", tags=["GRC programmes"])
MAX_EVIDENCE_BYTES = 25 * 1024 * 1024
SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]+")


def _tenant(db: Session, principal: Principal, tenant_id: str) -> Tenant:
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Customer not found")
    return tenant


def _naive(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


# --- library -------------------------------------------------------------------------------------------------------

@router.get("/library")
def library(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    if tenant_id:
        principal.check_tenant(tenant_id)
    frameworks = gp.frameworks_for(db, tenant_id)
    return {"frameworks": [{"key": f["key"], "name": f["name"], "short": f["short"], "version": f["version"], "description": f["description"],
                            "questionSet": f["questionSet"], "source": f["source"], "importedId": f.get("importedId"),
                            **{k: f.get(k, "") for k in (*gp.CATALOGUE_FIELDS, "currentVersion")},
                            "requirements": len(gp.requirements(f)),
                            "policies": len(gp.templates_for(f["key"]))} for f in frameworks.values()],
            "policies": [{"key": t["key"], "title": t["title"], "summary": t["summary"],
                          "frameworks": {k: len(v) for k, v in t["maps"].items()}} for t in gp.policy_templates().values()]}


@router.get("/library/policies/{key}")
def policy_template(key: str, principal: Principal = Depends(current_principal)):
    principal.require("read")
    template = gp.policy_templates().get(key)
    if template is None:
        raise HTTPException(404, "Template not found")
    return template


class ImportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str | None = None  # None: every customer (platform administrators only)
    key: str = Field(min_length=2, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    short: str = Field(default="", max_length=80)
    version: str = Field(default="", max_length=80)
    description: str = Field(default="", max_length=5000)
    questionSet: bool = False
    format: Literal["json", "yaml", "csv"] = "json"
    content: str = Field(min_length=2, max_length=5_000_000)
    dryRun: bool = False  # only report what would change


@router.post("/library/frameworks/import")
def import_framework(body: ImportInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Load a framework or question set (for example the current IASME Cyber Essentials booklet). Same key as a
    built-in framework = replaces it; requirement ids that match keep their policy links, answers and evidence."""
    principal.require("grc")
    if body.tenantId:
        principal.check_tenant(body.tenantId)
    elif principal.user.role != "platform_admin":
        raise HTTPException(403, "Only platform administrators can import a framework for every customer")
    if gp.retired_framework(body.key, body.name):
        raise HTTPException(422, "This framework is retired from the UK governance catalogue")
    if not gp.KEY_RE.match(body.key):
        raise HTTPException(400, "Key must be lower-case letters, digits and dashes")
    try:
        doc = gp.parse_import(body.content, "csv" if body.format == "csv" else "yaml")
        normalised = gp._normalise({"key": body.key, "name": body.name, "sections": doc["sections"]}, "imported")
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(400, f"Could not read the framework: {exc}")
    except Exception:  # yaml.YAMLError and friends
        raise HTTPException(400, "Could not read the framework: not valid JSON, YAML or CSV")
    current = gp.frameworks_for(db, body.tenantId).get(body.key)
    diff = gp.diff_frameworks(current, normalised)
    affected = gp.tenants_using(db, body.key, body.tenantId)
    if body.dryRun:
        return {"key": body.key, "dryRun": True, "requirements": len(gp.requirements(normalised)),
                "replacesBuiltIn": body.key in gp.builtin_frameworks(), "diff": diff, "affectedCustomers": len(affected)}
    gp.freeze_before_change(db, body.key, body.tenantId, principal.actor,
                            f"Before import of {body.name} {body.version}".strip())
    row = db.execute(select(GrcFramework).where(GrcFramework.key == body.key, GrcFramework.tenant_id.is_(None) if body.tenantId is None
                                                else GrcFramework.tenant_id == body.tenantId)).scalar_one_or_none()
    if row is None:
        row = GrcFramework(tenant_id=body.tenantId, key=body.key)
        db.add(row)
    row.name, row.short, row.version, row.description = body.name, body.short or body.name, body.version, body.description
    row.question_set, row.created_by = body.questionSet or bool(doc.get("questionSet")), principal.actor
    row.sections = [{"id": s["id"], "title": s["title"], "requirements": s["requirements"]} for s in normalised["sections"]]
    db.flush()
    audit.record(db, principal.actor, "grc.framework_imported", body.key, body.tenantId,
                 requirements=len(gp.requirements(normalised)), replacesBuiltIn=body.key in gp.builtin_frameworks(),
                 added=len(diff["added"]), removed=len(diff["removed"]), changed=len(diff["changed"]), affectedCustomers=len(affected))
    db.commit()
    return {"key": body.key, "requirements": len(gp.requirements(normalised)), "replacesBuiltIn": body.key in gp.builtin_frameworks(),
            "diff": diff, "affectedCustomers": len(affected)}


@router.delete("/library/frameworks/imported/{framework_id}")
def delete_import(framework_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    row = db.get(GrcFramework, framework_id)
    if row is None or (row.tenant_id and row.tenant_id not in principal.tenant_ids) or (row.tenant_id is None and principal.user.role != "platform_admin"):
        raise HTTPException(404, "Not found")
    gp.freeze_before_change(db, row.key, row.tenant_id, principal.actor, f"Before removing the imported {row.name} {row.version}".strip())
    audit.record(db, principal.actor, "grc.framework_import_deleted", row.key, row.tenant_id)
    db.delete(row)
    db.commit()
    return {"ok": True}


# --- programmes ----------------------------------------------------------------------------------------------------

@router.get("/programmes")
def programmes(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Adopted frameworks with progress, for one customer or all visible ones."""
    principal.require("read")
    tenant_ids = scoped_tenant(principal, tenant_id)
    out = []
    for adoption in db.execute(select(GrcAdoption).where(GrcAdoption.tenant_id.in_(tenant_ids), GrcAdoption.status == "active")).scalars():
        tenant = db.get(Tenant, adoption.tenant_id)
        try:
            summary = gp.programme(db, tenant, adoption.framework_key, include_requirements=False)
        except KeyError:
            continue
        if not summary["retired"]:
            out.append({"tenantId": tenant.id, **summary})
    return out


class AdoptInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    frameworkKey: str
    targetDate: datetime | None = None
    scope: str = Field(default="", max_length=5000)
    createPolicies: bool = True
    owner: str = Field(default="", max_length=200)
    securityContact: str = Field(default="", max_length=200)


def _adopt_policy(db: Session, tenant: Tenant, key: str, owner: str, contact: str, actor: str) -> GrcPolicy | None:
    if db.execute(select(GrcPolicy.id).where(GrcPolicy.tenant_id == tenant.id, GrcPolicy.template_key == key,
                                             GrcPolicy.status != "retired")).first():
        return None
    template = gp.policy_templates()[key]
    policy = GrcPolicy(tenant_id=tenant.id, template_key=key, title=template["title"], summary=template["summary"],
                       body=gp.render_template(template, tenant, owner, contact, 12), owner=owner, updated_by=actor)
    db.add(policy)
    return policy


@router.post("/programmes")
def adopt(body: AdoptInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    tenant = _tenant(db, principal, body.tenantId)
    if body.frameworkKey not in gp.frameworks_for(db, tenant.id):
        raise HTTPException(404, "Unknown framework")
    row = db.execute(select(GrcAdoption).where(GrcAdoption.tenant_id == tenant.id, GrcAdoption.framework_key == body.frameworkKey)).scalar_one_or_none()
    if row is None:
        row = GrcAdoption(tenant_id=tenant.id, framework_key=body.frameworkKey, adopted_by=principal.actor)
        db.add(row)
    row.status, row.target_date, row.scope = "active", _naive(body.targetDate), body.scope
    created = []
    if body.createPolicies:
        for template in gp.templates_for(body.frameworkKey):
            policy = _adopt_policy(db, tenant, template["key"], body.owner, body.securityContact, principal.actor)
            if policy is not None:
                created.append(template["title"])
    audit.record(db, principal.actor, "grc.framework_adopted", body.frameworkKey, tenant.id, policiesCreated=len(created))
    db.commit()
    return {"adopted": body.frameworkKey, "policiesCreated": created}


@router.delete("/programmes/{tenant_id}/{framework_key}")
def pause(tenant_id: str, framework_key: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Stops tracking a framework; answers, evidence and policies are kept."""
    principal.require("grc")
    _tenant(db, principal, tenant_id)
    row = db.execute(select(GrcAdoption).where(GrcAdoption.tenant_id == tenant_id, GrcAdoption.framework_key == framework_key)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Not adopted")
    row.status = "paused"
    audit.record(db, principal.actor, "grc.framework_paused", framework_key, tenant_id)
    db.commit()
    return {"ok": True}


@router.get("/programmes/{tenant_id}/{framework_key}")
def programme_detail(tenant_id: str, framework_key: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    tenant = _tenant(db, principal, tenant_id)
    try:
        return gp.programme(db, tenant, framework_key)
    except KeyError:
        raise HTTPException(404, "Unknown framework")


class RequirementInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["not_started", "in_progress", "implemented", "not_applicable"] | None = None
    answer: str | None = Field(default=None, max_length=20000)
    notes: str | None = Field(default=None, max_length=20000)
    naReason: str | None = Field(default=None, max_length=5000)
    owner: str | None = Field(default=None, max_length=200)
    dueDate: datetime | None = None
    clearDueDate: bool = False


@router.patch("/programmes/{tenant_id}/{framework_key}/requirements/{requirement_id}")
def update_requirement(tenant_id: str, framework_key: str, requirement_id: str, body: RequirementInput,
                       principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    tenant = _tenant(db, principal, tenant_id)
    framework = gp.frameworks_for(db, tenant.id).get(framework_key)
    req = next((r for r in gp.requirements(framework) if r["id"] == requirement_id), None) if framework else None
    if req is None:
        raise HTTPException(404, "Unknown requirement")
    state = db.execute(select(GrcRequirementState).where(GrcRequirementState.tenant_id == tenant.id, GrcRequirementState.framework_key == framework_key,
                                                         GrcRequirementState.requirement_id == requirement_id)).scalar_one_or_none()
    if state is None:
        state = GrcRequirementState(tenant_id=tenant.id, framework_key=framework_key, requirement_id=requirement_id)
        db.add(state)
    if body.status == "not_applicable" and not (body.naReason or state.na_reason or "").strip():
        raise HTTPException(400, "Say why this requirement does not apply")
    for field, column in (("status", "status"), ("answer", "answer"), ("notes", "notes"), ("naReason", "na_reason"), ("owner", "owner")):
        value = getattr(body, field)
        if value is not None:
            setattr(state, column, value)
    if body.dueDate is not None:
        state.due_date = _naive(body.dueDate)
    if body.clearDueDate:
        state.due_date = None
    reviewed = bool(state.requirement_hash and state.requirement_hash != gp.requirement_hash(req))
    # Saving an answer confirms it against the wording shown now.
    state.requirement_hash, state.requirement_text = gp.requirement_hash(req), gp.requirement_wording(req)
    state.updated_by, state.updated_at = principal.actor, utcnow()
    audit.record(db, principal.actor, "grc.requirement_updated", f"{framework_key}:{requirement_id}", tenant.id, status=state.status,
                 reviewedRevision=reviewed)
    db.commit()
    return {"requirementId": requirement_id, "status": state.status, "answer": state.answer, "updatedAt": state.updated_at.isoformat() + "Z"}


def _snapshot_view(row: GrcAssessmentSnapshot) -> dict:
    data = row.data or {}
    return {"id": row.id, "frameworkKey": row.framework_key, "label": row.label, "reason": row.reason, "createdBy": row.created_by,
            "createdAt": row.created_at.isoformat() + "Z", "version": data.get("version", ""), "progress": data.get("progress", 0),
            "counts": data.get("counts", {}), "total": data.get("total", 0)}


@router.get("/programmes/{tenant_id}/{framework_key}/snapshots")
def list_snapshots(tenant_id: str, framework_key: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    tenant = _tenant(db, principal, tenant_id)
    rows = db.execute(select(GrcAssessmentSnapshot).where(GrcAssessmentSnapshot.tenant_id == tenant.id,
                                                          GrcAssessmentSnapshot.framework_key == framework_key)
                      .order_by(GrcAssessmentSnapshot.created_at.desc())).scalars().all()
    return [_snapshot_view(r) for r in rows]


class SnapshotInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=200)


@router.post("/programmes/{tenant_id}/{framework_key}/snapshots")
def create_snapshot(tenant_id: str, framework_key: str, body: SnapshotInput, principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    """Freeze the assessment as it stands (for example when it is submitted to the certification body)."""
    principal.require("grc")
    tenant = _tenant(db, principal, tenant_id)
    row = gp.snapshot(db, tenant, framework_key, principal.actor, "Saved by hand", label=body.label.strip())
    if row is None:
        raise HTTPException(404, "Unknown framework")
    db.flush()
    audit.record(db, principal.actor, "grc.snapshot_created", f"{framework_key}:{row.id}", tenant.id, label=row.label)
    db.commit()
    return _snapshot_view(row)


@router.get("/programmes/{tenant_id}/{framework_key}/export")
def export_answers(tenant_id: str, framework_key: str, snapshot: str | None = Query(None, max_length=32),
                   principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """CSV of every requirement with status, answer, notes, policies and evidence - for the assessor or the
    certification body's portal. With snapshot=, the assessment exactly as it was frozen."""
    principal.require("read")
    tenant = _tenant(db, principal, tenant_id)
    if snapshot:
        row = db.get(GrcAssessmentSnapshot, snapshot)
        if row is None or row.tenant_id != tenant.id or row.framework_key != framework_key:
            raise HTTPException(404, "Snapshot not found")
        view = row.data
    else:
        try:
            view = gp.programme(db, tenant, framework_key)
        except KeyError:
            raise HTTPException(404, "Unknown framework")
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Section", "ID", "Requirement", "Question", "Status", "Answer", "Not applicable because", "Notes", "Owner",
                     "Policies", "Evidence", "Automatic checks", "Answered wording (if changed since)"])
    for section in view["sections"]:
        for r in section["requirements"]:
            writer.writerow([section["title"], r["id"], r["title"], r["text"], r["status"].replace("_", " "), r["answer"], r["naReason"],
                             r["notes"], r["owner"], "; ".join(f"{p['title']} ({p['status']})" for p in r["policies"]),
                             "; ".join(e["title"] for e in r["evidence"]),
                             "; ".join(f"{c['title']}: {'pass' if c['passed'] else 'fail'}" for c in r["checks"]),
                             r.get("previousWording") or ""])
    audit.record(db, principal.actor, "grc.exported", framework_key, tenant.id, snapshot=snapshot)
    db.commit()
    stamp = f"snapshot-{snapshot}" if snapshot else f"{utcnow():%Y%m%d}"
    name = f"{tenant.slug or tenant.id}-{framework_key}-{stamp}.csv"
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}"'})


# --- policies ------------------------------------------------------------------------------------------------------

def _policy_view(db: Session, policy: GrcPolicy, full: bool = False) -> dict:
    data = to_dict(policy)
    if not full:
        data.pop("body", None)
    data["mapsTo"] = gp.policy_maps(policy)
    data["reviewOverdue"] = bool(policy.review_due and policy.review_due < utcnow() and policy.status == "approved")
    if full:
        data["versions"] = [to_dict(v) for v in db.execute(select(GrcPolicyVersion).where(GrcPolicyVersion.policy_id == policy.id)
                                                            .order_by(GrcPolicyVersion.version.desc())).scalars()]
    return data


def _owned_policy(db: Session, principal: Principal, policy_id: str) -> GrcPolicy:
    policy = db.get(GrcPolicy, policy_id)
    if policy is None or policy.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Policy not found")
    return policy


@router.get("/policies")
def list_policies(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    rows = db.execute(select(GrcPolicy).where(GrcPolicy.tenant_id.in_(scoped_tenant(principal, tenant_id))).order_by(GrcPolicy.title)).scalars()
    return [_policy_view(db, p) for p in rows]


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    templateKey: str | None = None
    title: str = Field(default="", max_length=300)
    body: str = Field(default="", max_length=500_000)
    owner: str = Field(default="", max_length=200)
    securityContact: str = Field(default="", max_length=200)


@router.post("/policies")
def create_policy(body: PolicyCreate, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    tenant = _tenant(db, principal, body.tenantId)
    if body.templateKey:
        if body.templateKey not in gp.policy_templates():
            raise HTTPException(404, "Unknown template")
        policy = _adopt_policy(db, tenant, body.templateKey, body.owner, body.securityContact, principal.actor)
        if policy is None:
            raise HTTPException(409, "This customer already has that policy")
    else:
        if not body.title.strip():
            raise HTTPException(400, "A title is needed")
        policy = GrcPolicy(tenant_id=tenant.id, title=body.title.strip(), body=body.body, owner=body.owner, updated_by=principal.actor)
        db.add(policy)
    db.flush()
    audit.record(db, principal.actor, "grc.policy_created", policy.title, tenant.id, template=body.templateKey)
    db.commit()
    return _policy_view(db, policy, full=True)


@router.get("/policies/{policy_id}")
def get_policy(policy_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return _policy_view(db, _owned_policy(db, principal, policy_id), full=True)


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, max_length=300)
    body: str | None = Field(default=None, max_length=500_000)
    summary: str | None = Field(default=None, max_length=5000)
    owner: str | None = Field(default=None, max_length=200)
    reviewDue: datetime | None = None
    maps: dict[str, list[str]] | None = None


@router.patch("/policies/{policy_id}")
def update_policy(policy_id: str, body: PolicyUpdate, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Editing an approved policy starts a new draft version; the approved version stays published until the new
    one is approved."""
    principal.require("grc")
    policy = _owned_policy(db, principal, policy_id)
    content_change = (body.title is not None and body.title != policy.title) or (body.body is not None and body.body != policy.body)
    if content_change and policy.status in ("approved", "in_review"):
        if policy.status == "approved":
            policy.version += 1
        policy.status = "draft"
    for field, column in (("title", "title"), ("body", "body"), ("summary", "summary"), ("owner", "owner")):
        value = getattr(body, field)
        if value is not None:
            setattr(policy, column, value)
    if body.reviewDue is not None:
        policy.review_due = _naive(body.reviewDue)
    if body.maps is not None:
        policy.maps = {k: [str(i)[:80] for i in v][:500] for k, v in body.maps.items() if gp.KEY_RE.match(k)}
    policy.updated_by, policy.updated_at = principal.actor, utcnow()
    audit.record(db, principal.actor, "grc.policy_edited", policy.title, policy.tenant_id, version=policy.version)
    db.commit()
    return _policy_view(db, policy, full=True)


class PolicyAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["submit", "approve", "reject", "retire", "restore"]
    note: str = Field(default="", max_length=5000)
    reviewMonths: int = Field(default=12, ge=1, le=36)


@router.post("/policies/{policy_id}/workflow")
def policy_workflow(policy_id: str, body: PolicyAction, request: Request, principal: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    """draft -> submit -> in_review -> approve (published as a new version) or reject (back to draft)."""
    principal.require("grc")
    policy = _owned_policy(db, principal, policy_id)
    if body.action == "submit":
        if policy.status != "draft":
            raise HTTPException(409, "Only a draft can be submitted for review")
        policy.status = "in_review"
    elif body.action == "approve":
        require_reauth(request, principal)
        if policy.status not in ("draft", "in_review"):
            raise HTTPException(409, "This version is already approved or retired")
        if not policy.body.strip():
            raise HTTPException(400, "An empty policy cannot be approved")
        policy.status, policy.approved_version = "approved", policy.version
        policy.approved_by, policy.approved_at = principal.actor, utcnow()
        policy.review_due = gp.policy_review_due(body.reviewMonths)
        db.add(GrcPolicyVersion(policy_id=policy.id, tenant_id=policy.tenant_id, version=policy.version, title=policy.title,
                                body=policy.body, approved_by=principal.actor, note=body.note))
    elif body.action == "reject":
        if policy.status != "in_review":
            raise HTTPException(409, "Only a policy in review can be sent back")
        policy.status = "draft"
    elif body.action == "retire":
        policy.status = "retired"
    elif body.action == "restore":
        if policy.status != "retired":
            raise HTTPException(409, "Only a retired policy can be restored")
        policy.status = "draft"
    policy.updated_by, policy.updated_at = principal.actor, utcnow()
    audit.record(db, principal.actor, f"grc.policy_{body.action}", policy.title, policy.tenant_id, version=policy.version, note=body.note[:200])
    db.commit()
    return _policy_view(db, policy, full=True)


@router.get("/policies/{policy_id}/download")
def download_policy(policy_id: str, version: int | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The policy as Markdown: the approved version by default, or a specific published version."""
    principal.require("read")
    policy = _owned_policy(db, principal, policy_id)
    title, text = policy.title, policy.body
    wanted = version or (policy.approved_version if policy.status != "approved" else None)
    if wanted:
        row = db.execute(select(GrcPolicyVersion).where(GrcPolicyVersion.policy_id == policy.id, GrcPolicyVersion.version == wanted)).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "No such published version")
        title, text = row.title, row.body
    name = SAFE_NAME.sub("", title).strip().replace(" ", "-") or "policy"
    return Response(text, media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}.md"'})


# --- evidence ------------------------------------------------------------------------------------------------------

def _evidence_dir():
    path = get_settings().artifact_dir / "grc-evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _aad(row: GrcEvidence) -> str:
    return f"grc-evidence:{row.tenant_id}:{row.id}"


def _link(db: Session, row: GrcEvidence, links: list[str], framework_keys: set[str]) -> None:
    for ref in links:
        framework_key, _, requirement_id = ref.partition(":")
        if not requirement_id or framework_key not in framework_keys:
            raise HTTPException(400, f"Link {ref!r} must be framework:requirement")
        if not db.execute(select(GrcEvidenceLink.id).where(GrcEvidenceLink.evidence_id == row.id, GrcEvidenceLink.framework_key == framework_key,
                                                           GrcEvidenceLink.requirement_id == requirement_id)).first():
            db.add(GrcEvidenceLink(evidence_id=row.id, tenant_id=row.tenant_id, framework_key=framework_key, requirement_id=requirement_id[:80]))


def _evidence_view(db: Session, row: GrcEvidence) -> dict:
    data = to_dict(row, exclude={"storage_name"})
    data["links"] = [f"{l.framework_key}:{l.requirement_id}" for l in db.execute(select(GrcEvidenceLink).where(GrcEvidenceLink.evidence_id == row.id)).scalars()]
    data["expired"] = bool(row.valid_until and row.valid_until < utcnow())
    return data


@router.get("/evidence")
def list_evidence(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    rows = db.execute(select(GrcEvidence).where(GrcEvidence.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(GrcEvidence.created_at.desc()).limit(2000)).scalars()
    return [_evidence_view(db, r) for r in rows]


class EvidenceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str
    title: str = Field(min_length=1, max_length=300)
    kind: Literal["link", "note"]
    url: str = Field(default="", max_length=2000)
    description: str = Field(default="", max_length=20000)
    validUntil: datetime | None = None
    links: list[str] = Field(default_factory=list, max_length=200)


@router.post("/evidence")
def add_evidence(body: EvidenceInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A link (to a document, report or system screen) or a written note."""
    principal.require("grc")
    tenant = _tenant(db, principal, body.tenantId)
    if body.kind == "link" and not body.url.startswith("https://"):
        raise HTTPException(400, "Links must use https://")
    if body.kind == "note" and not body.description.strip():
        raise HTTPException(400, "Write the note")
    row = GrcEvidence(tenant_id=tenant.id, title=body.title, kind=body.kind, url=body.url, description=body.description,
                      valid_until=_naive(body.validUntil), uploaded_by=principal.actor)
    db.add(row)
    db.flush()
    _link(db, row, body.links, set(gp.frameworks_for(db, tenant.id)))
    audit.record(db, principal.actor, "grc.evidence_added", row.title, tenant.id, kind=row.kind)
    db.commit()
    return _evidence_view(db, row)


@router.post("/evidence/upload")
async def upload_evidence(request: Request, tenant_id: str = Query(...), title: str = Query("", max_length=300),
                          filename: str = Query(..., max_length=255), description: str = Query("", max_length=5000),
                          valid_until: datetime | None = None, links: str = Query("", max_length=20000),
                          principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The file is the request body (any type, up to 25 MB). Stored encrypted; links are comma-separated
    framework:requirement pairs."""
    principal.require("grc")
    tenant = _tenant(db, principal, tenant_id)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_EVIDENCE_BYTES:
        raise HTTPException(413, "Evidence files are limited to 25 MB")
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > MAX_EVIDENCE_BYTES:
            raise HTTPException(413, "Evidence files are limited to 25 MB")
    if not data:
        raise HTTPException(400, "Empty file")
    clean = SAFE_NAME.sub("_", os.path.basename(filename)).strip("._ ") or "evidence.bin"
    row = GrcEvidence(tenant_id=tenant.id, title=title.strip() or clean, kind="file", filename=clean[:255],
                      content_type=(request.headers.get("content-type") or "application/octet-stream")[:120], size=len(data),
                      sha256=hashlib.sha256(data).hexdigest(), storage_name=secrets.token_hex(16), description=description,
                      valid_until=_naive(valid_until), uploaded_by=principal.actor)
    db.add(row)
    db.flush()
    path = _evidence_dir() / row.storage_name
    with open(path, "w", encoding="utf-8") as out:
        os.chmod(path, 0o600)
        json.dump(crypto.encrypt(bytes(data), _aad(row)), out)
    _link(db, row, [l.strip() for l in links.split(",") if l.strip()], set(gp.frameworks_for(db, tenant.id)))
    audit.record(db, principal.actor, "grc.evidence_uploaded", row.filename, tenant.id, size=row.size, sha256=row.sha256)
    db.commit()
    return _evidence_view(db, row)


class LinkInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    add: list[str] = Field(default_factory=list, max_length=200)
    remove: list[str] = Field(default_factory=list, max_length=200)
    validUntil: datetime | None = None
    clearValidUntil: bool = False


@router.patch("/evidence/{evidence_id}")
def relink_evidence(evidence_id: str, body: LinkInput, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    row = db.get(GrcEvidence, evidence_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    _link(db, row, body.add, set(gp.frameworks_for(db, row.tenant_id)))
    for ref in body.remove:
        framework_key, _, requirement_id = ref.partition(":")
        db.execute(delete(GrcEvidenceLink).where(GrcEvidenceLink.evidence_id == row.id, GrcEvidenceLink.framework_key == framework_key,
                                                 GrcEvidenceLink.requirement_id == requirement_id))
    if body.validUntil is not None:
        row.valid_until = _naive(body.validUntil)
    if body.clearValidUntil:
        row.valid_until = None
    db.commit()
    return _evidence_view(db, row)


@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    row = db.get(GrcEvidence, evidence_id)
    if row is None or row.tenant_id not in principal.tenant_ids or row.kind != "file":
        raise HTTPException(404, "Not found")
    path = _evidence_dir() / row.storage_name
    if not path.is_file():
        raise HTTPException(410, "The file is no longer stored")
    content = crypto.decrypt_bytes(json.loads(path.read_text(encoding="utf-8")), _aad(row))
    audit.record(db, principal.actor, "grc.evidence_downloaded", row.filename, row.tenant_id)
    db.commit()
    return Response(content, media_type=row.content_type or "application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{row.filename}"', "Cache-Control": "private, no-store",
                             "X-Content-Type-Options": "nosniff"})


@router.delete("/evidence/{evidence_id}")
def delete_evidence(evidence_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("grc")
    row = db.get(GrcEvidence, evidence_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    if row.storage_name:
        (_evidence_dir() / row.storage_name).unlink(missing_ok=True)
    db.execute(delete(GrcEvidenceLink).where(GrcEvidenceLink.evidence_id == row.id))
    audit.record(db, principal.actor, "grc.evidence_deleted", row.title, row.tenant_id)
    db.delete(row)
    db.commit()
    return {"ok": True}
