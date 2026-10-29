"""GRC programmes per customer: frameworks (built-in library or imported question sets), requirements with status,
answers and evidence, and policies adopted from templates that map onto those requirements.

Built-in content lives in grc_library/*.yml. A customer (or the whole platform) can import a framework; one whose
key matches a built-in framework replaces it, which is how an MSP loads the exact official Cyber Essentials booklet.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import timedelta
from functools import lru_cache
from pathlib import Path

import yaml
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .grccatalogue import CATALOGUE, retired_framework
from .models import (GrcAdoption, GrcAssessmentSnapshot, GrcEvidence, GrcEvidenceLink, GrcFramework, GrcPolicy, GrcRequirementState,
                     Tenant, utcnow)

LIBRARY = Path(__file__).parent / "grc_library"
STATUSES = ("not_started", "in_progress", "implemented", "not_applicable")
ANSWER_TYPES = ("control", "yesno", "text")
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,78}$")
CATALOGUE_FIELDS = ("owner", "assessmentStyle", "targetScope", "jurisdiction", "sourceUrl")


def _requirement(raw, section_id: str) -> dict:
    if isinstance(raw, (list, tuple)):
        raw = {"id": raw[0], "title": raw[1], "text": raw[2] if len(raw) > 2 else "",
               "evidence": raw[3] if len(raw) > 3 else [], "auto": raw[4] if len(raw) > 4 else []}
    return {"id": str(raw["id"]).strip(), "section": section_id, "title": str(raw.get("title") or raw["id"]).strip(),
            "text": str(raw.get("text") or "").strip(), "guidance": str(raw.get("guidance") or "").strip(),
            "type": raw.get("type") if raw.get("type") in ANSWER_TYPES else "control",
            "evidence": [str(e) for e in raw.get("evidence") or []], "auto": [str(a) for a in raw.get("auto") or []],
            "reviewIfUnversioned": bool(raw.get("reviewIfUnversioned")), "legacyWording": str(raw.get("legacyWording") or "")}


def _normalise(doc: dict, source: str) -> dict:
    sections = []
    for section in doc.get("sections") or []:
        sid = str(section.get("id") or len(sections) + 1)
        sections.append({"id": sid, "title": str(section.get("title") or sid),
                         "requirements": [_requirement(r, sid) for r in section.get("requirements") or []]})
    metadata = CATALOGUE.get(doc["key"], {})
    return {**{k: metadata.get(k, "") for k in CATALOGUE_FIELDS},
            "currentVersion": metadata.get("version", ""), "retired": retired_framework(doc["key"], doc.get("name", "")),
            "key": doc["key"], "name": doc.get("name") or doc["key"], "short": doc.get("short") or doc.get("name") or doc["key"],
            "version": str(doc.get("version") or ""), "description": str(doc.get("description") or "").strip(),
            "questionSet": bool(doc.get("questionSet") or doc.get("question_set")), "sections": sections, "source": source}


@lru_cache(maxsize=2)
def builtin_frameworks(include_retired: bool = False) -> dict[str, dict]:
    out = {}
    for path in sorted(LIBRARY.glob("*.yml")):
        if path.name in ("policies.yml", "crosswalk.yml"):  # templates and the control map, not frameworks
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not include_retired and retired_framework(doc["key"], doc.get("name", "")):
            continue
        # Catalogue names are consistent across the risk register and adoption picker.
        if doc["key"] in CATALOGUE:
            doc["name"] = CATALOGUE[doc["key"]]["name"]
        out[doc["key"]] = _normalise(doc, "built-in")
    return out


@lru_cache(maxsize=1)
def policy_templates() -> dict[str, dict]:
    out = {}
    for template in yaml.safe_load((LIBRARY / "policies.yml").read_text(encoding="utf-8")):
        template["maps"] = {k: ids for k, ids in template["maps"].items() if not retired_framework(k)}
        out[template["key"]] = template
    return out


def frameworks_for(db: Session, tenant_id: str | None, include_retired: bool = False) -> dict[str, dict]:
    """Built-in frameworks, overridden by global imports, overridden by this customer's imports."""
    result = dict(builtin_frameworks(include_retired=include_retired))
    rows = db.execute(select(GrcFramework).where(or_(GrcFramework.tenant_id.is_(None), GrcFramework.tenant_id == tenant_id))
                      .order_by(GrcFramework.tenant_id.is_(None).desc())).scalars().all()
    for row in rows:  # global first, then tenant, so the tenant's wins
        if not include_retired and retired_framework(row.key, row.name):
            # An imported retired framework must not reappear under a different key.
            result.pop(row.key, None)
            continue
        result[row.key] = _normalise({"key": row.key, "name": row.name, "short": row.short, "version": row.version,
                                      "description": row.description, "questionSet": row.question_set, "sections": row.sections},
                                     "imported" if row.tenant_id else "imported (all customers)") | {"importedId": row.id}
    return result


def requirements(framework: dict) -> list[dict]:
    return [r for s in framework["sections"] for r in s["requirements"]]


# --- revisions (FIX-08) --------------------------------------------------------------------------------------------
# A requirement is identified by its id, but its meaning is its wording. Every answer records a hash of the wording it
# answered; when a framework revision changes that wording, an "implemented" or "not applicable" answer no longer
# counts as done until someone reviews it against the new text.

def requirement_hash(req: dict) -> str:
    return hashlib.sha256(json.dumps([req["title"], req["text"], req["type"]], ensure_ascii=False).encode()).hexdigest()


def requirement_wording(req: dict) -> str:
    return f"{req['title']}\n\n{req['text']}".strip()


def diff_frameworks(old: dict | None, new: dict) -> dict:
    before = {r["id"]: r for r in requirements(old)} if old else {}
    after = {r["id"]: r for r in requirements(new)}
    changed = [rid for rid in after if rid in before and requirement_hash(before[rid]) != requirement_hash(after[rid])]
    return {"added": [rid for rid in after if rid not in before], "removed": [rid for rid in before if rid not in after],
            "changed": changed, "unchanged": sum(1 for rid in after if rid in before and rid not in changed),
            "changedDetail": [{"id": rid, "before": requirement_wording(before[rid]), "after": requirement_wording(after[rid])} for rid in changed[:200]]}


def tenants_using(db: Session, framework_key: str, import_tenant_id: str | None) -> list[Tenant]:
    """Customers whose effective definition of framework_key changes when the import at this scope changes:
    the one customer for a customer import; for an all-customer import, those without their own import of it."""
    ids = set(db.execute(select(GrcRequirementState.tenant_id).where(GrcRequirementState.framework_key == framework_key)).scalars())
    ids |= set(db.execute(select(GrcAdoption.tenant_id).where(GrcAdoption.framework_key == framework_key)).scalars())
    if import_tenant_id is not None:
        ids &= {import_tenant_id}
    else:
        ids -= set(db.execute(select(GrcFramework.tenant_id).where(GrcFramework.key == framework_key, GrcFramework.tenant_id.is_not(None))).scalars())
    return [t for t in (db.get(Tenant, i) for i in sorted(ids)) if t is not None]


def snapshot(db: Session, tenant: Tenant, framework_key: str, actor: str, reason: str, label: str = "") -> GrcAssessmentSnapshot | None:
    try:
        view = programme(db, tenant, framework_key)
    except KeyError:
        return None
    row = GrcAssessmentSnapshot(tenant_id=tenant.id, framework_key=framework_key, label=label or f"{view['name']} {view['version']}".strip(),
                                reason=reason, data=json.loads(json.dumps(view, default=str)), created_by=actor)
    db.add(row)
    return row


def freeze_before_change(db: Session, framework_key: str, import_tenant_id: str | None, actor: str, reason: str) -> int:
    """Before a framework definition changes: snapshot each affected customer's assessment, and record on every answer
    which wording it answered (answers given before FIX-08 have none), so a changed requirement is flagged."""
    affected = tenants_using(db, framework_key, import_tenant_id)
    for tenant in affected:
        current = frameworks_for(db, tenant.id).get(framework_key)
        if current is None:
            continue
        snapshot(db, tenant, framework_key, actor, reason)
        by_id = {r["id"]: r for r in requirements(current)}
        for state in db.execute(select(GrcRequirementState).where(GrcRequirementState.tenant_id == tenant.id,
                                                                  GrcRequirementState.framework_key == framework_key,
                                                                  GrcRequirementState.requirement_hash.is_(None))).scalars():
            req = by_id.get(state.requirement_id)
            if req is not None:
                state.requirement_hash, state.requirement_text = requirement_hash(req), requirement_wording(req)
    db.flush()
    return len(affected)


# --- import ------------------------------------------------------------------------------------------------------

def parse_import(text: str, fmt: str) -> dict:
    """JSON/YAML (the library format) or CSV with columns section,id,title,text[,type,guidance,evidence]."""
    if fmt == "csv":
        reader = csv.DictReader(io.StringIO(text))
        fields = {f.strip().lower() for f in reader.fieldnames or []}
        if not {"id", "title"} <= fields:
            raise ValueError("CSV needs at least the columns id and title (and usually section, text, type)")
        sections: dict[str, dict] = {}
        for row in reader:
            row = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
            if not row.get("id"):
                continue
            sid = row.get("section") or "1"
            section = sections.setdefault(sid, {"id": sid.split(" ")[0], "title": sid, "requirements": []})
            section["requirements"].append({"id": row["id"], "title": row["title"], "text": row.get("text") or row.get("question") or "",
                                            "type": (row.get("type") or "control").lower(), "guidance": row.get("guidance", ""),
                                            "evidence": [e.strip() for e in (row.get("evidence") or "").split(";") if e.strip()]})
        doc = {"sections": list(sections.values())}
    else:
        doc = yaml.safe_load(text)  # YAML is a superset of JSON
        if not isinstance(doc, dict):
            raise ValueError("Expected an object with key, name and sections")
    sections = doc.get("sections") or []
    total = sum(len(s.get("requirements") or []) for s in sections if isinstance(s, dict))
    if not total:
        raise ValueError("No requirements found")
    if total > 2000:
        raise ValueError("At most 2000 requirements per framework")
    seen = set()
    for section in sections:
        for raw in section.get("requirements") or []:
            rid = str((raw[0] if isinstance(raw, (list, tuple)) else raw.get("id")) or "").strip()
            if not rid or len(rid) > 80:
                raise ValueError(f"Every requirement needs an id of up to 80 characters (got {rid!r})")
            if rid in seen:
                raise ValueError(f"Duplicate requirement id {rid}")
            seen.add(rid)
    return doc


# --- policies ----------------------------------------------------------------------------------------------------

def render_template(template: dict, tenant: Tenant, owner: str, security_contact: str, review_months: int) -> str:
    values = {"organisation": tenant.name, "owner": owner or "the Information Security Lead",
              "securityContact": security_contact or "the IT service desk", "reviewMonths": str(review_months),
              "effectiveDate": utcnow().strftime("%d %B %Y")}
    return re.sub(r"\{\{(\w+)\}\}", lambda m: values.get(m.group(1), m.group(0)), template["body"])


def policy_maps(policy: GrcPolicy) -> dict[str, list[str]]:
    base = (policy_templates().get(policy.template_key or "") or {}).get("maps") or {}
    extra = policy.maps or {}
    return {k: sorted(set(base.get(k, [])) | set(extra.get(k, []))) for k in set(base) | set(extra)
            if not retired_framework(k)}


def templates_for(framework_key: str) -> list[dict]:
    return [t for t in policy_templates().values() if t["maps"].get(framework_key)]


# --- programme view ------------------------------------------------------------------------------------------------

def _auto_results(db: Session, tenant: Tenant) -> dict[str, dict]:
    from . import compliance

    out = {}
    for framework in compliance.evaluate(db, tenant):
        for control in framework["controls"]:
            out[f"{framework['framework']}/{control['id']}"] = {"passed": control["passed"], "title": control["title"],
                                                                "evidence": control["evidence"]}
    return out


def programme(db: Session, tenant: Tenant, framework_key: str, include_requirements: bool = True) -> dict:
    # Retired definitions remain readable for old answers, snapshots and exports.
    framework = frameworks_for(db, tenant.id, include_retired=True).get(framework_key)
    if framework is None:
        raise KeyError(framework_key)
    states = {s.requirement_id: s for s in db.execute(select(GrcRequirementState).where(
        GrcRequirementState.tenant_id == tenant.id, GrcRequirementState.framework_key == framework_key)).scalars()}
    policies = db.execute(select(GrcPolicy).where(GrcPolicy.tenant_id == tenant.id, GrcPolicy.status != "retired")).scalars().all()
    by_requirement: dict[str, list[GrcPolicy]] = {}
    for policy in policies:
        for rid in policy_maps(policy).get(framework_key, []):
            by_requirement.setdefault(rid, []).append(policy)
    template_by_requirement: dict[str, list[dict]] = {}
    for template in templates_for(framework_key):
        for rid in template["maps"][framework_key]:
            template_by_requirement.setdefault(rid, []).append(template)
    links = db.execute(select(GrcEvidenceLink, GrcEvidence).join(GrcEvidence, GrcEvidence.id == GrcEvidenceLink.evidence_id)
                       .where(GrcEvidenceLink.tenant_id == tenant.id, GrcEvidenceLink.framework_key == framework_key)).all()
    evidence: dict[str, list[GrcEvidence]] = {}
    for link, item in links:
        evidence.setdefault(link.requirement_id, []).append(item)
    auto = _auto_results(db, tenant) if any(r["auto"] for r in requirements(framework)) else {}
    now = utcnow()
    counts = {s: 0 for s in STATUSES} | {"needs_review": 0}
    signals = {"withEvidence": 0, "withApprovedPolicy": 0, "autoPassing": 0, "answered": 0, "overdue": 0}
    sections_out = []
    for section in framework["sections"]:
        rows = []
        for req in section["requirements"]:
            state = states.get(req["id"])
            recorded = state.status if state else "not_started"
            wording_changed = bool(state and ((state.requirement_hash and state.requirement_hash != requirement_hash(req))
                                               or (not state.requirement_hash and req["reviewIfUnversioned"])))
            needs_review = wording_changed and (recorded in ("implemented", "not_applicable") or bool(state.answer.strip()))
            # An approval of different wording is not an approval of this wording.
            status = "needs_review" if needs_review and recorded in ("implemented", "not_applicable") else recorded
            counts[status] += 1
            pols = by_requirement.get(req["id"], [])
            valid_evidence = [e for e in evidence.get(req["id"], []) if not e.valid_until or e.valid_until >= now]
            checks = [{"ref": ref, **auto[ref]} for ref in req["auto"] if ref in auto]
            approved = bool(pols) and all(p.status == "approved" for p in pols)
            answered = bool(state and state.answer.strip())
            signals["withEvidence"] += bool(valid_evidence)
            signals["withApprovedPolicy"] += approved
            signals["autoPassing"] += bool(checks) and all(c["passed"] for c in checks)
            signals["answered"] += answered
            due = state.due_date if state else None
            signals["overdue"] += bool(due and due < now and status not in ("implemented", "not_applicable"))
            if include_requirements:
                rows.append({**req, "evidenceHints": req["evidence"], "status": status, "recordedStatus": recorded,
                             "needsReview": needs_review, "previousWording": (state.requirement_text or req["legacyWording"]) if needs_review else None, "answer": state.answer if state else "", "notes": state.notes if state else "",
                             "naReason": state.na_reason if state else "", "owner": state.owner if state else "",
                             "dueDate": due.isoformat() + "Z" if due else None,
                             "updatedAt": state.updated_at.isoformat() + "Z" if state else None,
                             "updatedBy": state.updated_by if state else "",
                             "policies": [{"id": p.id, "title": p.title, "status": p.status, "version": p.approved_version or p.version} for p in pols],
                             "suggestedPolicies": [{"key": t["key"], "title": t["title"]} for t in template_by_requirement.get(req["id"], [])
                                                   if not any(p.template_key == t["key"] for p in pols)],
                             "evidence": [{"id": e.id, "title": e.title, "kind": e.kind, "filename": e.filename, "url": e.url,
                                           "validUntil": e.valid_until.isoformat() + "Z" if e.valid_until else None,
                                           "expired": bool(e.valid_until and e.valid_until < now),
                                           "createdAt": e.created_at.isoformat() + "Z"} for e in evidence.get(req["id"], [])],
                             "checks": checks})
        if include_requirements:
            sections_out.append({"id": section["id"], "title": section["title"], "requirements": rows})
    total = sum(counts.values())
    done = counts["implemented"] + counts["not_applicable"]
    adoption = db.execute(select(GrcAdoption).where(GrcAdoption.tenant_id == tenant.id, GrcAdoption.framework_key == framework_key)).scalar_one_or_none()
    out = {**{k: framework.get(k, "") for k in (*CATALOGUE_FIELDS, "currentVersion")}, "retired": framework["retired"],
           "key": framework["key"], "name": framework["name"], "short": framework["short"], "version": framework["version"],
           "description": framework["description"], "questionSet": framework["questionSet"], "source": framework["source"],
           "total": total, "counts": counts, "progress": round(100 * done / total) if total else 0, "signals": signals,
           "adopted": adoption is not None and adoption.status == "active",
           "targetDate": adoption.target_date.isoformat() + "Z" if adoption and adoption.target_date else None,
           "scope": adoption.scope if adoption else ""}
    if include_requirements:
        out["sections"] = sections_out
    return out


def policy_review_due(months: int):
    return utcnow() + timedelta(days=round(30.4 * months))
