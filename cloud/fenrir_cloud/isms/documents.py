"""ISMS documents: generated from templates and live data, approved, published and acknowledged.

Lifecycle: draft -> in review -> approved -> published -> superseded or withdrawn. A version's content is frozen once
it leaves draft (``models._guard_versions``); regenerating always makes a new draft and never touches an approved or
published version. Every document reads its data through ``build_context``, so the context hash shows when a
document is out of date. Files are stored encrypted under the artifact directory. Every change is audited.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from datetime import date
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto
from ..config import get_settings
from ..models import Tenant, User, utcnow
from . import docgen, docwriter, library, organization, programme, risk_register
from .domain.risk import next_review_date
from .models import (IsmsApplicability, IsmsAsset, IsmsDocument, IsmsDocumentOverride, IsmsDocumentVersion,
                     IsmsMembership, IsmsProfileAnswer)

STATE_LABEL = {"draft": "Draft", "in_review": "In review", "approved": "Approved", "published": "Published",
               "superseded": "Superseded", "withdrawn": "Withdrawn"}
STATUS_TEXT = {"not_started": "Not started", "in_progress": "In progress", "implemented": "Implemented",
               "implemented_evidenced": "Implemented and evidenced", "not_applicable": "Not applicable"}
ACTION_NEEDS = {"submit": "draft", "return": "in_review", "approve": "in_review", "publish": "approved",
                "withdraw": "published"}
ACTION_PERMISSION = {"submit": "documents.edit", "return": "documents.approve", "approve": "documents.approve",
                     "publish": "documents.approve", "withdraw": "documents.approve"}
FRAMEWORK_LABEL = {"iso27001": "ISO/IEC 27001"}


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def uk_date(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        value = date.fromisoformat(value[:10])
    if hasattr(value, "hour"):
        value = value.replace(tzinfo=ZoneInfo("UTC")).astimezone(ZoneInfo("Europe/London")).date()
    return value.strftime("%d/%m/%Y")


def _cap(s: str | None) -> str:
    return s[:1].upper() + s[1:] if s else ""


# Templates ------------------------------------------------------------------------------------------------------

def templates(db: Session) -> list[dict]:
    """Templates of the newest templates pack."""
    pack = library.latest(db, "templates")
    if pack is None:
        return []
    out = []
    for t in pack.data["templates"]:
        meta = t["meta"]
        out.append({"ref": f"templates@{pack.pack_version}:{meta['doc_type']}", "docType": meta["doc_type"],
                    "title": meta["title"], "body": t["body"], "code": meta.get("code"),
                    "reviewMonths": int(meta.get("review_months") or 12),
                    "classification": meta.get("classification") or "Internal",
                    "satisfies": meta.get("satisfies") or []})
    return sorted(out, key=lambda t: t["title"])


def template(db: Session, doc_type: str) -> dict:
    t = next((t for t in templates(db) if t["docType"] == doc_type), None)
    if t is None:
        raise _error("There is no template for that document.", 404)
    return t


# Context --------------------------------------------------------------------------------------------------------

def build_context(db: Session, tenant_id: str) -> dict:
    """All data a document can use. Templates pick from it with placeholders."""
    tenant = db.get(Tenant, tenant_id)
    answers = {a.question_ref: a.value for a in db.execute(select(IsmsProfileAnswer).where(
        IsmsProfileAnswer.tenant_id == tenant_id)).scalars()}
    members = db.execute(select(User, IsmsMembership.role).join(IsmsMembership, IsmsMembership.user_id == User.id)
                         .where(IsmsMembership.tenant_id == tenant_id).order_by(User.name, User.email)).all()

    def names(role: str) -> str:
        return ", ".join((u.name or u.email) for u, r in members if r == role)

    scope = organization.get_scope(db, tenant_id)
    method, version = risk_register.get_method(db, tenant_id)
    owners = {u.id: (u.name or u.email) for u, _ in members}
    controls = [c for c in programme.control_rows(db, tenant_id) if c["state"] != "not_applicable"]

    def control_view(c: dict) -> dict:
        return {"ref": c["ref"], "title": c["title"], "statement": c["statement"],
                "owner": owners.get(c["ownerId"] or "", "Unassigned"), "status": STATUS_TEXT.get(c["state"], c["state"]),
                "implementation": c["implementation"] or ""}

    risks = [r for r in risk_register.risk_views(db, tenant_id) if r["status"] != "closed"]
    certifiable = [f for f in programme.framework_options(db, tenant_id) if f["selected"] and f["certifiable"]]
    soa = programme.soa_rows(db, tenant_id, certifiable[0]["framework"]) if certifiable else []
    suppliers = list(db.execute(select(IsmsAsset).where(IsmsAsset.tenant_id == tenant_id,
                                                        IsmsAsset.type == "supplier").order_by(IsmsAsset.name)).scalars())
    published = []
    for d, v in db.execute(select(IsmsDocument, IsmsDocumentVersion).join(
            IsmsDocumentVersion, IsmsDocumentVersion.document_id == IsmsDocument.id).where(
            IsmsDocument.tenant_id == tenant_id, IsmsDocumentVersion.state == "published",
            IsmsDocument.doc_type != "document-control-procedure").order_by(IsmsDocument.number)).all():
        published.append({"number": d.number, "title": d.title, "version": v.version,
                          "published": uk_date(v.published_at) if v.published_at else "",
                          "next_review": uk_date(d.next_review) if d.next_review else "Not set",
                          "owner": owners.get(d.owner_user_id or "", d.owner_name or "Unassigned"),
                          "classification": d.classification})
    legal = tenant.name
    return {
        "organization": {"legal_name": legal, "short_name": re.sub(r"\s+(Ltd|Limited|plc|LLP)\.?$", "", legal, flags=re.I),
                         "sector": str(answers.get("profile.sector") or ""),
                         "headcount_band": str(answers.get("profile.headcount_band") or ""),
                         "services": str(answers.get("profile.services") or "")},
        "scope": {"statement": (scope.statement if scope else "") or "The scope has not been written yet.",
                  "boundaries": scope.boundaries if scope else "", "interfaces": scope.interfaces if scope else "",
                  "exclusions": scope.exclusions if scope else "", "version": scope.version if scope else 0},
        "roles": {"top_management": names("tenant_admin") or "Top management",
                  "isms_manager": names("isms_manager") or names("tenant_admin") or "The ISMS manager",
                  "approvers": names("approver")},
        "risk": {"appetite": method.appetite, "acceptance_criteria": method.acceptance_criteria,
                 "review_months": method.review_months, "method_version": version or "default",
                 "likelihood_scale": [{"value": p.value, "label": p.label, "description": p.description}
                                      for p in method.likelihood_scale],
                 "impact_scale": [{"value": p.value, "label": p.label, "description": p.description}
                                  for p in method.impact_scale],
                 "levels": [{"min": lv.min, "level": lv.level, "label": lv.label} for lv in method.levels]},
        "controls": [control_view(c) for c in controls],
        "c": {c["ref"].replace("-", "_"): control_view(c) for c in controls},
        "risks": [{"ref": r["ref"], "title": r["title"], "owner": r["ownerName"] or "Unassigned",
                   "inherent": f"{r['inherentScore']} {r['inherentLevel']}" if r["inherentScore"] else "Not rated",
                   "treatment": _cap(r["treatment"]) or "Not decided", "treatment_plan": r["treatmentPlan"] or "",
                   "controls": ", ".join(c["ref"] for c in r["controls"]),
                   "residual": f"{r['residualScore']} {r['residualLevel']}" if r["residualScore"] else "Not rated",
                   "accepted": f"Yes, by {r['acceptance']['acceptedBy']}" if r["acceptance"] else "No"} for r in risks],
        "soa": [{"ref": s["ref"], "title": s["title"], "applicable": "Yes" if s["applicable"] else "No",
                 "reason": s["justification"] or s["reason"],
                 "implementation": "; ".join(f"{c['ref']}: {c['implementation']}" if c["implementation"] else c["ref"]
                                             for c in s["controls"]),
                 "status": s["status"], "owner": ", ".join(s["owners"]) or "Unassigned"} for s in soa],
        "soa_summary": {"total": len(soa), "applicable": sum(1 for s in soa if s["applicable"]),
                        "excluded": sum(1 for s in soa if not s["applicable"])},
        "suppliers": [{"name": a.name, "classification": _cap(a.classification),
                       "owner": owners.get(a.owner_user_id or "", "Unassigned")} for a in suppliers],
        **_management_context(db, tenant_id),
        "documents": published,
        "document": {},
    }


RACI_WORDS = (("responsible", "R"), ("accountable", "A"), ("consulted", "C"), ("informed", "I"))


def _management_context(db: Session, tenant_id: str) -> dict:
    """People, objectives, the audit programme, improvement and acknowledgements, as the standalone app's
    phase2Context gives them."""
    from . import audits, management, people, review
    from .domain._js import js_number

    def unit(o: dict) -> str:
        return f" {o['unit']}" if o["unit"] else ""

    matrix = people.raci(db, tenant_id)
    held = next((r for r in review.review_rows(db, tenant_id) if r["status"] == "held"), None)
    role_names = {r["id"]: r["name"] for r in matrix["roles"]}

    def letters(activity_id: str, letter: str) -> str:
        return ", ".join(role_names.get(c["roleId"], "") for c in matrix["cells"]
                         if c["activityId"] == activity_id and c["letter"] == letter)

    objectives = [o for o in management.objective_rows(db, tenant_id) if o["status"] == "active"]
    programmes = audits.programme_rows(db, tenant_id)
    prog = programmes[0] if programmes else None
    ncs = management.nonconformity_rows(db, tenant_id, "all")
    return {
        "isms_roles": [{"name": r["name"], "holders": ", ".join(h["name"] for h in r["holders"]) or "Not assigned",
                        "responsibilities": r["responsibilities"] or "Not described yet.",
                        "authorities": r["authorities"]} for r in people.role_rows(db, tenant_id)],
        "raci": [{"activity": a["title"], **{word: letters(a["id"], letter) for word, letter in RACI_WORDS}}
                 for a in matrix["activities"]],
        "last_review": {
            "ref": held["ref"], "title": held["title"], "held_on": uk_date(held["heldOn"]) if held["heldOn"] else "",
            "chair": held["chairName"] or "Not recorded", "attendees": held["attendees"], "minutes": held["minutes"],
            "decisions": held["decisions"], "changes_needed": held["changesNeeded"] or "None.",
            "period": (f"{uk_date(held['pack']['periodStart'])} to {uk_date(held['pack']['periodEnd'])}"
                       if held["pack"] else ""),
            "actions": [{"description": a["description"], "owner": a["ownerName"] or "Unassigned",
                         "due": uk_date(a["dueOn"]), "status": "Done" if a["doneAt"] else "Open"}
                        for a in held["actions"]],
        } if held else None,
        "acknowledgements": [{"document": f"{c['documentNumber']} {c['documentTitle']}",
                              "completion": f"{c['progress']['done']} of {c['progress']['total']}",
                              "status": _cap(c["status"])} for c in people.campaign_rows(db, tenant_id)],
        "objectives": [{
            "ref": o["ref"], "title": o["title"], "measure": o["measure"],
            "target": f"{'At least' if o['direction'] == 'at_least' else 'At most'} {js_number(o['target'])}{unit(o)}",
            "owner": o["ownerName"] or "Unassigned", "due": uk_date(o["dueOn"]) if o["dueOn"] else "Ongoing",
            "plan": o["plan"] or "To be planned.", "resources": o["resources"] or "Existing resources.",
            "frequency": o["frequency"],
            "latest": (f"{js_number(o['summary']['latest']['value'])}{unit(o)} on "
                       f"{uk_date(o['summary']['latest']['measuredOn'])}") if o["summary"]["latest"] else "No result yet",
        } for o in objectives],
        "audit_programme": {
            "title": prog["title"], "period": f"{uk_date(prog['periodStart'])} to {uk_date(prog['periodEnd'])}",
            "coverage": f"{prog['coverage']['percent']}%",
            "audits": [{"ref": a["ref"], "title": a["title"],
                        "dates": f"{uk_date(a['plannedStart'])} to {uk_date(a['plannedEnd'])}",
                        "lead": a["leadAuditorName"] or "To be chosen",
                        "status": _cap(a["status"].replace("_", " ", 1))} for a in prog["audits"]],
        } if prog else None,
        "improvement": {
            "open": sum(1 for n in ncs if n["kind"] == "nonconformity" and n["status"] == "open"),
            "closed": sum(1 for n in ncs if n["kind"] == "nonconformity" and n["status"] == "closed"),
            "opportunities": sum(1 for n in ncs if n["kind"] == "opportunity" and n["status"] == "open"),
        },
    }


def excluded_sections(db: Session, tenant_id: str) -> set[str]:
    return set(db.execute(select(IsmsApplicability.target_key).where(
        IsmsApplicability.tenant_id == tenant_id, IsmsApplicability.target_type == "template_section",
        IsmsApplicability.applicable.is_(False))).scalars())


def overrides_for(db: Session, document_id: str | None) -> dict[str, str]:
    if not document_id:
        return {}
    return {o.block_ref: o.content for o in db.execute(select(IsmsDocumentOverride).where(
        IsmsDocumentOverride.document_id == document_id)).scalars()}


def render_for(db: Session, tenant_id: str, t: dict, document_id: str | None) -> tuple[list[dict], str]:
    full = build_context(db, tenant_id)
    excluded = excluded_sections(db, tenant_id)
    overrides = overrides_for(db, document_id)
    blocks = docgen.render_template(t["body"], full, excluded, overrides)
    return blocks, docgen.context_hash(docgen.context_for_template(t["body"], full), t["ref"], overrides, excluded)


# Files ----------------------------------------------------------------------------------------------------------

def _dir():
    path = get_settings().artifact_dir / "isms-documents"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _aad(tenant_id: str, name: str) -> str:
    return f"isms-document:{tenant_id}:{name}"


def _store(tenant_id: str, data: bytes) -> str:
    name = secrets.token_hex(16)
    path = _dir() / name
    with open(path, "w", encoding="utf-8") as out:
        os.chmod(path, 0o600)
        json.dump(crypto.encrypt(data, _aad(tenant_id, name)), out)
    return name


def read_file(tenant_id: str, name: str) -> bytes:
    with open(_dir() / name, encoding="utf-8") as f:
        return crypto.decrypt_bytes(json.load(f), _aad(tenant_id, name))


def _discard(name: str | None) -> None:
    if name:
        try:
            (_dir() / name).unlink()
        except FileNotFoundError:
            pass


def _write_files(db: Session, doc: IsmsDocument, version: int, status: str, blocks: list[dict], satisfies: list[str],
                 approved_by: str | None = None, approved_on: str | None = None,
                 next_review: str | None = None) -> tuple[str, str | None, str | None]:
    from .. import branding

    tenant = db.get(Tenant, doc.tenant_id)
    owner = db.get(User, doc.owner_user_id) if doc.owner_user_id else None
    try:
        colour = str((branding.get(db, tenant.id) or {}).get("primaryColour") or "1E3A8A")
    except Exception:  # noqa: BLE001 - branding is cosmetic
        colour = "1E3A8A"
    meta = docwriter.DocumentMeta(
        title=doc.title, number=doc.number, version=version, status=status, organization=tenant.name,
        owner=(owner.name or owner.email) if owner else (doc.owner_name or "Unassigned"), approved_by=approved_by,
        approved_on=approved_on, next_review=next_review or (uk_date(doc.next_review) if doc.next_review else None),
        classification=doc.classification, generated_on=uk_date(utcnow().date()), brand_colour=colour,
        satisfies=satisfies)
    docx = _store(doc.tenant_id, docwriter.build_docx(meta, blocks))
    try:
        return docx, _store(doc.tenant_id, docwriter.build_pdf(meta, blocks)), None
    except Exception as exc:  # noqa: BLE001 - a PDF problem must not lose the Word document
        return docx, None, f"The PDF could not be made: {exc.__class__.__name__}"


def _citations(t: dict) -> list[str]:
    return [f"{FRAMEWORK_LABEL.get(s['framework'], s['framework'])} {s['ref']}" for s in t.get("satisfies", [])]


# Documents ------------------------------------------------------------------------------------------------------

def _number(db: Session, tenant_id: str, t: dict) -> str:
    tenant = db.get(Tenant, tenant_id)
    prefix = re.sub(r"[^a-z]", "", tenant.slug or "")[:3].upper() or "DOC"
    code = t.get("code") or "".join(w[:1].upper() for w in t["docType"].split("-"))[:4]
    taken = set(db.execute(select(IsmsDocument.number).where(IsmsDocument.tenant_id == tenant_id)).scalars())
    n = 1
    while f"{prefix}-{code}-{n:03d}" in taken:
        n += 1
    return f"{prefix}-{code}-{n:03d}"


def versions(db: Session, document_id: str) -> list[IsmsDocumentVersion]:
    return list(db.execute(select(IsmsDocumentVersion).where(IsmsDocumentVersion.document_id == document_id)
                           .order_by(IsmsDocumentVersion.version.desc())).scalars())


def generate(db: Session, tenant_id: str, actor: str, user_id: str, doc_type: str,
             change_note: str | None = None) -> IsmsDocumentVersion:
    """A new draft from live data. An existing draft is rebuilt in place; an approved or published latest version is
    left untouched and a new version is added."""
    t = template(db, doc_type)
    doc = db.execute(select(IsmsDocument).where(IsmsDocument.tenant_id == tenant_id,
                                                IsmsDocument.doc_type == doc_type)).scalar_one_or_none()
    if doc is None:
        doc = IsmsDocument(tenant_id=tenant_id, doc_type=doc_type, title=t["title"], number=_number(db, tenant_id, t),
                           owner_user_id=user_id, review_months=t["reviewMonths"], classification=t["classification"],
                           updated_by=actor)
        db.add(doc)
        db.flush()
    vs = versions(db, doc.id)
    if any(v.state == "in_review" for v in vs):
        raise _error("A version is in review. Approve or return it before regenerating.")
    draft = next((v for v in vs if v.state == "draft"), None)
    number = draft.version if draft else (vs[0].version if vs else 0) + 1
    blocks, digest = render_for(db, tenant_id, t, doc.id)
    html = "\n".join(f'<section data-block="{b["ref"]}">{docgen.to_html(docgen.parse_markdown(b["markdown"]))}</section>'
                     for b in blocks)
    docx, pdf, pdf_error = _write_files(db, doc, number, "Draft", blocks, _citations(t))
    if draft:
        _discard(draft.docx_name)
        _discard(draft.pdf_name)
        draft.template_ref, draft.context_hash, draft.blocks, draft.html = t["ref"], digest, blocks, html
        draft.docx_name, draft.pdf_name, draft.pdf_error = docx, pdf, pdf_error
        draft.change_note = change_note or draft.change_note
        draft.updated_at, draft.updated_by = utcnow(), actor
        row = draft
    else:
        row = IsmsDocumentVersion(tenant_id=tenant_id, document_id=doc.id, version=number, template_ref=t["ref"],
                                  context_hash=digest, blocks=blocks, html=html, docx_name=docx, pdf_name=pdf,
                                  pdf_error=pdf_error, change_note=change_note or ("First version." if number == 1 else None),
                                  updated_by=actor)
        db.add(row)
    db.flush()
    audit.record(db, actor, "isms.document_generated", f"{doc.number} v{number}", tenant_id, documentId=doc.id,
                 version=number, contextHash=digest)
    return row


def transition(db: Session, row: IsmsDocumentVersion, action: str, actor: str, user: User) -> None:
    """Moves a version through its lifecycle. Approval stamps a final copy with the approver."""
    need = ACTION_NEEDS.get(action)
    if need is None:
        raise _error("Unknown action.")
    if row.state != need:
        verb = {"submit": "submitted", "return": "returned", "approve": "approved", "publish": "published",
                "withdraw": "withdrawn"}[action]
        raise _error(f"A {STATE_LABEL[row.state].lower()} version cannot be {verb}.")
    doc = db.get(IsmsDocument, row.document_id)
    now = utcnow()
    if action == "submit":
        row.state, row.submitted_at, row.submitted_by_user_id = "in_review", now, user.id
    elif action == "return":
        row.state = "draft"
    elif action == "approve":
        name = user.name or user.email
        review = next_review_date(now.date(), doc.review_months)
        t = next((x for x in templates(db) if x["docType"] == doc.doc_type), None)
        docx, pdf, _ = _write_files(db, doc, row.version, "Approved", row.blocks, _citations(t) if t else [],
                                    approved_by=name, approved_on=uk_date(now.date()), next_review=uk_date(review))
        row.state, row.approved_at, row.approved_by_user_id, row.approved_by_name = "approved", now, user.id, name
        row.final_docx_name, row.final_pdf_name = docx, pdf
    elif action == "publish":
        for v in versions(db, doc.id):
            if v.state == "published":
                v.state, v.superseded_at = "superseded", now
        row.state, row.published_at = "published", now
        doc.next_review = date.fromisoformat(next_review_date(now.date(), doc.review_months))
    else:
        row.state, row.withdrawn_at = "withdrawn", now
    row.updated_at, row.updated_by = now, actor
    audit.record(db, actor, f"isms.document_{action}", f"{doc.number} v{row.version}", row.tenant_id,
                 documentId=doc.id, version=row.version)


def set_override(db: Session, tenant_id: str, actor: str, doc_type: str, block_ref: str, content: str | None) -> None:
    """The customer's own wording for one block (None removes it). It takes effect on the next generation."""
    t = template(db, doc_type)
    if not re.search(rf"::: block {re.escape(block_ref)}\s*\n", t["body"]):
        raise _error("That section is not in this document.")
    doc = db.execute(select(IsmsDocument).where(IsmsDocument.tenant_id == tenant_id,
                                                IsmsDocument.doc_type == doc_type)).scalar_one_or_none()
    if doc is None:
        raise _error("Generate the document first.")
    row = db.execute(select(IsmsDocumentOverride).where(IsmsDocumentOverride.document_id == doc.id,
                                                        IsmsDocumentOverride.block_ref == block_ref)).scalar_one_or_none()
    text = (content or "").strip()
    if text:
        try:
            docgen.render_mustache(text, {})
        except docgen.TemplateError as e:
            raise _error(f"The wording has a placeholder problem: {e}") from None
        if row is None:
            db.add(IsmsDocumentOverride(tenant_id=tenant_id, document_id=doc.id, block_ref=block_ref,
                                        content=text[:20_000], updated_by=actor))
        else:
            row.content, row.updated_at, row.updated_by = text[:20_000], utcnow(), actor
    elif row is not None:
        db.delete(row)
    audit.record(db, actor, "isms.document_wording_set" if text else "isms.document_wording_removed", block_ref,
                 tenant_id, documentId=doc.id)


def document_rows(db: Session, tenant_id: str) -> list[dict]:
    """Every template with its document (if generated): latest version, published version and whether it is out of
    date. Imported documents are listed too."""
    docs = {d.doc_type: d for d in db.execute(select(IsmsDocument).where(IsmsDocument.tenant_id == tenant_id)).scalars()}
    names = {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(
        [d.owner_user_id for d in docs.values() if d.owner_user_id]))).scalars()}
    out = []
    tpls = templates(db)
    full = build_context(db, tenant_id) if docs else {}
    excluded = excluded_sections(db, tenant_id) if docs else set()
    for t in tpls:
        out.append(_row(db, t, docs.get(t["docType"]), names, full, excluded))
    for d in docs.values():
        if d.source == "imported":
            out.append(_row(db, None, d, names, full, excluded))
    return out


def _row(db, t, doc, names, full, excluded) -> dict:
    vs = versions(db, doc.id) if doc else []
    latest = vs[0] if vs else None
    published = next((v for v in vs if v.state == "published"), None)
    out_of_date = False
    if t and latest:
        overrides = overrides_for(db, doc.id)
        digest = docgen.context_hash(docgen.context_for_template(t["body"], full), t["ref"], overrides, excluded)
        out_of_date = digest != latest.context_hash
    return {"docType": t["docType"] if t else doc.doc_type, "title": t["title"] if t else doc.title,
            "source": doc.source if doc else "template", "documentId": doc.id if doc else None,
            "number": doc.number if doc else None,
            "owner": (names.get(doc.owner_user_id or "") or doc.owner_name) if doc else None,
            "nextReview": doc.next_review.isoformat() if doc and doc.next_review else None,
            "reviewOverdue": bool(doc and doc.next_review and doc.next_review < utcnow().date()),
            "latest": _version(latest), "published": _version(published), "outOfDate": out_of_date,
            "satisfies": _citations(t) if t else []}


def _version(v: IsmsDocumentVersion | None) -> dict | None:
    if v is None:
        return None
    iso = (lambda d: d.isoformat() + "Z" if d else None)  # noqa: E731
    return {"id": v.id, "version": v.version, "state": v.state, "stateLabel": STATE_LABEL[v.state],
            "changeNote": v.change_note, "approvedBy": v.approved_by_name, "approvedAt": iso(v.approved_at),
            "publishedAt": iso(v.published_at), "hasPdf": bool(v.final_pdf_name or v.pdf_name), "pdfError": v.pdf_error}


def detail(db: Session, tenant_id: str, doc: IsmsDocument, version_id: str | None = None) -> dict:
    vs = versions(db, doc.id)
    viewing = next((v for v in vs if v.id == version_id), None) if version_id else (vs[0] if vs else None)
    t = next((x for x in templates(db) if x["docType"] == doc.doc_type), None)
    changes = []
    if t and vs:
        blocks, digest = render_for(db, tenant_id, t, doc.id)
        if digest != vs[0].context_hash:
            changes = docgen.diff_blocks(vs[0].blocks, blocks)
    blocks_tpl = [{"ref": m.group(1), "body": m.group(2).strip()}
                  for m in re.finditer(r"::: block ([^\s]+)\s*\n([\s\S]*?)\n:::", t["body"])] if t else []
    return {"documentId": doc.id, "docType": doc.doc_type, "title": doc.title, "number": doc.number,
            "source": doc.source, "versions": [_version(v) for v in vs], "viewing": _version(viewing),
            "html": viewing.html if viewing else "", "blocks": viewing.blocks if viewing else [], "changes": changes, "overrides": overrides_for(db, doc.id),
            "templateBlocks": blocks_tpl}


def file_for(row: IsmsDocumentVersion, fmt: str) -> tuple[bytes, str]:
    """The approved copy once approved, else the generated one."""
    name = (row.final_pdf_name or row.pdf_name) if fmt == "pdf" else (row.final_docx_name or row.docx_name)
    if not name:
        raise _error(row.pdf_error or "There is no file in that format.", 404)
    return read_file(row.tenant_id, name), name
