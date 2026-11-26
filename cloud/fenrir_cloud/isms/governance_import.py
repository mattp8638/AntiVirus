"""Moves a customer's records from Fenrir's earlier Governance module into the ISMS (plan decisions R3, R9, R10).

* Adopted frameworks become ISMS frameworks (newest pack version), and applicability is applied so controls exist.
* Requirement answers are kept read-only (``IsmsLegacyAnswer``) beside the Statement of Applicability, matched to the
  ISMS requirements. A "not applicable" answer becomes a justified exclusion where the match is exact (or the earlier
  requirement covers several ISMS ones, such as a NIST CSF category); looser matches only keep the answer.
* Policies become imported ISMS documents, every approved version kept (the approved one published, earlier ones
  superseded, a retired policy withdrawn), with Word and PDF copies stamped with the original approver.
* Evidence (files re-encrypted into the ISMS store, links and notes) is linked to the controls that satisfy the
  requirements it was linked to. Fenrir's automated evidence is not copied: the hourly ISMS job imports it.
* Risk register entries become ISMS risks; exceptions become retained risks; other record types become notes.

Nothing in the earlier module is changed or deleted. Every moved record is noted in ``IsmsImport``, so running the
move again only adds what is new. The whole move is audited.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto
from ..config import get_settings
from ..models import (GovernanceRecord, GrcAdoption, GrcEvidence, GrcEvidenceLink, GrcPolicy, GrcPolicyVersion,
                      GrcRequirementState, utcnow)
from . import docgen, documents, evidence as isms_evidence, programme
from .models import (IsmsApplicabilityOverride, IsmsDocument, IsmsDocumentVersion, IsmsEvidence, IsmsEvidenceLink,
                     IsmsImport, IsmsLegacyAnswer, IsmsRisk, IsmsScope, IsmsTenantControl)

# Fenrir framework key -> ISMS framework slug. Essential Eight is retired in Fenrir and stays there, read-only.
FRAMEWORKS = {
    "iso-27001": "iso27001", "cyber-essentials": "cyber-essentials", "cyber-essentials-plus": "cyber-essentials-plus",
    "ncsc-caf": "ncsc-caf", "nist-csf-2": "nist-csf", "uk-gdpr": "uk-gdpr", "soc2": "soc2", "pci-dss": "pci-dss",
    "cis-v8-ig1": "cis-controls", "def-stan-05-138": "def-stan-05-138", "dora": "dora", "eu-gdpr": "eu-gdpr",
    "govassure": "govassure", "govs-007": "govs-007", "nis2": "nis2",
}
# Cyber Essentials: Fenrir uses the self-assessment question numbers; the ISMS pack groups requirements by topic.
CE_SECTIONS = {"A4": "ce-firewalls", "A5": "ce-secure-configuration", "A6": "ce-security-updates",
               "A7": "ce-user-access", "A8": "ce-malware"}
STATUS_STATE = {"draft": "draft", "in_review": "in_review"}


def resolve(framework: str, ref: str, pack: dict) -> tuple[list[str], bool]:
    """ISMS requirement refs for an earlier requirement id, and whether the match is exact enough to carry an
    exclusion (exact, or the earlier requirement is the parent of several ISMS ones)."""
    refs = [r["ref"] for r in pack["requirements"]]
    if ref in refs:
        return [ref], True
    children = [r for r in refs if r.startswith(ref + ".") or r.startswith(ref + "-")]
    if children:
        return children, True
    if framework == "cyber-essentials":
        group = CE_SECTIONS.get(ref.split(".")[0])
        return ([r["ref"] for r in pack["requirements"] if r["group"] == group] if group else []), False
    m = re.fullmatch(r"Art\.(\d+)-(\d+)", ref)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        return [r for r in refs if re.fullmatch(r"Art\.\d+", r) and lo <= int(r[4:]) <= hi], False
    m = re.fullmatch(r"(Art\.\d+)\(.*", ref)
    if m and m.group(1) in refs:
        return [m.group(1)], False
    return [], False


def _done(db: Session, tenant_id: str, table: str) -> dict[str, IsmsImport]:
    return {i.source_id: i for i in db.execute(select(IsmsImport).where(IsmsImport.tenant_id == tenant_id,
                                                                       IsmsImport.source_table == table)).scalars()}


def _note(db: Session, tenant_id: str, table: str, source_id: str, target_table: str, target_id: str | None,
          note: str = "") -> None:
    db.add(IsmsImport(tenant_id=tenant_id, source_table=table, source_id=source_id, target_table=target_table,
                      target_id=target_id, note=note[:2000], updated_by="system:isms-import"))


def preview(db: Session, tenant_id: str) -> dict:
    """What the move would bring across, and what would stay behind."""
    adoptions = list(db.execute(select(GrcAdoption).where(GrcAdoption.tenant_id == tenant_id)).scalars())
    return {
        "frameworks": sorted(FRAMEWORKS[a.framework_key] for a in adoptions if a.framework_key in FRAMEWORKS),
        "frameworksNotMoved": sorted(a.framework_key for a in adoptions if a.framework_key not in FRAMEWORKS),
        "answers": _count(db, GrcRequirementState, tenant_id),
        "policies": _count(db, GrcPolicy, tenant_id),
        "evidence": len([e for e in db.execute(select(GrcEvidence).where(GrcEvidence.tenant_id == tenant_id)).scalars()
                         if e.kind != "automated"]),
        "records": _count(db, GovernanceRecord, tenant_id),
        "alreadyMoved": len(list(db.execute(select(IsmsImport.id).where(IsmsImport.tenant_id == tenant_id)).scalars())),
    }


def _count(db: Session, model, tenant_id: str) -> int:
    return len(list(db.execute(select(model.id).where(model.tenant_id == tenant_id)).scalars()))


def run(db: Session, tenant_id: str, actor: str, user_id: str) -> dict:
    out = {"frameworks": 0, "answers": 0, "exclusions": 0, "documents": 0, "versions": 0, "evidence": 0, "risks": 0,
           "notes": 0, "skipped": []}
    _frameworks(db, tenant_id, actor, out)
    packs = {p["meta"]["framework"]: p for p in programme.pinned_packs(db, tenant_id)}
    _answers(db, tenant_id, packs, out)
    if out["exclusions"] or out["frameworks"]:
        programme.apply(db, tenant_id, actor)
    controls = {c.ref: c for c in db.execute(select(IsmsTenantControl).where(
        IsmsTenantControl.tenant_id == tenant_id)).scalars()}
    _policies(db, tenant_id, actor, out)
    _evidence(db, tenant_id, user_id, packs, controls, out)
    _records(db, tenant_id, packs, controls, out)
    isms_evidence.refresh_states(db, tenant_id)
    audit.record(db, actor, "isms.governance_imported", "earlier Governance records", tenant_id,
                 **{k: v for k, v in out.items() if k != "skipped"}, skipped=out["skipped"][:50])
    return out


def _frameworks(db: Session, tenant_id: str, actor: str, out: dict) -> None:
    current = {f.framework: f for f in programme.tenant_frameworks(db, tenant_id)}
    selected = {slug: {"status": f.status, "targetDate": f.target_date.isoformat() if f.target_date else None}
                for slug, f in current.items()}
    scope_text = ""
    for a in db.execute(select(GrcAdoption).where(GrcAdoption.tenant_id == tenant_id)).scalars():
        slug = FRAMEWORKS.get(a.framework_key)
        if slug is None:
            out["skipped"].append(f"framework {a.framework_key} (not in the ISMS)")
            continue
        scope_text = scope_text or (a.scope or "").strip()
        if slug not in selected:
            selected[slug] = {"status": "target_certification",
                              "targetDate": a.target_date.date().isoformat() if a.target_date else None}
            out["frameworks"] += 1
    if out["frameworks"]:
        programme.set_frameworks(db, tenant_id, actor, selected)
    if scope_text and db.execute(select(IsmsScope.id).where(IsmsScope.tenant_id == tenant_id)).first() is None:
        db.add(IsmsScope(tenant_id=tenant_id, statement=scope_text[:16_000], updated_by=actor))


def _answers(db: Session, tenant_id: str, packs: dict, out: dict) -> None:
    done = _done(db, tenant_id, "grc_requirement_states")
    for s in db.execute(select(GrcRequirementState).where(GrcRequirementState.tenant_id == tenant_id)).scalars():
        if s.id in done:
            continue
        slug = FRAMEWORKS.get(s.framework_key)
        pack = packs.get(slug) if slug else None
        if pack is None:
            _note(db, tenant_id, "grc_requirement_states", s.id, "", None, "framework not in the ISMS")
            continue
        refs, exact = resolve(slug, s.requirement_id, pack)
        row = IsmsLegacyAnswer(tenant_id=tenant_id, framework=slug, source_framework=s.framework_key,
                               source_ref=s.requirement_id, refs=refs, status=s.status, answer=s.answer or "",
                               notes=s.notes or "", na_reason=s.na_reason or "", owner=s.owner or "",
                               answered_by=s.updated_by or "", answered_at=s.updated_at, updated_by="system:isms-import")
        db.add(row)
        db.flush()
        _note(db, tenant_id, "grc_requirement_states", s.id, "isms_legacy_answers", row.id)
        out["answers"] += 1
        if s.status == "not_applicable" and exact:
            mandatory = {r["ref"] for r in pack["requirements"] if r.get("mandatory")}
            why = (s.na_reason or s.answer or "Marked not applicable in the earlier Governance programme.").strip()
            for ref in refs:
                if ref in mandatory:
                    out["skipped"].append(f"{slug} {ref}: mandatory, so it cannot be excluded")
                    continue
                key = f"{slug}:{ref}"
                if db.execute(select(IsmsApplicabilityOverride.id).where(
                        IsmsApplicabilityOverride.tenant_id == tenant_id, IsmsApplicabilityOverride.target_type == "requirement",
                        IsmsApplicabilityOverride.target_key == key)).first() is None:
                    db.add(IsmsApplicabilityOverride(tenant_id=tenant_id, target_type="requirement", target_key=key,
                                                     applicable=False, justification=why[:4000],
                                                     updated_by="system:isms-import"))
                    out["exclusions"] += 1
    db.flush()


def _policies(db: Session, tenant_id: str, actor: str, out: dict) -> None:
    done = _done(db, tenant_id, "grc_policies")
    for p in db.execute(select(GrcPolicy).where(GrcPolicy.tenant_id == tenant_id).order_by(GrcPolicy.id)).scalars():
        if p.id in done:
            continue
        snapshots = list(db.execute(select(GrcPolicyVersion).where(GrcPolicyVersion.policy_id == p.id)
                                    .order_by(GrcPolicyVersion.version)).scalars())
        template = {"docType": "imported", "code": "POL"}
        doc = IsmsDocument(tenant_id=tenant_id, doc_type=f"imported-{p.id}"[:80], title=p.title[:300],
                           number=documents._number(db, tenant_id, {**template, "docType": "imported-policy"}),
                           owner_name=(p.owner or None), review_months=12,
                           next_review=p.review_due.date() if p.review_due else None, source="imported",
                           updated_by=actor)
        db.add(doc)
        db.flush()
        current = p.approved_version  # stays in force while a newer draft is being written
        for snap in snapshots:
            if snap.version == current:
                state = "withdrawn" if p.status == "retired" else "published"
            else:
                state = "superseded"
            _imported_version(db, doc, snap.version, state, snap.body, snap.title, snap.approved_by, snap.approved_at,
                              snap.note, out)
        if p.status in ("draft", "in_review") and (not snapshots or p.version > snapshots[-1].version):
            _imported_version(db, doc, p.version, STATUS_STATE[p.status], p.body, p.title, None, None,
                              "Imported from the earlier policy draft.", out)
        _note(db, tenant_id, "grc_policies", p.id, "isms_documents", doc.id)
        out["documents"] += 1
    db.flush()


def _imported_version(db: Session, doc: IsmsDocument, version: int, state: str, body: str, title: str,
                      approved_by: str | None, approved_at, note: str | None, out: dict) -> None:
    blocks = [{"ref": "body", "markdown": (body or "").strip() or f"# {title}", "overridden": False}]
    html = docgen.to_html(docgen.parse_markdown(blocks[0]["markdown"]))
    status = {"published": "Published", "superseded": "Superseded", "withdrawn": "Withdrawn", "draft": "Draft",
              "in_review": "In review"}[state]
    docx, pdf, pdf_error = documents._write_files(
        db, doc, version, status, blocks, [], approved_by=approved_by or None,
        approved_on=documents.uk_date(approved_at) if approved_at else None)
    approved = state in ("published", "superseded", "withdrawn")
    db.add(IsmsDocumentVersion(
        tenant_id=doc.tenant_id, document_id=doc.id, version=version, state=state,
        template_ref=f"imported:grc_policies:{doc.doc_type[9:]}",
        context_hash=hashlib.sha256((body or "").encode()).hexdigest(), blocks=blocks, html=html,
        docx_name=docx, pdf_name=pdf, final_docx_name=docx if approved else None,
        final_pdf_name=pdf if approved else None, pdf_error=pdf_error,
        change_note=(note or "Imported from the earlier Governance policies.")[:2000],
        approved_at=approved_at if approved else None, approved_by_name=(approved_by or None) if approved else None,
        published_at=approved_at if state in ("published", "superseded") else None,
        updated_by="system:isms-import"))
    out["versions"] += 1


def _controls_for(packs: dict, links: list[GrcEvidenceLink], controls: dict) -> list[IsmsTenantControl]:
    found: dict[str, IsmsTenantControl] = {}
    for link in links:
        slug = FRAMEWORKS.get(link.framework_key)
        pack = packs.get(slug) if slug else None
        if pack is None:
            continue
        refs, _ = resolve(slug, link.requirement_id, pack)
        for m in pack["mappings"]:
            if m["requirement"] in refs and m["strength"] == "satisfies" and m["control"] in controls:
                found[m["control"]] = controls[m["control"]]
    return [found[k] for k in sorted(found)]


def _evidence(db: Session, tenant_id: str, user_id: str, packs: dict, controls: dict, out: dict) -> None:
    done = _done(db, tenant_id, "grc_evidence")
    old_dir = get_settings().artifact_dir / "grc-evidence"
    for e in db.execute(select(GrcEvidence).where(GrcEvidence.tenant_id == tenant_id)).scalars():
        if e.id in done or e.kind == "automated":
            continue
        links = list(db.execute(select(GrcEvidenceLink).where(GrcEvidenceLink.evidence_id == e.id)).scalars())
        row = IsmsEvidence(tenant_id=tenant_id, title=e.title[:300], kind=e.kind if e.kind in ("file", "link", "note")
                           else "note", note=(e.description or None), url=(e.url or None),
                           collected_at=e.created_at, valid_until=e.valid_until.date() if e.valid_until else None,
                           scan_status="not_required", source="fenrir-governance", source_ref=e.id,
                           updated_by="system:isms-import")
        if e.kind == "file":
            try:
                with open(old_dir / e.storage_name, encoding="utf-8") as f:
                    data = crypto.decrypt_bytes(json.load(f), f"grc-evidence:{e.tenant_id}:{e.id}")
            except (OSError, ValueError, KeyError) as exc:
                out["skipped"].append(f"evidence file {e.filename}: could not be read ({exc.__class__.__name__})")
                continue
            row.filename, row.content_type, row.size = e.filename, e.content_type, e.size
            row.sha256, row.storage_name = hashlib.sha256(data).hexdigest(), secrets.token_hex(16)
            db.add(row)
            db.flush()
            isms_evidence._write(row, data)
            isms_evidence._apply_scan(db, row, data, "system:isms-import")
        else:
            db.add(row)
            db.flush()
        for c in _controls_for(packs, links, controls):
            db.add(IsmsEvidenceLink(tenant_id=tenant_id, evidence_id=row.id, tenant_control_id=c.id,
                                    updated_by="system:isms-import"))
        _note(db, tenant_id, "grc_evidence", e.id, "isms_evidence", row.id)
        out["evidence"] += 1
    db.flush()


def _records(db: Session, tenant_id: str, packs: dict, controls: dict, out: dict) -> None:
    done = _done(db, tenant_id, "governance_records")
    refs = [r for (r,) in db.execute(select(IsmsRisk.ref).where(IsmsRisk.tenant_id == tenant_id)).all()]
    n = max((int(r[2:]) for r in refs if re.fullmatch(r"R-\d+", r)), default=0)
    for g in db.execute(select(GovernanceRecord).where(GovernanceRecord.tenant_id == tenant_id)
                        .order_by(GovernanceRecord.created_at)).scalars():
        if g.id in done:
            continue
        lines = [g.description or ""]
        if g.owner:
            lines.append(f"Owner in the earlier register: {g.owner}.")
        if g.framework or g.control:
            lines.append(f"Earlier reference: {g.framework} {g.control}".strip() + ".")
        if g.approved_by:
            lines.append(f"Approved by {g.approved_by}.")
        text = "\n\n".join(x for x in lines if x.strip())
        if g.kind in ("risk", "exception"):
            n += 1
            status = {"closed": "closed"}.get(g.status, "assessed")
            risk = IsmsRisk(tenant_id=tenant_id, ref=f"R-{n:03d}", title=g.title[:300], description=text[:4000] or None,
                            inherent_likelihood=max(1, min(5, g.likelihood or 1)),
                            inherent_impact=max(1, min(5, g.impact or 1)),
                            treatment="retain" if g.kind == "exception" else None,
                            treatment_plan=("Accepted exception from the earlier register." if g.kind == "exception"
                                            else None),
                            status="treatment_planned" if g.kind == "exception" and status != "closed" else status,
                            next_review=g.review_due.date() if g.review_due else None,
                            updated_by="system:isms-import")
            db.add(risk)
            db.flush()
            _note(db, tenant_id, "governance_records", g.id, "isms_risks", risk.id)
            out["risks"] += 1
            continue
        row = IsmsEvidence(tenant_id=tenant_id, title=f"{g.kind.title()}: {g.title}"[:300],
                           kind="link" if g.evidence_url else "note", url=g.evidence_url or None,
                           note=text[:10_000] or g.title, collected_at=g.created_at, scan_status="not_required",
                           source="fenrir-governance", source_ref=g.id, updated_by="system:isms-import")
        db.add(row)
        db.flush()
        ref = (g.control or "").split()[0] if g.control else ""
        if ref in controls:
            db.add(IsmsEvidenceLink(tenant_id=tenant_id, evidence_id=row.id, tenant_control_id=controls[ref].id,
                                    updated_by="system:isms-import"))
        _note(db, tenant_id, "governance_records", g.id, "isms_evidence", row.id)
        out["notes"] += 1
    db.flush()


def legacy_answers(db: Session, tenant_id: str, framework: str) -> dict[str, list[dict]]:
    """Earlier answers by ISMS requirement ref (unmatched ones under ""), for the Statement of Applicability."""
    out: dict[str, list[dict]] = {}
    for a in db.execute(select(IsmsLegacyAnswer).where(IsmsLegacyAnswer.tenant_id == tenant_id,
                                                       IsmsLegacyAnswer.framework == framework)).scalars():
        item = {"sourceRef": a.source_ref, "status": a.status, "answer": a.answer, "notes": a.notes,
                "naReason": a.na_reason, "owner": a.owner, "answeredBy": a.answered_by,
                "answeredAt": a.answered_at.isoformat() + "Z" if a.answered_at else None}
        for ref in (a.refs or [""]):
            out.setdefault(ref, []).append(item)
    return out

