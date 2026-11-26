"""ISMS tables. Every table holding tenant data is registered with ``@tenant_table`` (see ``scope.py``)."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from ..models import new_id, utcnow
from .scope import tenant_table


@tenant_table
class IsmsMembership(Base):
    """A person's ISMS role in one customer (plan decision R7: a separate ISMS role, set per person per customer).

    Fenrir's own role decides whether someone can reach Governance at all; this decides what they can do in the ISMS
    for that customer. Auditor roles always expire. Client portal accounts can only hold the staff role.
    """
    __tablename__ = "isms_memberships"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="uq_isms_membership"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ism"))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(40))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    granted_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class _Row:
    """Columns every ISMS register row has."""
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(200), default="")


@tenant_table
class IsmsScope(_Row, Base):
    """The ISMS scope (ISO 27001 4.3): one per customer. Each material change increments the version."""
    __tablename__ = "isms_scope"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_isms_scope_tenant"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("isc"))
    statement: Mapped[str] = mapped_column(Text, default="")
    boundaries: Mapped[str] = mapped_column(Text, default="")
    interfaces: Mapped[str] = mapped_column(Text, default="")
    exclusions: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[int] = mapped_column(Integer, default=1)


@tenant_table
class IsmsEntity(_Row, Base):
    """A legal entity of the organization, in or out of the ISMS scope."""
    __tablename__ = "isms_entities"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ien"))
    name: Mapped[str] = mapped_column(String(300))
    address: Mapped[str | None] = mapped_column(Text, nullable=True)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)


@tenant_table
class IsmsSite(_Row, Base):
    """A site (office, data centre), in or out of the ISMS scope."""
    __tablename__ = "isms_sites"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ist"))
    name: Mapped[str] = mapped_column(String(300))
    address: Mapped[str | None] = mapped_column(Text, nullable=True)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)


@tenant_table
class IsmsContextIssue(_Row, Base):
    """An internal or external issue affecting the ISMS (ISO 27001 4.1), including whether climate change is one."""
    __tablename__ = "isms_context_issues"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ici"))
    kind: Mapped[str] = mapped_column(String(20))  # internal | external
    description: Mapped[str] = mapped_column(Text)
    climate_related: Mapped[bool] = mapped_column(Boolean, default=False)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)


@tenant_table
class IsmsInterestedParty(_Row, Base):
    """An interested party and its requirements (ISO 27001 4.2), including climate related ones."""
    __tablename__ = "isms_interested_parties"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iip"))
    name: Mapped[str] = mapped_column(String(300))
    requirements: Mapped[str | None] = mapped_column(Text, nullable=True)
    climate_requirements: Mapped[str | None] = mapped_column(Text, nullable=True)
    addressed_by: Mapped[str | None] = mapped_column(Text, nullable=True)


@tenant_table
class IsmsAsset(_Row, Base):
    """An information asset, system, service, person, supplier or site, with its owner and classification."""
    __tablename__ = "isms_assets"
    __table_args__ = (UniqueConstraint("tenant_id", "type", "name", name="uq_isms_asset_name"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ias"))
    type: Mapped[str] = mapped_column(String(20))
    name: Mapped[str] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    classification: Mapped[str] = mapped_column(String(20), default="internal")
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class IsmsContentPack(Base):
    """One published version of a content pack (platform content, not tenant data; see ``library.py``)."""
    __tablename__ = "isms_content_packs"
    __table_args__ = (UniqueConstraint("pack_id", "pack_version", name="uq_isms_content_pack_version"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("icp"))
    pack_id: Mapped[str] = mapped_column(String(80), index=True)
    pack_version: Mapped[str] = mapped_column(String(20))
    kind: Mapped[str] = mapped_column(String(20))  # framework | control-library | templates
    framework: Mapped[str | None] = mapped_column(String(80), nullable=True)
    licence: Mapped[str] = mapped_column(String(120))
    data: Mapped[dict] = mapped_column(JSON)
    sha256: Mapped[str] = mapped_column(String(64))
    published_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


@tenant_table
class IsmsTenantFramework(_Row, Base):
    """A framework the customer runs, pinned to the pack version chosen (upgrades are reviewed, never automatic)."""
    __tablename__ = "isms_tenant_frameworks"
    __table_args__ = (UniqueConstraint("tenant_id", "framework", name="uq_isms_tenant_framework"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("itf"))
    framework: Mapped[str] = mapped_column(String(80))
    pack_id: Mapped[str] = mapped_column(String(80))
    pack_version: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(30), default="target_certification")  # in_scope | target_certification | certified
    target_date: Mapped[date | None] = mapped_column(Date, nullable=True)


@tenant_table
class IsmsProfileAnswer(_Row, Base):
    """An answer to an onboarding question, by the question's stable ref."""
    __tablename__ = "isms_profile_answers"
    __table_args__ = (UniqueConstraint("tenant_id", "question_ref", name="uq_isms_profile_answer"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ipa"))
    question_ref: Mapped[str] = mapped_column(String(80))
    value: Mapped[Any] = mapped_column(JSON)


@tenant_table
class IsmsApplicability(_Row, Base):
    """The applicability engine's decision for one requirement, control or template section, with its reason."""
    __tablename__ = "isms_applicability"
    __table_args__ = (UniqueConstraint("tenant_id", "target_type", "target_key", name="uq_isms_applicability"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iap"))
    target_type: Mapped[str] = mapped_column(String(20))  # requirement | control | template_section
    target_key: Mapped[str] = mapped_column(String(200))  # requirement: <framework>:<ref>; otherwise the ref
    applicable: Mapped[bool] = mapped_column(Boolean)
    source: Mapped[str] = mapped_column(String(20))  # default | mandatory | rule | override | derived
    rule_refs: Mapped[list] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(Text)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    locked: Mapped[bool] = mapped_column(Boolean, default=False)


@tenant_table
class IsmsApplicabilityOverride(_Row, Base):
    """A manual decision on applicability, always with a justification."""
    __tablename__ = "isms_applicability_overrides"
    __table_args__ = (UniqueConstraint("tenant_id", "target_type", "target_key", name="uq_isms_applicability_override"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iao"))
    target_type: Mapped[str] = mapped_column(String(20))
    target_key: Mapped[str] = mapped_column(String(200))
    applicable: Mapped[bool] = mapped_column(Boolean)
    justification: Mapped[str] = mapped_column(Text)
    set_by_control: Mapped[str | None] = mapped_column(String(40), nullable=True)  # from a "does not apply" answer


@tenant_table
class IsmsTenantControl(_Row, Base):
    """A control in the customer's programme: from the common control library, or one the customer added."""
    __tablename__ = "isms_tenant_controls"
    __table_args__ = (UniqueConstraint("tenant_id", "ref", name="uq_isms_tenant_control"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("itc"))
    ref: Mapped[str] = mapped_column(String(40))
    common: Mapped[bool] = mapped_column(Boolean, default=True)  # False for the customer's own controls
    test_procedure: Mapped[str | None] = mapped_column(Text, nullable=True)  # the customer's own controls
    title: Mapped[str] = mapped_column(String(300))
    statement: Mapped[str] = mapped_column(Text)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    state: Mapped[str] = mapped_column(String(30), default="not_started")
    frequency: Mapped[str | None] = mapped_column(String(30), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "Is this in place today?": yes | partly | no | not_relevant, and how it is done (shown in the SoA).
    assessment: Mapped[str | None] = mapped_column(String(20), nullable=True)
    implementation: Mapped[str | None] = mapped_column(Text, nullable=True)
    assessed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    assessed_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


@tenant_table
class IsmsRiskMethod(_Row, Base):
    """The customer's risk method (ISO 27001 6.1.2): scales, levels, appetite and acceptance criteria, versioned."""
    __tablename__ = "isms_risk_methods"
    __table_args__ = (UniqueConstraint("tenant_id", name="uq_isms_risk_method_tenant"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("irm"))
    likelihood_scale: Mapped[list] = mapped_column(JSON)
    impact_scale: Mapped[list] = mapped_column(JSON)
    levels: Mapped[list] = mapped_column(JSON)
    appetite: Mapped[int] = mapped_column(Integer)
    acceptance_criteria: Mapped[str] = mapped_column(Text)
    review_months: Mapped[int] = mapped_column(Integer, default=12)
    version: Mapped[int] = mapped_column(Integer, default=1)


@tenant_table
class IsmsRisk(_Row, Base):
    """An information security risk with its inherent and residual ratings and treatment (6.1.2, 6.1.3, 8.2, 8.3)."""
    __tablename__ = "isms_risks"
    __table_args__ = (UniqueConstraint("tenant_id", "ref", name="uq_isms_risk_ref"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("irk"))
    ref: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat: Mapped[str | None] = mapped_column(Text, nullable=True)
    vulnerability: Mapped[str | None] = mapped_column(Text, nullable=True)
    asset_ids: Mapped[list] = mapped_column(JSON, default=list)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    inherent_likelihood: Mapped[int | None] = mapped_column(Integer, nullable=True)
    inherent_impact: Mapped[int | None] = mapped_column(Integer, nullable=True)
    treatment: Mapped[str | None] = mapped_column(String(20), nullable=True)  # modify | retain | avoid | share
    treatment_plan: Mapped[str | None] = mapped_column(Text, nullable=True)
    residual_likelihood: Mapped[int | None] = mapped_column(Integer, nullable=True)
    residual_impact: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="identified")
    next_review: Mapped[date | None] = mapped_column(Date, nullable=True)


@tenant_table
class IsmsRiskControl(_Row, Base):
    """A control that treats a risk."""
    __tablename__ = "isms_risk_controls"
    __table_args__ = (UniqueConstraint("risk_id", "tenant_control_id", name="uq_isms_risk_control"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("irc"))
    risk_id: Mapped[str] = mapped_column(ForeignKey("isms_risks.id"), index=True)
    tenant_control_id: Mapped[str] = mapped_column(ForeignKey("isms_tenant_controls.id"), index=True)


@tenant_table
class IsmsRiskAcceptance(_Row, Base):
    """The risk owner's acceptance of a residual risk: who, when, at what score and why. A record of what happened,
    so the application only ever adds these."""
    __tablename__ = "isms_risk_acceptances"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ira"))
    risk_id: Mapped[str] = mapped_column(ForeignKey("isms_risks.id"), index=True)
    accepted_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    accepted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    residual_score: Mapped[int] = mapped_column(Integer)
    rationale: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[date | None] = mapped_column(Date, nullable=True)


@tenant_table
class IsmsRiskSnapshot(_Row, Base):
    """A dated copy of the whole risk assessment (8.2 evidence). Only ever added."""
    __tablename__ = "isms_risk_snapshots"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("irs"))
    taken_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    taken_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    reason: Mapped[str] = mapped_column(String(200), default="manual")
    payload: Mapped[dict] = mapped_column(JSON)


@tenant_table
class IsmsEvidence(_Row, Base):
    """Evidence that controls operate: an uploaded file (stored encrypted, virus scanned), a link, a note, or a result
    of Fenrir's automated GRC checks."""
    __tablename__ = "isms_evidence"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iev"))
    title: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(20))  # file | link | note | connector_result
    storage_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(80), default="upload")  # upload | fenrir:FC-BACKUP ...
    source_ref: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # Fenrir GRC evidence id
    passing: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # automated results only
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    valid_until: Mapped[date | None] = mapped_column(Date, nullable=True)
    scan_status: Mapped[str] = mapped_column(String(20), default="not_required")  # pending | clean | infected | failed | not_required
    scan_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    uploaded_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    expiry_notified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


@tenant_table
class IsmsEvidenceLink(_Row, Base):
    """Evidence for a control."""
    __tablename__ = "isms_evidence_links"
    __table_args__ = (UniqueConstraint("evidence_id", "tenant_control_id", name="uq_isms_evidence_link"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iel"))
    evidence_id: Mapped[str] = mapped_column(ForeignKey("isms_evidence.id"), index=True)
    tenant_control_id: Mapped[str] = mapped_column(ForeignKey("isms_tenant_controls.id"), index=True)


@tenant_table
class IsmsTask(_Row, Base):
    """A task (ISO 27001 8.1: planned processes ran): putting a control in place, operating it on its schedule, or
    anything people add. Reminder columns record each stage once."""
    __tablename__ = "isms_tasks"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("itk"))
    tenant_control_id: Mapped[str | None] = mapped_column(ForeignKey("isms_tenant_controls.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(20))  # implement | operate | manual
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    assignee_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    due_on: Mapped[date] = mapped_column(Date)
    recurrence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open | done | cancelled
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    completion_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("isms_evidence.id"), nullable=True)
    reminded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    overdue_notified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


@tenant_table
class IsmsDocument(_Row, Base):
    """A controlled document: generated from a template, or imported from Fenrir's older Governance policies."""
    __tablename__ = "isms_documents"
    __table_args__ = (UniqueConstraint("tenant_id", "doc_type", name="uq_isms_document_type"),
                      UniqueConstraint("tenant_id", "number", name="uq_isms_document_number"))
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("idc"))
    doc_type: Mapped[str] = mapped_column(String(80))  # template doc_type, or imported-<id> for an imported policy
    title: Mapped[str] = mapped_column(String(300))
    number: Mapped[str] = mapped_column(String(40))
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    owner_name: Mapped[str | None] = mapped_column(String(200), nullable=True)  # imported owners that are not users
    review_months: Mapped[int] = mapped_column(Integer, default=12)
    next_review: Mapped[date | None] = mapped_column(Date, nullable=True)
    classification: Mapped[str] = mapped_column(String(20), default="Internal")
    source: Mapped[str] = mapped_column(String(20), default="template")  # template | imported


DOCUMENT_CONTENT_COLUMNS = ("document_id", "version", "template_ref", "context_hash", "blocks", "html", "docx_name",
                            "pdf_name", "tenant_id")


@tenant_table
class IsmsDocumentVersion(_Row, Base):
    """One version of a document. Its content is frozen once it leaves draft (see the guard below): regenerating
    always makes a new draft and never touches an approved or published version."""
    __tablename__ = "isms_document_versions"
    __table_args__ = (UniqueConstraint("document_id", "version", name="uq_isms_document_version"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("idv"))
    document_id: Mapped[str] = mapped_column(ForeignKey("isms_documents.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(20), default="draft")  # draft | in_review | approved | published | superseded | withdrawn
    template_ref: Mapped[str] = mapped_column(String(120))
    context_hash: Mapped[str] = mapped_column(String(64))
    blocks: Mapped[list] = mapped_column(JSON)
    html: Mapped[str] = mapped_column(Text)
    docx_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pdf_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    final_docx_name: Mapped[str | None] = mapped_column(String(64), nullable=True)  # stamped with the approval
    final_pdf_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pdf_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    change_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    submitted_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    approved_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_by_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


@tenant_table
class IsmsDocumentOverride(_Row, Base):
    """The customer's own wording for one block of a document; it survives regeneration."""
    __tablename__ = "isms_document_overrides"
    __table_args__ = (UniqueConstraint("document_id", "block_ref", name="uq_isms_document_override"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ido"))
    document_id: Mapped[str] = mapped_column(ForeignKey("isms_documents.id"), index=True)
    block_ref: Mapped[str] = mapped_column(String(120))
    content: Mapped[str] = mapped_column(Text)


class FrozenDocumentVersion(RuntimeError):
    """An approved or published document version was about to be changed or deleted."""


def _guard_versions(session, _flush_context, _instances) -> None:
    from sqlalchemy import inspect as sa_inspect

    for obj in list(session.dirty) + list(session.deleted):
        if not isinstance(obj, IsmsDocumentVersion):
            continue
        state = sa_inspect(obj)
        before = state.attrs.state.history
        was = (before.deleted or [obj.state])[0] if before.has_changes() else obj.state
        if was == "draft":
            continue
        if obj in session.deleted:
            raise FrozenDocumentVersion("Document versions that have left draft cannot be deleted.")
        changed = [c for c in DOCUMENT_CONTENT_COLUMNS if state.attrs[c].history.has_changes()]
        if changed:
            raise FrozenDocumentVersion(f"A {was} document version cannot be changed ({', '.join(changed)}).")


from sqlalchemy import event as _event  # noqa: E402
from sqlalchemy.orm import Session as _Session  # noqa: E402

_event.listen(_Session, "before_flush", _guard_versions)


@tenant_table
class IsmsLegacyAnswer(_Row, Base):
    """An answer from Fenrir's earlier Governance programmes, kept read-only beside the Statement of Applicability.
    ``refs`` are the ISMS requirements it was matched to (empty when nothing matches)."""
    __tablename__ = "isms_legacy_answers"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ila"))
    framework: Mapped[str] = mapped_column(String(80))  # ISMS framework slug
    source_framework: Mapped[str] = mapped_column(String(80))  # Fenrir framework key
    source_ref: Mapped[str] = mapped_column(String(80))
    refs: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20))
    answer: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    na_reason: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(200), default="")
    answered_by: Mapped[str] = mapped_column(String(200), default="")
    answered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


@tenant_table
class IsmsImport(_Row, Base):
    """What was moved from Fenrir's earlier Governance records, so the move can run again without duplicating."""
    __tablename__ = "isms_imports"
    __table_args__ = (UniqueConstraint("tenant_id", "source_table", "source_id", name="uq_isms_import_source"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iim"))
    source_table: Mapped[str] = mapped_column(String(60))
    source_id: Mapped[str] = mapped_column(String(64))
    target_table: Mapped[str] = mapped_column(String(60))
    target_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")


@tenant_table
class IsmsNonconformity(_Row, Base):
    """A nonconformity (ISO 27001 10.2) or an improvement opportunity (10.1). Never deleted, only cancelled."""
    __tablename__ = "isms_nonconformities"
    __table_args__ = (UniqueConstraint("tenant_id", "ref", name="uq_isms_nonconformity_ref"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("inc"))
    ref: Mapped[str] = mapped_column(String(20))  # NC-001 or OFI-001
    kind: Mapped[str] = mapped_column(String(20), default="nonconformity")  # nonconformity | opportunity
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(30))
    severity: Mapped[str | None] = mapped_column(String(10), nullable=True)  # minor | major (nonconformities)
    requirement_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)
    raised_on: Mapped[date] = mapped_column(Date)
    raised_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    correction: Mapped[str] = mapped_column(Text, default="")
    root_cause: Mapped[str] = mapped_column(Text, default="")
    due_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open | closed | cancelled
    effectiveness_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    effective: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verified_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    closure_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    audit_finding_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # raised from an audit finding


@tenant_table
class IsmsCorrectiveAction(_Row, Base):
    __tablename__ = "isms_corrective_actions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ica"))
    nonconformity_id: Mapped[str] = mapped_column(ForeignKey("isms_nonconformities.id"), index=True)
    description: Mapped[str] = mapped_column(Text)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    due_on: Mapped[date] = mapped_column(Date)
    done_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    done_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    done_note: Mapped[str | None] = mapped_column(Text, nullable=True)


@tenant_table
class IsmsObjective(_Row, Base):
    """An information security objective with its measure and target (ISO 27001 6.2, 9.1)."""
    __tablename__ = "isms_objectives"
    __table_args__ = (UniqueConstraint("tenant_id", "ref", name="uq_isms_objective_ref"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iob"))
    ref: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    measure: Mapped[str] = mapped_column(Text)
    unit: Mapped[str] = mapped_column(String(40), default="")
    direction: Mapped[str] = mapped_column(String(10))  # at_least | at_most
    target: Mapped[float] = mapped_column(Float)
    baseline: Mapped[float | None] = mapped_column(Float, nullable=True)
    plan: Mapped[str] = mapped_column(Text, default="")
    resources: Mapped[str] = mapped_column(Text, default="")
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    frequency: Mapped[str] = mapped_column(String(20), default="monthly")
    due_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | achieved | dropped
    status_note: Mapped[str | None] = mapped_column(Text, nullable=True)


@tenant_table
class IsmsMetricValue(_Row, Base):
    __tablename__ = "isms_metric_values"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("imv"))
    objective_id: Mapped[str] = mapped_column(ForeignKey("isms_objectives.id"), index=True)
    measured_on: Mapped[date] = mapped_column(Date)
    value: Mapped[float] = mapped_column(Float)
    note: Mapped[str] = mapped_column(Text, default="")


@tenant_table
class IsmsChange(_Row, Base):
    """A planned change to the ISMS (ISO 27001 6.3)."""
    __tablename__ = "isms_changes"
    __table_args__ = (UniqueConstraint("tenant_id", "ref", name="uq_isms_change_ref"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ich"))
    ref: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    purpose: Mapped[str] = mapped_column(Text)
    consequences: Mapped[str] = mapped_column(Text, default="")
    resources: Mapped[str] = mapped_column(Text, default="")
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    planned_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="planned")  # planned | in_progress | done | cancelled
    completed_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    outcome: Mapped[str] = mapped_column(Text, default="")


@tenant_table
class IsmsAuditProgramme(_Row, Base):
    """An internal audit programme for a period (ISO 27001 9.2)."""
    __tablename__ = "isms_audit_programmes"
    __table_args__ = (UniqueConstraint("tenant_id", "title", name="uq_isms_audit_programme_title"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iap"))
    title: Mapped[str] = mapped_column(String(160))
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    objectives: Mapped[str] = mapped_column(Text, default="")


@tenant_table
class IsmsAudit(_Row, Base):
    """One internal audit. A completed audit is a record and never changes (see the guard below)."""
    __tablename__ = "isms_audits"
    __table_args__ = (UniqueConstraint("tenant_id", "ref", name="uq_isms_audit_ref"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iau"))
    programme_id: Mapped[str] = mapped_column(ForeignKey("isms_audit_programmes.id"), index=True)
    ref: Mapped[str] = mapped_column(String(20))  # AUD-001
    title: Mapped[str] = mapped_column(String(160))
    scope: Mapped[str] = mapped_column(Text, default="")
    frameworks: Mapped[list[str]] = mapped_column(JSON, default=list)
    planned_start: Mapped[date] = mapped_column(Date)
    planned_end: Mapped[date] = mapped_column(Date)
    lead_auditor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    other_auditors: Mapped[str] = mapped_column(Text, default="")
    independence_note: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="planned")  # planned | in_progress | completed
    summary: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


@tenant_table
class IsmsAuditCheck(_Row, Base):
    """A checklist item: a snapshot of one requirement at generation time, with the auditor's result."""
    __tablename__ = "isms_audit_checks"
    __table_args__ = (UniqueConstraint("audit_id", "framework", "requirement_ref", name="uq_isms_audit_check"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iak"))
    audit_id: Mapped[str] = mapped_column(ForeignKey("isms_audits.id"), index=True)
    framework: Mapped[str] = mapped_column(String(80))
    requirement_ref: Mapped[str] = mapped_column(String(80))
    requirement_title: Mapped[str] = mapped_column(String(300))
    group_title: Mapped[str] = mapped_column(String(300), default="")
    mandatory: Mapped[bool] = mapped_column(Boolean, default=False)
    controls: Mapped[str] = mapped_column(Text, default="")
    sort: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[str | None] = mapped_column(String(20), nullable=True)  # conforms | observation | minor | major | not_assessed
    notes: Mapped[str] = mapped_column(Text, default="")
    evidence_seen: Mapped[str] = mapped_column(Text, default="")
    checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    checked_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class CompletedAudit(RuntimeError):
    """A completed audit, or its checklist, was about to change."""


def _guard_audits(session, _flush_context, _instances) -> None:
    from sqlalchemy import inspect as sa_inspect

    for obj in list(session.new) + list(session.dirty) + list(session.deleted):
        if isinstance(obj, IsmsAudit) and obj not in session.new:
            hist = sa_inspect(obj).attrs.status.history
            was = (hist.deleted or [obj.status])[0] if hist.has_changes() else obj.status
            if was == "completed" and (obj in session.deleted or session.is_modified(obj)):
                raise CompletedAudit("A completed audit cannot change.")
            if obj in session.deleted and was != "planned":
                raise CompletedAudit("Only a planned audit can be deleted.")
        elif isinstance(obj, IsmsAuditCheck):
            parent = session.get(IsmsAudit, obj.audit_id)
            if parent is not None:
                hist = sa_inspect(parent).attrs.status.history
                was = (hist.deleted or [parent.status])[0] if hist.has_changes() else parent.status
                if was == "completed":
                    raise CompletedAudit("The audit is completed; its checklist cannot change.")


_event.listen(_Session, "before_flush", _guard_audits)


@tenant_table
class IsmsOrgRole(_Row, Base):
    """A named ISMS role with its responsibilities and authorities (ISO 27001 5.3), such as information security
    lead. Separate from ``IsmsMembership``, which decides what a person can do in Fenrir."""
    __tablename__ = "isms_org_roles"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_isms_org_role_name"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ior"))
    name: Mapped[str] = mapped_column(String(120))
    responsibilities: Mapped[str] = mapped_column(Text, default="")
    authorities: Mapped[str] = mapped_column(Text, default="")
    sort: Mapped[int] = mapped_column(Integer, default=0)


@tenant_table
class IsmsOrgRoleHolder(_Row, Base):
    __tablename__ = "isms_org_role_holders"
    __table_args__ = (UniqueConstraint("role_id", "user_id", name="uq_isms_org_role_holder"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("irh"))
    role_id: Mapped[str] = mapped_column(ForeignKey("isms_org_roles.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))


@tenant_table
class IsmsRaciActivity(_Row, Base):
    __tablename__ = "isms_raci_activities"
    __table_args__ = (UniqueConstraint("tenant_id", "title", name="uq_isms_raci_activity"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ira"))
    title: Mapped[str] = mapped_column(String(160))
    sort: Mapped[int] = mapped_column(Integer, default=0)


@tenant_table
class IsmsRaciAssignment(_Row, Base):
    __tablename__ = "isms_raci_assignments"
    __table_args__ = (UniqueConstraint("activity_id", "role_id", name="uq_isms_raci_cell"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("irc"))
    activity_id: Mapped[str] = mapped_column(ForeignKey("isms_raci_activities.id"), index=True)
    role_id: Mapped[str] = mapped_column(ForeignKey("isms_org_roles.id"), index=True)
    letter: Mapped[str] = mapped_column(String(1))  # R | A | C | I


@tenant_table
class IsmsCompetence(_Row, Base):
    """A training, qualification, experience or awareness record for one person (ISO 27001 7.2, 7.3)."""
    __tablename__ = "isms_competence"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("icp"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # training | qualification | experience | awareness
    title: Mapped[str] = mapped_column(String(200))
    achieved_on: Mapped[date] = mapped_column(Date)
    expires_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    evidence_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")


@tenant_table
class IsmsAckCampaign(_Row, Base):
    """A request for people with an ISMS role to read and acknowledge one published document version."""
    __tablename__ = "isms_ack_campaigns"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iac"))
    document_version_id: Mapped[str] = mapped_column(ForeignKey("isms_document_versions.id"), index=True)
    audience_roles: Mapped[list[str]] = mapped_column(JSON, default=list)  # ISMS roles asked; empty means everyone
    due_on: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(10), default="open")  # open | closed
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_reminded_on: Mapped[date | None] = mapped_column(Date, nullable=True)


@tenant_table
class IsmsAcknowledgement(Base):
    """One person's acknowledgement of a campaign's document version. Append-only (see the guard below)."""
    __tablename__ = "isms_acknowledgements"
    __table_args__ = (UniqueConstraint("campaign_id", "user_id", name="uq_isms_acknowledgement"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iag"))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("isms_ack_campaigns.id"), index=True)
    document_version_id: Mapped[str] = mapped_column(ForeignKey("isms_document_versions.id"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    content_sha256: Mapped[str] = mapped_column(String(64))  # of the text that was shown
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(300), default="")
    via: Mapped[str] = mapped_column(String(10), default="console")  # console | portal


class AcknowledgementsAreFinal(RuntimeError):
    """An acknowledgement was about to be changed or deleted."""


def _guard_acknowledgements(session, _flush_context, _instances) -> None:
    for obj in list(session.dirty) + list(session.deleted):
        if isinstance(obj, IsmsAcknowledgement) and (obj in session.deleted or session.is_modified(obj)):
            raise AcknowledgementsAreFinal("Acknowledgements cannot be changed or deleted.")


_event.listen(_Session, "before_flush", _guard_acknowledgements)


@tenant_table
class IsmsManagementReview(_Row, Base):
    """A management review (ISO 27001 9.3). Its pack is built from live data; recording the meeting freezes the pack,
    minutes and decisions (see the guard below). Actions can still be added and completed afterwards."""
    __tablename__ = "isms_management_reviews"
    __table_args__ = (UniqueConstraint("tenant_id", "ref", name="uq_isms_management_review_ref"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("imr"))
    ref: Mapped[str] = mapped_column(String(20))  # MR-001
    title: Mapped[str] = mapped_column(String(200))
    planned_on: Mapped[date] = mapped_column(Date)
    period_start: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(10), default="draft")  # draft | held
    pack: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    pack_built_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    interested_party_feedback: Mapped[str] = mapped_column(Text, default="")
    held_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    chair_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    attendees: Mapped[str] = mapped_column(Text, default="")
    minutes: Mapped[str] = mapped_column(Text, default="")
    decisions: Mapped[str] = mapped_column(Text, default="")
    changes_needed: Mapped[str] = mapped_column(Text, default="")
    recorded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    recorded_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


@tenant_table
class IsmsReviewAction(_Row, Base):
    __tablename__ = "isms_review_actions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ima"))
    review_id: Mapped[str] = mapped_column(ForeignKey("isms_management_reviews.id"), index=True)
    description: Mapped[str] = mapped_column(Text)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    due_on: Mapped[date] = mapped_column(Date)
    done_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    done_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    done_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class HeldReview(RuntimeError):
    """A held management review was about to change or be deleted."""


def _guard_reviews(session, _flush_context, _instances) -> None:
    from sqlalchemy import inspect as sa_inspect

    for obj in list(session.dirty) + list(session.deleted):
        if not isinstance(obj, IsmsManagementReview):
            continue
        hist = sa_inspect(obj).attrs.status.history
        was = (hist.deleted or [obj.status])[0] if hist.has_changes() else obj.status
        if was == "held" and (obj in session.deleted or session.is_modified(obj)):
            raise HeldReview("A held management review cannot change.")


_event.listen(_Session, "before_flush", _guard_reviews)


@tenant_table
class IsmsAuditSample(_Row, Base):
    """A sample an auditor drew from a live population, kept so it can be reproduced and reviewed."""
    __tablename__ = "isms_audit_samples"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ias"))
    population: Mapped[str] = mapped_column(String(30))
    size: Mapped[int] = mapped_column(Integer)
    seed: Mapped[str] = mapped_column(String(200))
    population_size: Mapped[int] = mapped_column(Integer)
    items: Mapped[list] = mapped_column(JSON)
    note: Mapped[str] = mapped_column(Text, default="")
    created_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)


@tenant_table
class IsmsEvidenceRequest(_Row, Base):
    """An auditor's request for evidence, answered by the control's owner or an ISMS manager."""
    __tablename__ = "isms_evidence_requests"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ier"))
    tenant_control_id: Mapped[str | None] = mapped_column(ForeignKey("isms_tenant_controls.id"), nullable=True)
    request: Mapped[str] = mapped_column(Text)
    due_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(10), default="open")  # open | answered | closed
    response: Mapped[str] = mapped_column(Text, default="")
    evidence_id: Mapped[str | None] = mapped_column(ForeignKey("isms_evidence.id"), nullable=True)
    requested_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    answered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    answered_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


@tenant_table
class IsmsSupplierLink(_Row, Base):
    """Links a Fenrir third-party risk supplier (``tprm_vendors``) to the ISMS assets, risks and controls it touches."""
    __tablename__ = "isms_supplier_links"
    __table_args__ = (UniqueConstraint("vendor_id", "target_type", "target_id", name="uq_isms_supplier_link"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("isl"))
    vendor_id: Mapped[str] = mapped_column(ForeignKey("tprm_vendors.id"), index=True)
    target_type: Mapped[str] = mapped_column(String(10))  # asset | risk | control
    target_id: Mapped[str] = mapped_column(String(32))


@tenant_table
class IsmsIncidentReview(_Row, Base):
    """The ISMS view of a Fenrir SOC incident (ISO 27001 A.5.24 to A.5.28): category, personal data, regulator
    notice, root cause, lessons learned and the controls involved. The SOC keeps running the incident itself."""
    __tablename__ = "isms_incident_reviews"
    __table_args__ = (UniqueConstraint("incident_id", name="uq_isms_incident_review"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("iir"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    category: Mapped[str] = mapped_column(String(30), default="other")
    personal_data: Mapped[bool] = mapped_column(Boolean, default=False)
    reported_to_authority_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    vendor_id: Mapped[str | None] = mapped_column(ForeignKey("tprm_vendors.id"), nullable=True)
    root_cause: Mapped[str] = mapped_column(Text, default="")
    lessons_learned: Mapped[str] = mapped_column(Text, default="")
    control_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(10), default="open")  # open | complete
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


@tenant_table
class IsmsControlRequirement(_Row, Base):
    """Links one of the customer's own controls (CUST-001) to a requirement of a framework in its programme, so the
    control counts in the Statement of Applicability, readiness and audit checklists."""
    __tablename__ = "isms_control_requirements"
    __table_args__ = (UniqueConstraint("tenant_control_id", "framework", "requirement_ref",
                                       name="uq_isms_control_requirement"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("icq"))
    tenant_control_id: Mapped[str] = mapped_column(ForeignKey("isms_tenant_controls.id"), index=True)
    framework: Mapped[str] = mapped_column(String(80))
    requirement_ref: Mapped[str] = mapped_column(String(80))


@tenant_table
class IsmsDashboardLayout(_Row, Base):
    """The tiles one person chose for their ISMS dashboard in one customer, in order."""
    __tablename__ = "isms_dashboard_layouts"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="uq_isms_dashboard_layout"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("idl"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    tiles: Mapped[list[str]] = mapped_column(JSON, default=list)


@tenant_table
class IsmsDigestSubscription(_Row, Base):
    """An email digest of the same tiles, weekly (Mondays) or monthly (the 1st), at 07:00 UTC."""
    __tablename__ = "isms_digest_subscriptions"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="uq_isms_digest_subscription"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ids"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    frequency: Mapped[str] = mapped_column(String(10))  # weekly | monthly
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_send_at: Mapped[datetime] = mapped_column(DateTime)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
