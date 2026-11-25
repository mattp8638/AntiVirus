"""ISMS tables. Every table holding tenant data is registered with ``@tenant_table`` (see ``scope.py``)."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
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
