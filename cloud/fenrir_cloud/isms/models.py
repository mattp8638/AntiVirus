"""ISMS tables. Every table holding tenant data is registered with ``@tenant_table`` (see ``scope.py``)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
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
