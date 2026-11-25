"""ISMS tables. Every table holding tenant data is registered with ``@tenant_table`` (see ``scope.py``)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
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
