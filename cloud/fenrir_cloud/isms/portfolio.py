"""Portfolio: headline ISMS figures for every customer the person runs or reads an ISMS for (an MSP's view).

Only customers where the person holds an ISMS role that can see controls are included (plan decision R7: ISMS
access is per person per customer, MSP staff included). Each customer is read on its own; nothing is combined
across customers except the list itself.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Tenant, User, utcnow
from .access import can
from .memberships import active_role
from .models import IsmsDocument, IsmsEvidenceRequest, IsmsMembership, IsmsNonconformity, IsmsTask


def customer_summary(db: Session, tenant_id: str) -> dict:
    from . import audits, programme, risk_register

    today = utcnow().date()
    ready = programme.readiness(db, tenant_id)
    first = ready[0] if ready else None
    names = {f["framework"]: f["name"] for f in programme.framework_options(db, tenant_id)} if first else {}
    count = lambda q: db.execute(q).scalar() or 0  # noqa: E731
    risks = [r for r in risk_register.risk_views(db, tenant_id) if r["status"] != "closed"]
    return {
        "framework": names.get(first["framework"], first["framework"]) if first else None,
        "readiness": first["score"] if first else None,
        "overdueTasks": count(select(func.count()).select_from(IsmsTask).where(
            IsmsTask.tenant_id == tenant_id, IsmsTask.status == "open", IsmsTask.due_on < today)),
        "openNonconformities": count(select(func.count()).select_from(IsmsNonconformity).where(
            IsmsNonconformity.tenant_id == tenant_id, IsmsNonconformity.kind == "nonconformity",
            IsmsNonconformity.status == "open")),
        "risksAboveAppetite": sum(1 for r in risks if not r["withinAppetite"] and
                                  (r["residualScore"] or r["inherentScore"]) is not None),
        "documentsDueForReview": count(select(func.count()).select_from(IsmsDocument).where(
            IsmsDocument.tenant_id == tenant_id, IsmsDocument.next_review < today)),
        "openEvidenceRequests": count(select(func.count()).select_from(IsmsEvidenceRequest).where(
            IsmsEvidenceRequest.tenant_id == tenant_id, IsmsEvidenceRequest.status == "open")),
        "nextAudit": audits.next_audit(db, tenant_id),
    }


def portfolio(db: Session, user: User, tenant_ids) -> list[dict]:
    held = db.execute(select(IsmsMembership.tenant_id).where(IsmsMembership.user_id == user.id)).scalars().all()
    out = []
    for tid in sorted(set(held) & set(tenant_ids)):
        role = active_role(db, user, tid)
        if not can(role, "controls.view"):
            continue
        tenant = db.get(Tenant, tid)
        out.append({"tenantId": tid, "name": tenant.name if tenant else tid, "role": role,
                    "canManage": can(role, "programme.manage"), **customer_summary(db, tid)})
    return sorted(out, key=lambda x: x["name"].lower())
