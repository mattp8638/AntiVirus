"""Two-person approval for high-impact actions (CORE-15).

Off by default. A customer (or the MSP above it) can require a second person for destructive device actions and for
scripts or bulk actions that reach at least a threshold of devices. The first request is held and answered with
202 and an approval id; a different user with the "approve" permission over every target decides, after a fresh
password check. The requester then resends the request with that id: it runs only if it is still exactly the
request that was approved (same body, same resolved devices), within an hour of approval, and only once.
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from . import audit
from .models import ApprovalRequest, Device, Tenant, utcnow

PENDING_FOR = timedelta(hours=24)
VALID_AFTER_APPROVAL = timedelta(hours=1)
DEFAULT_THRESHOLD = 25


class ApprovalRequired(Exception):
    def __init__(self, request: ApprovalRequest):
        self.request = request

    def response(self) -> JSONResponse:
        return JSONResponse(status_code=202, content={"approvalRequired": True, "approval": view(self.request),
                                                      "detail": "This needs a second person's approval. Resend it with approvalId once approved."})


def policy_for(db: Session, tenant_id: str) -> dict:
    """The nearest tenant (customer, then its MSP ancestors) with an approval policy decides."""
    tenant = db.get(Tenant, tenant_id)
    seen = set()
    while tenant is not None and tenant.id not in seen:
        seen.add(tenant.id)
        policy = (tenant.settings or {}).get("approvals")
        if isinstance(policy, dict) and policy.get("twoPerson"):
            return {"twoPerson": True, "bulkThreshold": max(1, int(policy.get("bulkThreshold") or DEFAULT_THRESHOLD)), "tenantId": tenant.id}
        tenant = db.get(Tenant, tenant.parent_id) if tenant.parent_id else None
    return {"twoPerson": False}


def fingerprint(kind: str, request: dict, device_ids: list[str]) -> str:
    canonical = json.dumps({"kind": kind, "request": {k: v for k, v in request.items() if k not in ("approvalId", "_route")},
                            "devices": sorted(device_ids)}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def needed(db: Session, devices: list[Device], destructive: bool) -> bool:
    for tenant_id in {d.tenant_id for d in devices}:
        policy = policy_for(db, tenant_id)
        if policy["twoPerson"] and (destructive or len(devices) >= policy["bulkThreshold"]):
            return True
    return False


def gate(db: Session, principal, kind: str, summary: str, request: dict, devices: list[Device], destructive: bool = False,
         route: str = "") -> None:
    """Return to let the action run; raise ApprovalRequired (202) to hold it."""
    if not devices or not needed(db, devices, destructive):
        return
    device_ids = [d.id for d in devices]
    print_ = fingerprint(kind, request, device_ids)
    now = utcnow()
    approval_id = request.get("approvalId")
    if approval_id:
        row = db.get(ApprovalRequest, str(approval_id))
        if row is None or row.requested_by != principal.actor or row.kind != kind:
            raise HTTPException(404, "Approval not found")
        if row.status != "approved":
            raise HTTPException(409, f"This request is {row.status}, not approved")
        if row.expires_at <= now:
            row.status = "expired"
            db.commit()
            raise HTTPException(409, "The approval has expired; ask again")
        if row.fingerprint != print_:
            raise HTTPException(409, "The request changed since it was approved (body or target devices); it needs a new approval")
        row.status, row.executed_at = "executed", now
        audit.record(db, principal.actor, "approval.executed", row.id, row.tenant_id, kind=kind)
        return
    tenant_ids = sorted({d.tenant_id for d in devices})
    row = ApprovalRequest(tenant_id=tenant_ids[0], kind=kind, summary=summary[:500], fingerprint=print_,
                          request={**{k: v for k, v in request.items() if k != "approvalId"}, "_route": route}, device_ids=device_ids,
                          requested_by=principal.actor, expires_at=now + PENDING_FOR)
    db.add(row)
    db.flush()
    audit.record(db, principal.actor, "approval.requested", row.id, row.tenant_id, kind=kind, devices=len(device_ids), summary=row.summary)
    db.commit()
    raise ApprovalRequired(row)


def decide(db: Session, principal, row: ApprovalRequest, approve: bool, reason: str) -> ApprovalRequest:
    now = utcnow()
    if row.status != "pending":
        raise HTTPException(409, f"This request is already {row.status}")
    if row.expires_at <= now:
        row.status = "expired"
        raise HTTPException(409, "This request expired before anyone decided")
    if row.requested_by == principal.actor:
        raise HTTPException(403, "Someone other than the requester has to decide")
    targets = [db.get(Device, i) for i in row.device_ids]
    if any(d is None or d.tenant_id not in principal.tenant_ids for d in targets):
        raise HTTPException(403, "You cannot decide on devices outside your customers")
    row.status = "approved" if approve else "rejected"
    row.decided_by, row.decided_at, row.reason = principal.actor, now, reason[:500]
    if approve:
        row.expires_at = now + VALID_AFTER_APPROVAL
    audit.record(db, principal.actor, f"approval.{row.status}", row.id, row.tenant_id, kind=row.kind, requestedBy=row.requested_by, reason=reason)
    return row


def view(row: ApprovalRequest) -> dict:
    iso = lambda d: d.isoformat() + "Z" if d else None  # noqa: E731
    return {"id": row.id, "tenantId": row.tenant_id, "kind": row.kind, "summary": row.summary, "devices": len(row.device_ids or []),
            "request": row.request, "requestedBy": row.requested_by, "requestedAt": iso(row.requested_at), "status": row.status,
            "decidedBy": row.decided_by, "decidedAt": iso(row.decided_at), "reason": row.reason, "expiresAt": iso(row.expires_at),
            "executedAt": iso(row.executed_at)}
