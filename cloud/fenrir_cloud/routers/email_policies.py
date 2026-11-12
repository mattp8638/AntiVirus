"""Email security policies: view, save (a new version each time), compare, restore, and test a draft on a real message.

Reading needs ``respond``; saving needs ``configure``. A customer's policy can only be seen and changed by users who
can see that customer; the MSP default (on the MSP's own tenant) only by MSP staff.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import email_content, email_policy, email_security
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import EmailPolicyVersion, EmailScan, Tenant
from .documentation import owned

router = APIRouter(prefix="/api/console/email-security", tags=["Email security policies"])


class PolicyIn(BaseModel):
    document: dict | None = None
    comment: str = Field(default="", max_length=500)
    preset: str = ""
    inherit: bool = False


class TestIn(BaseModel):
    scanId: str
    document: dict | None = None


def _version_view(row: EmailPolicyVersion) -> dict:
    return {"id": row.id, "version": row.version, "createdBy": row.created_by, "createdAt": row.created_at.isoformat() + "Z",
            "comment": row.comment, "preset": row.preset, "inherit": row.inherit}


@router.get("/policy-schema")
def schema(principal: Principal = Depends(current_principal)):
    """What the policy editor offers: presets, rule fields and operators, actions and classifications."""
    principal.require("respond")
    return {"presets": {k: v for k, v in email_policy.PRESETS.items()}, "fields": email_policy.RULE_FIELDS,
            "operators": list(email_policy.OPERATORS), "ruleActions": list(email_policy.RULE_ACTIONS),
            "actions": list(email_policy.ACTIONS), "classes": list(email_policy.CLASSES),
            "defaultBlockedTypes": email_policy.DEFAULT_BLOCKED_TYPES}


@router.get("/policy/{tenant_id}")
def get_policy(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The policy in force for this customer (or the MSP default), where it comes from, and this scope's history."""
    principal.require("respond")
    principal.check_tenant(tenant_id)
    document, meta = email_policy.resolve(db, tenant_id)
    tenant = db.get(Tenant, tenant_id)
    own = db.execute(select(EmailPolicyVersion).where(EmailPolicyVersion.tenant_id == tenant_id)
                     .order_by(EmailPolicyVersion.version.desc()).limit(100)).scalars().all()
    source = db.get(Tenant, meta["tenantId"]) if meta.get("tenantId") else None
    return {"tenantId": tenant_id, "tenantName": tenant.name if tenant else "", "document": document,
            "effective": {**meta, "sourceName": source.name if source else "Built-in Standard preset"},
            "isRoot": bool(tenant and not tenant.parent_id), "versions": [_version_view(r) for r in own]}


@router.put("/policy/{tenant_id}")
def save_policy(tenant_id: str, body: PolicyIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Save a new version. Earlier versions stay, so any change can be compared and undone."""
    principal.require("configure")
    principal.check_tenant(tenant_id)
    try:
        row = email_policy.save(db, tenant_id, body.document, principal.actor, body.comment, body.preset, body.inherit)
    except email_policy.PolicyError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return {**_version_view(row), "document": row.document}


@router.get("/policy/{tenant_id}/versions/{version}")
def get_version(tenant_id: str, version: int, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    principal.check_tenant(tenant_id)
    row = db.execute(select(EmailPolicyVersion).where(EmailPolicyVersion.tenant_id == tenant_id,
                                                      EmailPolicyVersion.version == version)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "No such version")
    previous = db.execute(select(EmailPolicyVersion).where(EmailPolicyVersion.tenant_id == tenant_id,
                                                           EmailPolicyVersion.version < version)
                          .order_by(EmailPolicyVersion.version.desc()).limit(1)).scalar_one_or_none()
    return {**_version_view(row), "document": row.document,
            "changes": email_policy.diff(previous.document if previous else {}, row.document) if not row.inherit else []}


@router.post("/policy/{tenant_id}/versions/{version}/restore")
def restore_version(tenant_id: str, version: int, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Make an earlier version current again, as a new version (history is never rewritten)."""
    principal.require("configure")
    principal.check_tenant(tenant_id)
    old = db.execute(select(EmailPolicyVersion).where(EmailPolicyVersion.tenant_id == tenant_id,
                                                      EmailPolicyVersion.version == version)).scalar_one_or_none()
    if old is None:
        raise HTTPException(404, "No such version")
    row = email_policy.save(db, tenant_id, old.document, principal.actor, f"Restored version {version}", inherit=old.inherit)
    db.commit()
    return {**_version_view(row), "document": row.document}


@router.post("/policy/test")
def test_policy(body: TestIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run a stored message through a draft policy (or the one in force) and show what would happen, step by step.
    Changes nothing."""
    principal.require("respond")
    scan = owned(db, EmailScan, body.scanId, principal)
    if body.document is not None:
        try:
            document = email_policy.validate(body.document)
        except email_policy.PolicyError as exc:
            raise HTTPException(400, str(exc)) from None
        meta = {"version": "draft"}
    else:
        document, meta = email_policy.resolve(db, scan.tenant_id)
    message, result, info = rebuild(db, scan)
    decision = email_policy.decide(message, result, document, info, meta)
    return {"decision": decision, "current": (scan.details or {}).get("decision")}


def rebuild(db: Session, scan: EmailScan) -> tuple[email_security.Message, dict, dict]:
    """A stored scan as the message, analysis and facts the policy engine needs (the body only if it was kept)."""
    from .. import email_scan

    details = scan.details or {}
    headers = {str(k).lower(): str(v) for k, v in details.get("headers") or []}
    content = None
    try:
        content = email_content.stored(db, scan)
    except Exception:  # noqa: BLE001 - a body that cannot be decrypted is simply not used
        content = None
    attachments = list((details.get("attachments") or scan.attachments) or [])
    message = email_security.Message(
        mailbox=scan.mailbox, folder=scan.folder, sender_address=scan.sender_address, sender_name=scan.sender_name,
        reply_to=list((details.get("addresses") or {}).get("replyTo") or []), subject=scan.subject, headers=headers,
        body_html=(content or {}).get("html", ""), attachments=attachments)
    result = {"verdict": scan.verdict, "score": scan.score, "reasons": scan.reasons or [], "sender_domain": scan.sender_domain,
              "link_domains": scan.link_domains or [], "microsoft": {**(scan.microsoft or {}), "verdict": scan.microsoft_verdict}}
    from .. import mail_gateway
    from ..models import EmailGatewayDomain

    own = mail_gateway.verified_domains(db, scan.tenant_id) | {
        d for (d,) in db.execute(select(EmailGatewayDomain.domain).where(EmailGatewayDomain.tenant_id == scan.tenant_id))}
    info = {"gateway": (scan.source or "graph") == "gateway", "ip": (details.get("origin") or {}).get("ip", ""),
            "recipients": scan.recipients or [scan.mailbox], "size": details.get("size") or 0, "ownDomains": own,
            "lists": email_scan.list_entries(db, scan.tenant_id), "details": details,
            "dmarcPolicy": (scan.microsoft or {}).get("dmarcPolicy", "")}
    return message, result, info
