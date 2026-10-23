"""Revision history for the existing knowledge base."""
from sqlalchemy import select
from .models import DocumentRevision

TEMPLATES = [
    {"id": "runbook", "title": "Service runbook", "category": "Runbooks", "body": "Purpose\n\nOwner and escalation\n\nPrerequisites\n\nProcedure\n\nValidation\n\nRollback\n"},
    {"id": "customer", "title": "Customer overview", "category": "Customers", "body": "Contacts and escalation\n\nSites and services\n\nSupport hours\n\nDependencies\n\nRecovery priorities\n"},
    {"id": "recovery", "title": "Recovery procedure", "category": "Recovery", "body": "Service and owner\n\nRPO / RTO\n\nBackup location (link to vault, never paste secrets)\n\nRecovery steps\n\nValidation and evidence\n"},
]

def snapshot(db, article, actor):
    db.flush()
    data = {key: getattr(article, key) for key in ("title", "body", "category", "tags", "public")}
    latest = db.execute(select(DocumentRevision).where(DocumentRevision.article_id == article.id)
                        .order_by(DocumentRevision.created_at.desc(), DocumentRevision.id.desc()).limit(1)).scalar_one_or_none()
    if latest is None or latest.snapshot != data:
        db.add(DocumentRevision(article_id=article.id, tenant_id=article.tenant_id, snapshot=data, author=actor))
