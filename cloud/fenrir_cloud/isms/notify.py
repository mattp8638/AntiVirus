"""ISMS events for webhooks. They go through Fenrir's durable webhook outbox (``services.fire_webhooks``), so they
are retried, signed and shown with every other webhook under Settings.

Bodies carry identifiers, references, titles and states only: never document text, evidence contents, notes or
personal details beyond what the event names.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

EVENTS = {
    "isms.document_published": "ISMS document published",
    "isms.nonconformity_raised": "ISMS nonconformity raised",
    "isms.nonconformity_closed": "ISMS nonconformity closed",
    "isms.risk_accepted": "ISMS risk accepted",
    "isms.audit_completed": "ISMS internal audit completed",
    "isms.review_held": "ISMS management review held",
    "isms.evidence_requested": "ISMS evidence requested by an auditor",
    "isms.acknowledgement_requested": "ISMS document sent for acknowledgement",
    "isms.incident_review_completed": "ISMS incident review completed",
}


def emit(db: Session, tenant_id: str, event: str, **body) -> int:
    from .. import services
    assert event in EVENTS, event
    return services.fire_webhooks(db, tenant_id, event, {"tenantId": tenant_id, **body})
