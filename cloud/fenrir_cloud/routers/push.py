"""Push notifications to the console app: each person turns them on per phone or computer (Settings → Account)."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, webpush
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import PushSubscription

router = APIRouter(prefix="/api/console/push", tags=["Push notifications"])


def _view(row: PushSubscription) -> dict:
    return {"id": row.id, "label": row.label, "createdAt": row.created_at.isoformat() + "Z",
            "lastSuccessAt": row.last_success_at.isoformat() + "Z" if row.last_success_at else None}


@router.get("/key")
def application_key(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The key the browser subscribes with."""
    key = webpush.public_key(db)
    db.commit()  # normally a read: the key is made at start-up
    return {"publicKey": key}


@router.get("/subscriptions")
def my_subscriptions(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(PushSubscription).where(PushSubscription.user_id == principal.user.id)
                      .order_by(PushSubscription.created_at)).scalars().all()
    return [_view(r) for r in rows]


@router.post("/subscriptions")
def subscribe(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Body: the browser's PushSubscription JSON ({endpoint, keys: {p256dh, auth}}) and an optional label."""
    if principal.user.role in ("client", "service"):
        raise HTTPException(403, "Push notifications are for staff accounts")
    try:
        row = webpush.subscribe(db, principal.user.id, body.get("subscription") or body, str(body.get("label") or ""))
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    audit.record(db, principal.actor, "push.subscribed", row.label or "device", principal.user.tenant_id)
    db.commit()
    return _view(row)


@router.post("/unsubscribe")
def unsubscribe(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Remove by endpoint (this browser) or id (another of my devices)."""
    query = select(PushSubscription).where(PushSubscription.user_id == principal.user.id)
    if body.get("endpoint"):
        query = query.where(PushSubscription.endpoint == str(body["endpoint"]))
    elif body.get("id"):
        query = query.where(PushSubscription.id == str(body["id"]))
    else:
        raise HTTPException(400, "Give endpoint or id")
    removed = 0
    for row in db.execute(query).scalars().all():
        db.delete(row)
        removed += 1
    db.commit()
    return {"removed": removed}


@router.post("/test")
def test(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Send a test notification to every device I turned notifications on for."""
    queued = webpush.notify_users(db, [principal.user.id], "Fenrir notifications are on",
                                  "You will be notified here about the alerts you are chosen for.", "/", tag="test")
    db.commit()
    return {"queued": queued}
