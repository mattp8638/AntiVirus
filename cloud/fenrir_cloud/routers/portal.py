"""Client portal: customers raise and follow tickets, read public KB articles and see invoices."""

from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import audit, presence, psa, services
from .. import backup as bk
from ..db import get_db
from ..deps import Principal, current_principal
from ..models import (BackupAgent, BackupImage, BackupJob, BackupRepoAccess, Board, Contact, Device, Invoice, KbArticle,
                      Tenant, Ticket, utcnow)
from ..serialize import to_dict

router = APIRouter(prefix="/api/portal", tags=["Client portal"])


def _portal(principal: Principal = Depends(current_principal)) -> Principal:
    # Staff can open the portal too (to see what customers see); everyone else needs the portal permission.
    if not (principal.can("portal") or principal.can("read")):
        raise HTTPException(403, "No portal access")
    return principal


def _public_ticket(db: Session, ticket: Ticket) -> dict:
    board = db.get(Board, ticket.board_id) if ticket.board_id else None
    return {"id": ticket.id, "number": ticket.number, "subject": ticket.subject, "description": ticket.description,
            "status": ticket.status, "priority": ticket.priority, "closed": ticket.status in psa.closed_statuses(board),
            "createdAt": to_dict(ticket)["createdAt"], "updatedAt": to_dict(ticket)["updatedAt"], "assignee": ticket.assignee or "",
            "notes": [{"at": c.get("at"), "by": c.get("by"), "text": c.get("text"), "kind": c.get("kind", "discussion")}
                      for c in ticket.comments or [] if not c.get("internal") and c.get("kind") != "system"]}


def _account(principal: Principal) -> str:
    return principal.user.tenant_id


@router.get("/me")
def portal_me(principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    tenant = db.get(Tenant, _account(principal))
    owner = db.get(Tenant, services.msp_tenant_id(db, tenant.id)) if tenant else None
    return {"user": {"email": principal.user.email, "name": principal.user.name}, "company": tenant.name if tenant else "",
            "provider": owner.name if owner else "", "supportPhone": (owner.settings or {}).get("phone", "") if owner else ""}


@router.get("/tickets")
def portal_tickets(principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    rows = db.execute(select(Ticket).where(Ticket.account_tenant_id == _account(principal))
                      .order_by(Ticket.created_at.desc()).limit(500)).scalars()
    return [_public_ticket(db, t) for t in rows]


@router.post("/tickets")
def portal_create(body: dict = Body(...), principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    subject = str(body.get("subject") or "").strip()
    if not subject:
        raise HTTPException(400, "Please give your request a subject")
    urgency = str(body.get("urgency") or "Medium").title()
    impact = str(body.get("impact") or "Low").title()
    priority = psa.priority_for(impact, urgency) or "P3"
    contact = db.execute(select(Contact).where(Contact.email == principal.user.email,
                                               Contact.account_tenant_id == _account(principal))).scalars().first()
    ticket = services.open_ticket(db, _account(principal), subject, str(body.get("description") or ""), priority, "portal",
                                  principal.user.name or principal.user.email, impact=impact, urgency=urgency,
                                  contact_email=principal.user.email, contact_id=contact.id if contact else None)
    psa.notify_contact(ticket, f"We have received your request and logged it as ticket #{ticket.number}.",
                       "You can follow progress in the portal or reply to this email.")
    audit.record(db, principal.actor, "portal.ticket.created", f"#{ticket.number}", ticket.account_tenant_id)
    db.commit()
    return _public_ticket(db, ticket)


@router.get("/tickets/{ticket_id}")
def portal_ticket(ticket_id: str, principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    ticket = db.get(Ticket, ticket_id)
    if ticket is None or ticket.account_tenant_id != _account(principal):
        raise HTTPException(404, "Not found")
    return _public_ticket(db, ticket)


@router.post("/tickets/{ticket_id}/reply")
def portal_reply(ticket_id: str, body: dict = Body(...), principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    ticket = db.get(Ticket, ticket_id)
    if ticket is None or ticket.account_tenant_id != _account(principal):
        raise HTTPException(404, "Not found")
    text = str(body.get("text") or "").strip()
    if not text:
        raise HTTPException(400, "Write a reply first")
    psa.add_note(db, ticket, principal.user.email, text, "discussion", staff=False)
    board = db.get(Board, ticket.board_id) if ticket.board_id else None
    responded = next((s["name"] for s in (board.statuses if board else []) or [] if s.get("customerResponded")), None)
    if body.get("close"):
        psa.set_status(db, ticket, "Closed", principal.user.email)
    elif psa.is_closed(db, ticket):
        psa.set_status(db, ticket, responded or "Open", principal.user.email)
    elif responded:
        psa.set_status(db, ticket, responded, principal.user.email)
    psa.run_workflows(db, ticket, "ticket.updated")
    ticket.updated_at = utcnow()
    db.commit()
    return _public_ticket(db, ticket)


@router.get("/kb")
def portal_kb(q: str | None = None, principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    owner = services.msp_tenant_id(db, _account(principal))
    query = select(KbArticle).where(KbArticle.tenant_id == owner, KbArticle.public.is_(True))
    if q:
        query = query.where(or_(KbArticle.title.ilike(f"%{q}%"), KbArticle.body.ilike(f"%{q}%")))
    return [to_dict(a) for a in db.execute(query.order_by(KbArticle.category, KbArticle.title)).scalars()]


@router.get("/invoices")
def portal_invoices(principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    rows = db.execute(select(Invoice).where(Invoice.account_tenant_id == _account(principal), Invoice.status != "Draft")
                      .order_by(Invoice.created_at.desc())).scalars()
    return [to_dict(i) for i in rows]


@router.get("/devices")
def portal_devices(principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    rows = db.execute(select(Device).where(Device.tenant_id == _account(principal), Device.approved.is_(True))).scalars()
    now = utcnow()
    return [{"id": d.id, "hostname": d.hostname, "osVersion": d.os_version, "healthState": d.health_state,
             "online": presence.is_up(d, now),
             "loggedOnUser": (d.metrics or {}).get("loggedOnUser", "")} for d in rows]


# ---------------------------------------------------------------------------------------------------------------------
# Self-service restore: files from the backups of the devices an administrator granted this user
# (Backups > Self-service). Download only: the machine encrypts the files for this browser's one-time key and the
# server relays ciphertext. Files the latest malware scan found infected are refused.
# ---------------------------------------------------------------------------------------------------------------------


def _self_images(db: Session, principal: Principal) -> list[BackupImage]:
    devices = list(principal.user.backup_restore_devices or [])
    if not devices:
        return []
    agents = db.execute(select(BackupAgent.id).where(BackupAgent.tenant_id == principal.user.tenant_id,
                                                     BackupAgent.device_id.in_(devices))).scalars().all()
    if not agents:
        return []
    rows = db.execute(select(BackupImage).where(BackupImage.tenant_id == principal.user.tenant_id,
                                                BackupImage.agent_id.in_(agents))
                      .order_by(BackupImage.created_unix.desc())).scalars().all()
    return [i for i in rows if not (i.machine_id or "").startswith(("saas:", "k8s:", "cdp:"))]


def _self_image(db: Session, principal: Principal, image_id: str) -> BackupImage:
    im = next((i for i in _self_images(db, principal) if i.image_id == image_id), None)
    if im is None:
        raise HTTPException(404, "Not found")
    return im


def _self_agent(db: Session, im: BackupImage) -> BackupAgent:
    rows = db.execute(select(BackupAgent).join(BackupRepoAccess, BackupRepoAccess.agent_id == BackupAgent.id)
                      .where(BackupRepoAccess.repository_id == im.repository_id,
                             BackupAgent.revoked.is_(False))).scalars().all()
    rows = [a for a in rows if "restore_files" in bk.capabilities(a)]
    rows.sort(key=lambda a: (a.id != im.agent_id, not bk.online(a)))
    if not rows:
        raise HTTPException(409, "no machine can read this backup at the moment; ask your IT provider")
    return rows[0]


def _by(principal: Principal) -> str:
    return f"portal:{principal.user.email}"


def _volume(body: dict) -> dict | None:
    d, p = body.get("disk"), body.get("partition")
    if isinstance(d, int) and isinstance(p, int) and 0 <= d < 64 and 0 <= p < 256:
        return {"disk": d, "partition": p}
    return None


@router.get("/backups")
def portal_backups(principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    return [{"imageId": i.image_id, "repositoryId": i.repository_id, "agentId": i.agent_id, "hostname": i.hostname,
             "vmName": i.vm_name, "created": i.created_unix, "kind": i.kind,
             "source": "files" if bk.is_folder_backup(i) else "disks"} for i in _self_images(db, principal)[:500]]


@router.post("/backups/images/{image_id}/browse")
def portal_browse(image_id: str, body: dict = Body(default={}), principal: Principal = Depends(_portal),
                  db: Session = Depends(get_db)):
    im = _self_image(db, principal, image_id)
    a = _self_agent(db, im)
    path = str(body.get("path") or "/")
    if len(path) > 4000 or ".." in path.replace("\\", "/").split("/"):
        raise HTTPException(400, "invalid folder")
    job = bk.queue(db, a, {"type": "browse_files", "image_id": im.image_id, "volume": _volume(body), "path": path},
                   im.repository_id, _by(principal))
    if _volume(body) is None:
        bk.record(db, _by(principal), "backup.self_service.browsed", im.hostname, im.tenant_id, image=im.image_id)
    db.commit()
    return {"id": job.id, "agentId": a.id, "agentName": a.display_name or a.hostname, "agentOnline": bk.online(a)}


@router.post("/backups/images/{image_id}/download-files")
def portal_download(image_id: str, body: dict = Body(...), principal: Principal = Depends(_portal),
                    db: Session = Depends(get_db)):
    im = _self_image(db, principal, image_id)
    a = _self_agent(db, im)
    volume = _volume(body)
    paths = [str(x) for x in body.get("paths") or [] if str(x).strip("/")]
    if volume is None or not paths or len(paths) > 1000 or any(len(x) > 4000 for x in paths):
        raise HTTPException(400, "choose 1 to 1000 files or folders")
    sc = bk.scan_latest(db, [im.image_id]).get(im.image_id)
    if sc is not None and sc.state == "infected":
        hits = [f.get("path", "").lower() for f in sc.findings or []]
        if any(h == x.rstrip("/").lower() or h.startswith(x.rstrip("/").lower() + "/") for h in hits for x in paths):
            raise HTTPException(409, "the latest malware scan found an infected file in what you chose; ask your IT provider")
    recipient = str(body.get("recipient") or "").strip()
    try:
        ok = len(base64.b64decode(recipient, validate=True)) == 32
    except (binascii.Error, ValueError):
        ok = False
    if not ok:
        raise HTTPException(400, "recipient must be a 32-byte X25519 public key (base64)")
    job = bk.queue(db, a, {"type": "download_files", "image_id": im.image_id, "volume": volume, "paths": paths,
                           "recipient": recipient}, im.repository_id, _by(principal))
    bk.record(db, _by(principal), "backup.self_service.download_requested", im.hostname, im.tenant_id,
              image=im.image_id, items=len(paths), first=paths[0][:300])
    db.commit()
    return {"id": job.id}


def _own_job(db: Session, principal: Principal, job_id: str) -> BackupJob:
    job = db.get(BackupJob, job_id)
    if job is None or job.requested_by != _by(principal) or job.tenant_id != principal.user.tenant_id:
        raise HTTPException(404, "Not found")
    return job


@router.get("/backups/jobs/{job_id}")
def portal_job(job_id: str, principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    j = _own_job(db, principal, job_id)
    return {"id": j.id, "state": j.state, "result": j.result, "error": j.error, "warnings": j.warnings or [],
            "progress": j.progress}


@router.get("/backups/jobs/{job_id}/download")
def portal_job_download(job_id: str, principal: Principal = Depends(_portal), db: Session = Depends(get_db)):
    j = _own_job(db, principal, job_id)
    if (j.kind or {}).get("type") != "download_files" or j.state not in ("succeeded", "warning"):
        raise HTTPException(409, "the download is not ready")
    path = bk.download_path(j.id)
    if not path.exists():
        raise HTTPException(404, "the download has expired")
    return FileResponse(path, media_type="application/octet-stream", headers={"Cache-Control": "no-store"})
