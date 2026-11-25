"""Console API for eDiscovery cases (fenrir_cloud/backup_cases.py)."""

from __future__ import annotations

import base64
import binascii
import uuid as uuidlib

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import backup as bk
from .. import backup_cases as cases
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth, scoped_tenant
from ..models import BackupAgent, BackupCase, BackupImage, BackupRepoAccess, utcnow
from .backup import _unlocked, bad, iso

router = APIRouter(prefix="/api/console/backup/cases", tags=["Backup"])
KINDS = ("mail", "file", "site-file", "record", "teams-message", "directory")


def _case(db: Session, p: Principal, case_id: str) -> BackupCase:
    c = db.get(BackupCase, case_id)
    if c is None or c.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "no such case")
    return c


def _out(db: Session, c: BackupCase, full: bool = False) -> dict:
    held = sum(1 for i in db.execute(select(BackupImage.legal_hold).where(BackupImage.tenant_id == c.tenant_id)).scalars()
               if c.id in ((i or {}).get("cases") or []))
    out = {"id": c.id, "tenantId": c.tenant_id, "name": c.name, "matter": c.matter, "description": c.description,
           "status": c.status, "custodians": c.custodians or [], "holdNew": c.hold_new, "heldBackups": held,
           "createdBy": c.created_by, "createdAt": iso(c.created_at), "closedBy": c.closed_by,
           "closedAt": iso(c.closed_at), "searchCount": len(c.searches or []), "exportCount": len(c.exports or [])}
    if full:
        out["searches"] = c.searches or []
        out["exports"] = c.exports or []
    return out


def _custodians(db: Session, tenant_id: str, raw) -> list[dict]:
    if not isinstance(raw, list) or len(raw) > 200:
        bad("custodians: a list of up to 200 machines or cloud tenants")
    known = {cases.device_key(i): i for i in db.execute(select(BackupImage).where(BackupImage.tenant_id == tenant_id)).scalars()}
    out = []
    for c in raw:
        key = str((c or {}).get("device") or "")
        if key not in known:
            bad("each custodian must be a machine or cloud tenant with backups in this organisation")
        accounts = [str(a).strip()[:320] for a in (c.get("accounts") or []) if str(a).strip()][:500]
        if accounts and not key.startswith("app:saas:"):
            bad("accounts can be chosen only for cloud-service (SaaS) custodians")
        im = known[key]
        out.append({"device": key, "label": str(c.get("label") or im.vm_name or im.hostname)[:200], "accounts": accounts})
    return out


@router.get("")
def list_cases(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    tenants = scoped_tenant(p, tenantId)
    rows = db.execute(select(BackupCase).where(BackupCase.tenant_id.in_(tenants))
                      .order_by(BackupCase.created_at.desc())).scalars().all()
    return [_out(db, c) for c in rows]


@router.post("")
def create_case(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("configure")
    tenant = str(body.get("tenantId") or p.user.tenant_id)
    p.check_tenant(tenant)
    name = str(body.get("name") or "").strip()
    if not 3 <= len(name) <= 200:
        bad("name the case (3 to 200 characters)")
    c = BackupCase(tenant_id=tenant, name=name, matter=str(body.get("matter") or "").strip()[:200],
                   description=str(body.get("description") or "")[:5000],
                   custodians=_custodians(db, tenant, body.get("custodians") or []),
                   hold_new=body.get("holdNew", True) is not False, searches=[], exports=[], created_by=p.actor)
    db.add(c)
    db.flush()
    held, _ = cases.apply_holds(db, c, p.actor)
    bk.record(db, p.actor, "backup.case.created", c.name, c.tenant_id, case=c.id, matter=c.matter,
              custodians=[x["label"] for x in c.custodians], held=held)
    db.commit()
    return _out(db, c, True)


@router.get("/{case_id}")
def get_case(case_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    return _out(db, _case(db, p, case_id), True)


@router.patch("/{case_id}")
def update_case(case_id: str, body: dict = Body(...), p: Principal = Depends(current_principal),
                db: Session = Depends(get_db)):
    p.require("configure")
    c = _case(db, p, case_id)
    if c.status != "open":
        bad("the case is closed")
    if "description" in body:
        c.description = str(body["description"] or "")[:5000]
    if "holdNew" in body:
        c.hold_new = bool(body["holdNew"])
    held = released = 0
    if "custodians" in body:
        c.custodians = _custodians(db, c.tenant_id, body["custodians"])
        held, released = cases.apply_holds(db, c, p.actor)
    bk.record(db, p.actor, "backup.case.updated", c.name, c.tenant_id, case=c.id,
              custodians=[x["label"] for x in c.custodians], held=held, released=released, hold_new=c.hold_new)
    db.commit()
    return _out(db, c, True)


@router.post("/{case_id}/close")
def close_case(case_id: str, request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Close the case and release the holds it placed (holds placed by hand or by other cases stay)."""
    p.require("configure")
    require_reauth(request, p)
    c = _case(db, p, case_id)
    if c.status != "open":
        bad("the case is already closed")
    c.status, c.closed_by, c.closed_at = "closed", p.actor, utcnow()
    _, released = cases.apply_holds(db, c, p.actor)
    bk.record(db, p.actor, "backup.case.closed", c.name, c.tenant_id, case=c.id, released=released)
    db.commit()
    return _out(db, c, True)


@router.post("/{case_id}/search")
def search_case(case_id: str, request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
                db: Session = Depends(get_db)):
    """Search the custodians' backups (those in repositories this session unlocked); matches are kept with the case."""
    p.require("scripts")
    c = _case(db, p, case_id)
    query = str(body.get("query") or "").strip()
    if not query or len(query) > 200:
        bad("type what to search for (up to 200 characters)")
    unlocked = _unlocked(request, p)
    images = cases.custodian_images(db, c)
    usable = [i for i in images if i.repository_id in unlocked]
    if not usable:
        raise HTTPException(403, "repository_locked") if images else bad("the custodians have no backups")
    sid = uuidlib.uuid4().hex[:12]
    by_repo: dict[str, list[BackupImage]] = {}
    for i in usable:
        by_repo.setdefault(i.repository_id, []).append(i)
    jobs = []
    for repo_id, ims in by_repo.items():
        agents = db.execute(select(BackupAgent).join(BackupRepoAccess, BackupRepoAccess.agent_id == BackupAgent.id)
                            .where(BackupRepoAccess.repository_id == repo_id, BackupAgent.revoked.is_(False))).scalars().all()
        agents = sorted((a for a in agents if "search_files" in bk.capabilities(a)), key=lambda a: not bk.online(a))
        if not agents:
            continue
        job = bk.queue(db, agents[0], {"type": "search_files", "query": query, "images": [i.image_id for i in ims[:2000]],
                                       "limit": 2000, "budget_secs": 600}, repo_id, f"case:{c.id}:search:{sid}")
        jobs.append(job.id)
    if not jobs:
        bad("no machine with access to these backups can search them: update its backup agent")
    c.searches = (c.searches or []) + [{"id": sid, "query": query, "by": p.actor, "at": utcnow().isoformat(),
                                        "jobs": jobs, "done": [], "hits": [], "state": "running",
                                        "locked": len(images) - len(usable)}]
    bk.record(db, p.actor, "backup.case.search", c.name, c.tenant_id, case=c.id, query=query, jobs=len(jobs))
    db.commit()
    return {"id": sid, "jobs": jobs, "lockedBackups": len(images) - len(usable)}


@router.post("/{case_id}/export")
def export_case(case_id: str, request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
                db: Session = Depends(get_db)):
    """Export items of one custodian backup for this browser, with each item's SHA-256 in the archive's manifest."""
    p.require("scripts")
    c = _case(db, p, case_id)
    if c.status != "open":
        bad("the case is closed")
    image_id = str(body.get("imageId") or "")
    im = next((i for i in cases.custodian_images(db, c) if i.image_id == image_id), None)
    if im is None:
        bad("choose a backup of one of the case's custodians")
    if im.repository_id not in _unlocked(request, p):
        raise HTTPException(403, "repository_locked")
    recipient = str(body.get("recipient") or "").strip()
    try:
        ok = len(base64.b64decode(recipient, validate=True)) == 32
    except (binascii.Error, ValueError):
        ok = False
    if not ok:
        bad("recipient must be a 32-byte X25519 public key (base64)")
    agents = db.execute(select(BackupAgent).join(BackupRepoAccess, BackupRepoAccess.agent_id == BackupAgent.id)
                        .where(BackupRepoAccess.repository_id == im.repository_id, BackupAgent.revoked.is_(False))).scalars().all()
    agents = sorted((a for a in agents if "ediscovery" in bk.capabilities(a)), key=lambda a: (a.id != im.agent_id, not bk.online(a)))
    if not agents:
        bad("no machine with access to this backup can make eDiscovery exports yet: update its backup agent")
    eid = uuidlib.uuid4().hex[:12]
    saas = (im.machine_id or "").startswith("saas:")
    if saas:
        custodian = next(x for x in c.custodians if x["device"] == cases.device_key(im))
        accounts = [str(a) for a in body.get("accounts") or []][:500] or custodian.get("accounts") or []
        allowed = {a.lower() for a in custodian.get("accounts") or []}
        if allowed and any(a.lower() not in allowed for a in accounts):
            bad("only the case's accounts of this tenant can be exported")
        kinds = [k for k in body.get("kinds") or [] if k in KINDS]
        items = [str(x)[:4000] for x in body.get("items") or []][:5000]
        kind = {"type": "export_saas", "image_id": im.image_id, "accounts": accounts, "kinds": kinds, "items": items,
                "recipient": recipient}
        what = f"{len(items) or 'all matching'} items"
    else:
        d, part = body.get("disk"), body.get("partition")
        paths = [str(x) for x in body.get("paths") or [] if str(x).strip("/")]
        if not (isinstance(d, int) and isinstance(part, int)) or not paths or len(paths) > 1000:
            bad("choose a volume and 1 to 1000 files or folders")
        kind = {"type": "download_files", "image_id": im.image_id, "volume": {"disk": d, "partition": part},
                "paths": paths, "recipient": recipient, "manifest": True}
        what = f"{len(paths)} files or folders"
    job = bk.queue(db, agents[0], kind, im.repository_id, f"case:{c.id}:export:{eid}")
    c.exports = (c.exports or []) + [{"id": eid, "imageId": im.image_id, "machine": im.vm_name or im.hostname,
                                      "backedUpUnix": im.created_unix, "what": what, "by": p.actor,
                                      "at": utcnow().isoformat(), "jobId": job.id, "agent": agents[0].hostname,
                                      "state": "queued"}]
    bk.record(db, p.actor, "backup.case.export", c.name, c.tenant_id, case=c.id, image=im.image_id, job=job.id,
              what=what)
    db.commit()
    return {"id": eid, "jobId": job.id}


@router.post("/{case_id}/exports/{export_id}/receipt")
def export_receipt(case_id: str, export_id: str, body: dict = Body(...), p: Principal = Depends(current_principal),
                   db: Session = Depends(get_db)):
    """The browser that decrypted an export reports the SHA-256 of what it saved: the last link of the chain."""
    p.require("scripts")
    c = _case(db, p, case_id)
    sha = str(body.get("sha256") or "").lower()
    if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        bad("sha256: 64 hex characters")
    exports = [dict(e) for e in c.exports or []]
    e = next((e for e in exports if e["id"] == export_id), None)
    if e is None:
        raise HTTPException(404, "no such export")
    e.setdefault("receipts", []).append({"by": p.actor, "at": utcnow().isoformat(), "sha256": sha,
                                          "bytes": int(body.get("bytes") or 0)})
    c.exports = exports
    bk.record(db, p.actor, "backup.case.export_received", c.name, c.tenant_id, case=c.id, export=export_id, sha256=sha)
    db.commit()
    return e


@router.get("/{case_id}/manifest")
def case_manifest(case_id: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    c = _case(db, p, case_id)
    doc = cases.manifest(db, c)
    bk.record(db, p.actor, "backup.case.manifest", c.name, c.tenant_id, case=c.id, sha256=doc["sha256"])
    db.commit()
    return JSONResponse(doc, headers={"Content-Disposition": f'attachment; filename="case-{c.id[:8]}-manifest.json"'})
