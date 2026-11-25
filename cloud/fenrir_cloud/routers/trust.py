"""Trust centre (GRC-14, FLOW-10): a customer's public page of security documents.

* Documents are frozen when added (content, as-of date, SHA-256) and appear only after their disclosure is approved.
* Public documents are open to anyone; gated ones need an access request: the requester accepts the NDA (its hash is
  recorded), a person approves the request, and the requester gets a link that expires. Revoking the request, or
  withdrawing the document, stops any later access at once. Every access, served or refused, is logged.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, mailer, ratelimit
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import (GrcAssessmentSnapshot, GrcEvidence, GrcPolicy, GrcPolicyVersion, Tenant, TrustAccessLog,
                      TrustAccessRequest, TrustCentre, TrustDocument, utcnow)

router = APIRouter(prefix="/api/console/trust", tags=["Trust centre"])
public = APIRouter(prefix="/api/trust", tags=["Trust centre (public)"])
SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,58}[a-z0-9])$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def bad(msg: str):
    raise HTTPException(400, msg)


def _aad(d: TrustDocument) -> str:
    return f"trust-doc:{d.tenant_id}:{d.id}"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _doc_view(d: TrustDocument) -> dict:
    return {"id": d.id, "title": d.title, "description": d.description, "kind": d.kind, "access": d.access,
            "filename": d.filename, "sha256": d.sha256, "asOf": d.as_of.isoformat(), "status": d.status,
            "approvedBy": d.approved_by, "approvedAt": d.approved_at.isoformat() if d.approved_at else None,
            "addedBy": d.added_by}


def _req_view(r: TrustAccessRequest) -> dict:
    return {"id": r.id, "name": r.name, "email": r.email, "company": r.company, "reason": r.reason,
            "ndaSha256": r.nda_sha256, "status": r.status, "documents": r.documents,
            "expiresAt": r.expires_at.isoformat() if r.expires_at else None, "decidedBy": r.decided_by,
            "decidedAt": r.decided_at.isoformat() if r.decided_at else None, "createdAt": r.created_at.isoformat()}


# --- console -------------------------------------------------------------------------------------------------------

def _centre(db: Session, p: Principal, tenant_id: str) -> TrustCentre:
    p.check_tenant(tenant_id)
    c = db.execute(select(TrustCentre).where(TrustCentre.tenant_id == tenant_id)).scalar_one_or_none()
    if c is None:
        raise HTTPException(404, "no trust centre yet")
    return c


@router.get("")
def get_centre(tenantId: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    p.check_tenant(tenantId)
    c = db.execute(select(TrustCentre).where(TrustCentre.tenant_id == tenantId)).scalar_one_or_none()
    if c is None:
        return None
    docs = db.execute(select(TrustDocument).where(TrustDocument.tenant_id == tenantId).order_by(TrustDocument.title)).scalars()
    reqs = db.execute(select(TrustAccessRequest).where(TrustAccessRequest.tenant_id == tenantId)
                      .order_by(TrustAccessRequest.created_at.desc())).scalars()
    log = db.execute(select(TrustAccessLog).where(TrustAccessLog.tenant_id == tenantId)
                     .order_by(TrustAccessLog.at.desc()).limit(200)).scalars()
    return {"id": c.id, "slug": c.slug, "title": c.title, "overview": c.overview, "contact": c.contact, "ndaText": c.nda_text,
            "published": c.published, "defaultDays": c.default_days, "url": f"/trust/{c.slug}",
            "documents": [_doc_view(d) for d in docs], "requests": [_req_view(r) for r in reqs],
            "accessLog": [{"documentId": a.document_id, "email": a.email, "outcome": a.outcome, "reason": a.reason,
                           "ip": a.ip, "at": a.at.isoformat()} for a in log]}


@router.put("")
def save_centre(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    slug = str(body.get("slug") or "").strip().lower()
    if not SLUG.match(slug):
        bad("the address is 3 to 60 lower-case letters, digits and hyphens")
    other = db.execute(select(TrustCentre).where(TrustCentre.slug == slug, TrustCentre.tenant_id != tenant)).first()
    if other:
        bad("that address is taken")
    c = db.execute(select(TrustCentre).where(TrustCentre.tenant_id == tenant)).scalar_one_or_none()
    if c is None:
        name = (db.get(Tenant, tenant).name if db.get(Tenant, tenant) else "")
        c = TrustCentre(tenant_id=tenant, slug=slug, title=f"{name} trust centre", overview="", contact="", nda_text="",
                        published=False, default_days=30)
        db.add(c)
    c.slug = slug
    for k, attr, n in (("title", "title", 200), ("overview", "overview", 20000), ("contact", "contact", 200),
                       ("ndaText", "nda_text", 50000)):
        if k in body:
            setattr(c, attr, str(body[k] or "")[:n])
    if "published" in body:
        c.published = bool(body["published"])
    if "defaultDays" in body:
        c.default_days = max(1, min(365, int(body["defaultDays"] or 30)))
    if c.published and not c.nda_text.strip():
        bad("write the NDA requesters accept before publishing")
    c.updated_by, c.updated_at = p.actor, utcnow()
    audit.record(db, p.actor, "trust.centre.saved", c.slug, tenant, published=c.published)
    db.commit()
    return get_centre(tenant, p, db)


@router.post("/documents")
def add_document(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Freeze a document for the trust centre: an approved policy version, an evidence file, a compliance snapshot
    or a written note. It waits for disclosure approval."""
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    c = _centre(db, p, tenant)
    kind, src = body.get("kind"), str(body.get("sourceId") or "")
    access = body.get("access") or "gated"
    if access not in ("public", "gated"):
        bad("access is public or gated")
    now = utcnow()
    if kind == "policy":
        pol = db.get(GrcPolicy, src)
        if pol is None or pol.tenant_id != tenant or not pol.approved_version:
            bad("choose an approved policy")
        v = db.execute(select(GrcPolicyVersion).where(GrcPolicyVersion.policy_id == pol.id,
                                                      GrcPolicyVersion.version == pol.approved_version)).scalar_one()
        data, ctype, fname, as_of = f"# {v.title}\n\n{v.body}".encode(), "text/markdown; charset=utf-8", f"{v.title}-v{v.version}.md", v.approved_at
        title = body.get("title") or f"{v.title} (version {v.version})"
    elif kind == "evidence":
        ev = db.get(GrcEvidence, src)
        if ev is None or ev.tenant_id != tenant or ev.kind != "file":
            bad("choose an evidence file")
        from .grc_programme import _aad as ev_aad, _evidence_dir
        path = _evidence_dir() / ev.storage_name
        if not path.is_file():
            bad("that evidence file is no longer stored")
        data = crypto.decrypt_bytes(json.loads(path.read_text(encoding="utf-8")), ev_aad(ev))
        ctype, fname, as_of = ev.content_type or "application/octet-stream", ev.filename, ev.created_at
        title = body.get("title") or ev.title
    elif kind == "snapshot":
        snap = db.get(GrcAssessmentSnapshot, src)
        if snap is None or snap.tenant_id != tenant:
            bad("choose a programme snapshot")
        data = json.dumps({"framework": snap.framework_key, "label": snap.label, "takenAt": snap.created_at.isoformat(),
                           "data": snap.data}, indent=1, default=str).encode()
        ctype, fname, as_of = "application/json", f"{snap.framework_key}-{snap.created_at.date()}.json", snap.created_at
        title = body.get("title") or f"{snap.framework_key} status ({snap.created_at.date()})"
    elif kind == "note":
        text = str(body.get("text") or "").strip()
        if not text:
            bad("write the note")
        data, ctype, fname, as_of = text.encode(), "text/plain; charset=utf-8", "note.txt", now
        title = body.get("title") or "Note"
    else:
        bad("a document is a policy, evidence, snapshot or note")
    d = TrustDocument(tenant_id=tenant, title=str(title)[:300], description=str(body.get("description") or "")[:2000],
                      kind=kind, source_id=src, access=access, filename=fname[:255], content_type=ctype, content={},
                      sha256=_sha(data), as_of=as_of or now, added_by=p.actor)
    db.add(d)
    db.flush()
    d.content = crypto.encrypt(data, _aad(d))
    audit.record(db, p.actor, "trust.document.added", d.title, tenant, document=d.id, sha256=d.sha256, access=access)
    db.commit()
    return _doc_view(d)


@router.post("/documents/{doc_id}/decision")
def document_decision(doc_id: str, body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Approve the document's disclosure, change its access, or withdraw it (stops all later access)."""
    p.require("grc")
    d = db.get(TrustDocument, doc_id)
    if d is None or d.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Not found")
    action = body.get("action")
    if action == "approve":
        d.status, d.approved_by, d.approved_at = "approved", p.actor, utcnow()
    elif action == "withdraw":
        d.status = "withdrawn"
    elif action == "access" and body.get("access") in ("public", "gated"):
        d.access = body["access"]
    else:
        bad("action is approve, withdraw or access")
    audit.record(db, p.actor, f"trust.document.{action}", d.title, d.tenant_id, document=d.id, access=d.access)
    db.commit()
    return _doc_view(d)


@router.post("/requests/{req_id}/decision")
def request_decision(req_id: str, request: Request, body: dict = Body(...), p: Principal = Depends(current_principal),
                     db: Session = Depends(get_db)):
    """Approve (with an expiry and optionally only some documents), deny, or revoke an access request."""
    p.require("grc")
    r = db.get(TrustAccessRequest, req_id)
    if r is None or r.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Not found")
    c = db.execute(select(TrustCentre).where(TrustCentre.tenant_id == r.tenant_id)).scalar_one()
    action = body.get("action")
    link = None
    if action == "approve":
        if r.status not in ("pending", "revoked", "approved"):
            bad("this request was denied")
        days = max(1, min(365, int(body.get("days") or c.default_days)))
        docs = [str(x) for x in body.get("documents") or []]
        valid = {d.id for d in db.execute(select(TrustDocument).where(TrustDocument.tenant_id == r.tenant_id)).scalars()}
        if any(x not in valid for x in docs):
            bad("unknown document")
        token = secrets.token_urlsafe(32)
        r.token_hash, r.expires_at, r.documents, r.status = _sha(token.encode()), utcnow() + timedelta(days=days), docs, "approved"
        link = f"{get_settings().public_base_url.rstrip('/')}/trust/{c.slug}?access={token}"
        mailer.send(r.email, f"Access to the {c.title}",
                    f"Your request was approved. Open the documents here until {r.expires_at.date()}:\n\n{link}\n")
    elif action == "deny":
        r.status, r.token_hash = "denied", None
    elif action == "revoke":
        r.status, r.token_hash = "revoked", None
    else:
        bad("action is approve, deny or revoke")
    r.decided_by, r.decided_at = p.actor, utcnow()
    audit.record(db, p.actor, f"trust.request.{action}", r.email, r.tenant_id, request=r.id,
                 expires=r.expires_at.isoformat() if r.expires_at and action == "approve" else None)
    db.commit()
    return {**_req_view(r), "link": link}


# --- public --------------------------------------------------------------------------------------------------------

def _public_centre(db: Session, slug: str) -> TrustCentre:
    c = db.execute(select(TrustCentre).where(TrustCentre.slug == slug, TrustCentre.published.is_(True))).scalar_one_or_none()
    if c is None:
        raise HTTPException(404, "Not found")
    return c


def _grant(db: Session, c: TrustCentre, token: str | None) -> TrustAccessRequest | None:
    if not token:
        return None
    r = db.execute(select(TrustAccessRequest).where(TrustAccessRequest.token_hash == _sha(token.encode()),
                                                    TrustAccessRequest.tenant_id == c.tenant_id)).scalar_one_or_none()
    if r is None or r.status != "approved" or not r.expires_at or r.expires_at < utcnow():
        return None
    return r


@public.get("/{slug}")
def public_centre(slug: str, access: str | None = None, db: Session = Depends(get_db)):
    c = _public_centre(db, slug)
    grant = _grant(db, c, access)
    docs = db.execute(select(TrustDocument).where(TrustDocument.tenant_id == c.tenant_id, TrustDocument.status == "approved")
                      .order_by(TrustDocument.title)).scalars().all()

    def open_to_me(d: TrustDocument) -> bool:
        return d.access == "public" or (grant is not None and (not grant.documents or d.id in grant.documents))

    return {"title": c.title, "overview": c.overview, "contact": c.contact, "ndaText": c.nda_text,
            "ndaSha256": _sha(c.nda_text.encode()), "generatedAt": utcnow().isoformat(),
            "access": {"email": grant.email, "expiresAt": grant.expires_at.isoformat()} if grant else None,
            "documents": [{"id": d.id, "title": d.title, "description": d.description, "access": d.access,
                           "asOf": d.as_of.isoformat(), "sha256": d.sha256, "open": open_to_me(d)} for d in docs]}


@public.post("/{slug}/requests")
def public_request(slug: str, request: Request, body: dict = Body(...), db: Session = Depends(get_db)):
    c = _public_centre(db, slug)
    ip = request.client.host if request.client else ""
    ratelimit.check(f"trust-request:{ip}", 10, 3600)
    name, email = str(body.get("name") or "").strip()[:200], str(body.get("email") or "").strip().lower()[:200]
    if not name or not EMAIL.match(email):
        bad("your name and a work email address")
    if body.get("acceptNda") is not True or body.get("ndaSha256") != _sha(c.nda_text.encode()):
        bad("read and accept the NDA as shown")
    r = TrustAccessRequest(tenant_id=c.tenant_id, name=name, email=email, company=str(body.get("company") or "")[:200],
                           reason=str(body.get("reason") or "")[:2000], nda_sha256=_sha(c.nda_text.encode()), ip=ip[:64])
    db.add(r)
    db.flush()
    audit.record(db, f"trust:{email}", "trust.request.received", email, c.tenant_id, request=r.id, nda_sha256=r.nda_sha256)
    db.commit()
    return {"status": "pending", "message": "Thank you. You will receive an email if your request is approved."}


@public.get("/{slug}/documents/{doc_id}")
def public_document(slug: str, doc_id: str, request: Request, access: str | None = None, db: Session = Depends(get_db)):
    c = _public_centre(db, slug)
    d = db.get(TrustDocument, doc_id)
    ip = request.client.host if request.client else ""
    grant = _grant(db, c, access)

    def log(outcome: str, reason: str) -> None:
        db.add(TrustAccessLog(tenant_id=c.tenant_id, document_id=doc_id[:32], request_id=grant.id if grant else None,
                              email=grant.email if grant else "", outcome=outcome, reason=reason, ip=ip[:64]))
        db.commit()

    if d is None or d.tenant_id != c.tenant_id or d.status != "approved":
        log("refused", "not available")
        raise HTTPException(404, "Not found")
    if d.access == "gated" and not (grant and (not grant.documents or d.id in grant.documents)):
        log("refused", "no valid access")
        raise HTTPException(403, "This document needs approved access (the link may have expired or been revoked).")
    data = crypto.decrypt_bytes(d.content, _aad(d))
    if _sha(data) != d.sha256:
        log("refused", "integrity check failed")
        raise HTTPException(500, "The document failed its integrity check")
    log("served", d.access)
    return Response(data, media_type=d.content_type, headers={
        "Content-Disposition": f'attachment; filename="{d.filename}"', "Cache-Control": "private, no-store",
        "X-Content-SHA256": d.sha256, "X-As-Of": d.as_of.isoformat(), "X-Content-Type-Options": "nosniff"})


@router.get("/centres")
def list_centres(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(TrustCentre).where(TrustCentre.tenant_id.in_(scoped_tenant(p, tenantId)))).scalars()
    return [{"tenantId": c.tenant_id, "slug": c.slug, "title": c.title, "published": c.published} for c in rows]


# --- the public page (no account) ----------------------------------------------------------------------------------

import html  # noqa: E402
from urllib.parse import parse_qs, quote  # noqa: E402

from fastapi.responses import HTMLResponse  # noqa: E402

page = APIRouter(include_in_schema=False)
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>body{{font:15px/1.5 system-ui,sans-serif;max-width:820px;margin:24px auto;padding:0 16px;color:#1f2937}}
.doc{{border:1px solid #d1d5db;border-radius:8px;padding:10px 14px;margin:8px 0}}.muted{{color:#6b7280;font-size:13px}}
input,textarea{{width:100%;padding:6px;margin:4px 0 10px}}button{{padding:10px 18px;font-size:15px}}.lock{{color:#92400e}}
pre{{white-space:pre-wrap;background:#f9fafb;padding:10px;border-radius:6px}}</style></head><body>{body}</body></html>"""


def _html(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(PAGE.format(title=html.escape(title), body=body), status_code=status,
                        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"})


@page.get("/trust/{slug}", response_class=HTMLResponse)
def trust_page(slug: str, request: Request, access: str | None = None, db: Session = Depends(get_db)):
    ratelimit.check(f"trust-page:{request.client.host if request.client else ''}", 120, 3600)
    try:
        data = public_centre(slug, access, db)
    except HTTPException:
        return _html("Not found", "<h1>Not found</h1>", 404)
    e = html.escape
    q = f"?access={quote(access)}" if access and data["access"] else ""
    docs = []
    for d in data["documents"]:
        link = (f'<a href="/api/trust/{e(slug)}/documents/{e(d["id"])}{q}">Download</a>' if d["open"]
                else '<span class="lock">Available on request</span>')
        docs.append(f'<div class="doc"><b>{e(d["title"])}</b> <span class="muted">as of {e(d["asOf"][:10])}'
                    f' · SHA-256 {e(d["sha256"][:16])}…</span><div>{e(d["description"])}</div>{link}</div>')
    grant = (f'<p class="muted">Access for {e(data["access"]["email"])} until {e(data["access"]["expiresAt"][:10])}.</p>'
             if data["access"] else "")
    form = "" if data["access"] else f"""<h2>Request access</h2><p class="muted">Documents marked "available on request"
are shared after approval, under this non-disclosure agreement:</p><pre>{e(data["ndaText"])}</pre>
<form method="post" action="/trust/{e(slug)}"><input type="hidden" name="nda" value="{e(data["ndaSha256"])}">
<label>Name<input name="name" required maxlength="200"></label><label>Work email<input name="email" type="email" required maxlength="200"></label>
<label>Company<input name="company" maxlength="200"></label><label>Why you need the documents<textarea name="reason" rows="3" maxlength="2000"></textarea></label>
<label><input type="checkbox" name="accept" value="yes" required style="width:auto"> I accept the non-disclosure agreement above</label>
<button type="submit">Request access</button></form>"""
    contact = f'<p class="muted">Questions: {e(data["contact"])}</p>' if data["contact"] else ""
    return _html(data["title"], f"<h1>{e(data['title'])}</h1><p>{e(data['overview']).replace(chr(10), '<br>')}</p>"
                 f"<p class='muted'>Page generated {e(data['generatedAt'][:16].replace('T', ' '))} UTC; each document shows the date "
                 f"it is as of.</p>{grant}<h2>Documents</h2>{''.join(docs) or '<p>No documents yet.</p>'}{contact}{form}")


@page.post("/trust/{slug}", response_class=HTMLResponse)
async def trust_page_request(slug: str, request: Request, db: Session = Depends(get_db)):
    raw = await request.body()
    if len(raw) > 16 * 1024:
        return _html("Request access", "<p>The request is too long.</p>", 413)
    form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}
    try:
        public_request(slug, request, {"name": form.get("name"), "email": form.get("email"), "company": form.get("company"),
                                       "reason": form.get("reason"), "acceptNda": form.get("accept") == "yes",
                                       "ndaSha256": form.get("nda")}, db)
    except HTTPException as exc:
        return _html("Request access", f"<p>{html.escape(str(exc.detail))}</p><p><a href='/trust/{html.escape(slug)}'>Back</a></p>",
                     exc.status_code)
    return _html("Request access", "<h1>Thank you</h1><p>Your request has been received. You will receive an email if it is approved.</p>")
