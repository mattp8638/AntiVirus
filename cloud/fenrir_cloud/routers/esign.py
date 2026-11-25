"""Console API and the signer's page for agreements and e-signature (GRC-09), fenrir_cloud/esign.py."""
from __future__ import annotations

import html
import json
import re
import uuid
from datetime import datetime
from urllib.parse import parse_qs, quote

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from .. import audit, ratelimit
from .. import esign as es
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import Agreement, AgreementTemplate, utcnow

router = APIRouter(prefix="/api/console/agreements", tags=["Agreements"])
page = APIRouter(include_in_schema=False)
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def bad(msg: str):
    raise HTTPException(400, msg)


def _view(a: Agreement, full: bool = False) -> dict:
    out = {"id": a.id, "tenantId": a.tenant_id, "title": a.title, "sha256": a.sha256, "order": a.order, "status": a.status,
           "expiresAt": a.expires_at.isoformat() if a.expires_at else None,
           "completedAt": a.completed_at.isoformat() if a.completed_at else None, "createdBy": a.created_by,
           "parties": [{k: p.get(k) for k in ("id", "name", "email", "role", "order", "status", "signedAt", "invited")} for p in a.parties]}
    if full:
        out["body"] = a.body
        out["events"] = a.events
    return out


def _owned(db: Session, p: Principal, aid: str) -> Agreement:
    a = db.get(Agreement, aid)
    if a is None or a.tenant_id not in p.tenant_ids:
        raise HTTPException(404, "Not found")
    return a


@router.get("/templates")
def list_templates(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(AgreementTemplate).where(AgreementTemplate.tenant_id.in_(scoped_tenant(p, tenantId)))).scalars()
    return [{"id": t.id, "name": t.name, "body": t.body, "variables": sorted(set(es.VAR.findall(t.body)))} for t in rows]


@router.post("/templates")
def create_template(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    name, text = str(body.get("name") or "").strip(), str(body.get("body") or "")
    if not name or len(text.strip()) < 20:
        bad("a name and the agreement text")
    t = AgreementTemplate(tenant_id=tenant, name=name[:200], body=text[:200000], created_by=p.actor)
    db.add(t)
    db.flush()
    audit.record(db, p.actor, "agreement.template_created", t.name, tenant, template=t.id)
    db.commit()
    return {"id": t.id, "name": t.name, "variables": sorted(set(es.VAR.findall(t.body)))}


@router.get("")
def list_agreements(tenantId: str | None = None, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    rows = db.execute(select(Agreement).where(Agreement.tenant_id.in_(scoped_tenant(p, tenantId)))
                      .order_by(Agreement.created_at.desc())).scalars()
    return [_view(a) for a in rows]


@router.post("")
def create_agreement(body: dict = Body(...), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """From a template and its values (or a full text), with the parties in signing order. The text is frozen."""
    p.require("grc")
    tenant = str(body.get("tenantId") or "")
    p.check_tenant(tenant)
    if body.get("templateId"):
        t = db.get(AgreementTemplate, str(body["templateId"]))
        if t is None or t.tenant_id != tenant:
            bad("unknown template")
        try:
            text = es.render(t.body, body.get("values") or {})
        except ValueError as e:
            bad(str(e))
    else:
        text = str(body.get("body") or "")
    if len(text.strip()) < 20:
        bad("the agreement needs its text")
    parties = []
    for i, x in enumerate(body.get("parties") or []):
        name, email = str(x.get("name") or "").strip(), str(x.get("email") or "").strip().lower()
        if not name or not EMAIL.match(email):
            bad("each signer needs a name and an email address")
        parties.append({"id": uuid.uuid4().hex[:10], "name": name[:200], "email": email[:200], "role": str(x.get("role") or "")[:100],
                        "order": int(x.get("order") or i + 1), "status": "pending", "invited": False})
    if not parties or len(parties) > 20 or len({p_["email"] for p_ in parties}) != len(parties):
        bad("1 to 20 signers, each email once")
    order = body.get("order") or "sequential"
    if order not in ("sequential", "parallel"):
        bad("order is sequential or parallel")
    try:
        expires = datetime.fromisoformat(str(body["expiresOn"])[:10]) if body.get("expiresOn") else None
    except ValueError:
        bad("the expiry date is YYYY-MM-DD")
    a = Agreement(tenant_id=tenant, title=str(body.get("title") or "Agreement")[:300], body=text, sha256=es.sha(text),
                  template_id=body.get("templateId"), order=order, parties=parties, expires_at=expires, events=[],
                  created_by=p.actor, status="draft")
    db.add(a)
    db.flush()
    es.add_event(a, "created", p.actor, signers=[x["email"] for x in parties], order=order)
    audit.record(db, p.actor, "agreement.created", a.title, tenant, agreement=a.id, sha256=a.sha256)
    db.commit()
    return _view(a, True)


@router.get("/{aid}")
def get_agreement(aid: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    return _view(_owned(db, p, aid), True)


@router.post("/{aid}/send")
def send(aid: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    a = _owned(db, p, aid)
    if a.status != "draft":
        bad("already sent")
    if a.expires_at and a.expires_at < utcnow():
        bad("the expiry date has passed")
    a.status = "sent"
    es.invite(a, es.due_parties(a))
    flag_modified(a, "parties")
    audit.record(db, p.actor, "agreement.sent", a.title, a.tenant_id, agreement=a.id)
    db.commit()
    return _view(a, True)


@router.post("/{aid}/void")
def void(aid: str, body: dict = Body(default={}), p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("grc")
    a = _owned(db, p, aid)
    if a.status in ("completed", "voided"):
        bad(f"the agreement is {a.status}")
    a.status = "voided"
    for x in a.parties:
        x["tokenHash"] = None
    flag_modified(a, "parties")
    es.add_event(a, "voided", p.actor, reason=str(body.get("reason") or "")[:500])
    audit.record(db, p.actor, "agreement.voided", a.title, a.tenant_id, agreement=a.id)
    db.commit()
    return _view(a, True)


@router.get("/{aid}/certificate")
def certificate(aid: str, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    p.require("read")
    return es.certificate(_owned(db, p, aid))


@router.post("/verify")
def verify(body: dict = Body(...), p: Principal = Depends(current_principal)):
    """Check a completion certificate: its events' hash chain and its own hash."""
    p.require("read")
    cert = body if isinstance(body, dict) else {}
    claimed = cert.get("sha256")
    rest = {k: v for k, v in cert.items() if k != "sha256"}
    return {"chainValid": es.verify_chain(str(cert.get("agreement")), str(cert.get("documentSha256")), cert.get("events") or []),
            "certificateIntact": claimed == es.sha(json.dumps(rest, sort_keys=True, separators=(",", ":")))}


def expire_due(db: Session) -> int:
    """Hourly: agreements past their expiry stop accepting signatures."""
    n = 0
    for a in db.execute(select(Agreement).where(Agreement.status == "sent", Agreement.expires_at.is_not(None),
                                                Agreement.expires_at < utcnow())).scalars():
        a.status = "expired"
        for x in a.parties:
            x["tokenHash"] = None
        flag_modified(a, "parties")
        es.add_event(a, "expired", "system")
        n += 1
    db.commit()
    return n


# --- the signer's page ---------------------------------------------------------------------------------------------

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>body{{font:15px/1.5 system-ui,sans-serif;max-width:820px;margin:24px auto;padding:0 16px;color:#1f2937}}
.doc{{white-space:pre-wrap;border:1px solid #d1d5db;border-radius:8px;padding:14px;max-height:55vh;overflow:auto;background:#f9fafb}}
.muted{{color:#6b7280;font-size:13px}}input{{padding:6px;margin:4px 0 10px;width:100%}}button{{padding:10px 18px;font-size:15px}}
.err{{color:#b91c1c}}.ok{{color:#166534}}</style></head><body>{body}</body></html>"""


def _html(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(PAGE.format(title=html.escape(title), body=body), status_code=status,
                        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"})


def _open(db: Session, aid: str, token: str) -> tuple[Agreement | None, dict | None, str]:
    a = db.get(Agreement, aid)
    if a is None:
        return None, None, "This link is not valid."
    p = es.party_by_token(a, token)
    if p is None:
        return a, None, "This link is not valid, or it was already used to sign."
    if a.status == "expired" or (a.expires_at and a.expires_at < utcnow()):
        return a, None, "This agreement has expired."
    if a.status != "sent":
        return a, None, f"This agreement is {a.status}."
    return a, p, ""


def _form(a: Agreement, p: dict, token: str, msg: str = "", ok: str = "") -> str:
    e = html.escape
    t = quote(token)
    turn = p in es.due_parties(a)
    waiting = "" if turn else "<p class=muted>Other people sign before you; this page will accept your signature when it is your turn.</p>"
    return (f"<h1>{e(a.title)}</h1><p class=muted>For {e(p['name'])} ({e(p['email'])}). Document SHA-256: <code>{e(a.sha256)}</code></p>"
            f"<div class=doc>{e(a.body)}</div>{waiting}"
            f"{f'<p class=err>{e(msg)}</p>' if msg else ''}{f'<p class=ok>{e(ok)}</p>' if ok else ''}"
            f"<form method=post action='/sign/{e(a.id)}?t={t}'><input type=hidden name=action value=code>"
            f"<button type=submit>Email me a signing code</button></form>"
            f"<form method=post action='/sign/{e(a.id)}?t={t}'><input type=hidden name=action value=sign>"
            f"<label>Code from the email<input name=code inputmode=numeric autocomplete=one-time-code maxlength=6></label>"
            f"<label>Type your full name<input name=name maxlength=200></label>"
            f"<label><input type=checkbox name=consent value=yes style='width:auto'> I have read this agreement and agree to sign it electronically</label><br>"
            f"<button type=submit {'disabled' if not turn else ''}>Sign</button></form>"
            f"<form method=post action='/sign/{e(a.id)}?t={t}'><input type=hidden name=action value=decline><button type=submit>Decline to sign</button></form>")


@page.get("/sign/{aid}", response_class=HTMLResponse)
def sign_page(aid: str, request: Request, t: str = "", db: Session = Depends(get_db)):
    ratelimit.check(f"sign-page:{request.client.host if request.client else ''}", 120, 3600)
    a, p, problem = _open(db, aid, t)
    if p is None:
        return _html("Sign", f"<h1>Sign</h1><p>{html.escape(problem)}</p>", 404)
    if not p.get("viewed"):
        p["viewed"] = True
        flag_modified(a, "parties")
        es.add_event(a, "viewed", p["email"], party=p["id"], ip=(request.client.host if request.client else "")[:64])
        db.commit()
    return _html(a.title, _form(a, p, t))


@page.post("/sign/{aid}", response_class=HTMLResponse)
async def sign_post(aid: str, request: Request, t: str = "", db: Session = Depends(get_db)):
    ip = request.client.host if request.client else ""
    ratelimit.check(f"sign-post:{ip}", 30, 3600)
    raw = await request.body()
    form = {k: v[0] for k, v in parse_qs(raw[:8192].decode("utf-8", "replace")).items()}
    a, p, problem = _open(db, aid, t)
    if p is None:
        return _html("Sign", f"<h1>Sign</h1><p>{html.escape(problem)}</p>", 404)
    action = form.get("action")
    if action == "code":
        es.send_code(a, p)
        flag_modified(a, "parties")
        db.commit()
        return _html(a.title, _form(a, p, t, ok=f"A code was sent to {p['email']}. It works for {es.CODE_MINUTES} minutes."))
    if action == "decline":
        p["status"] = "declined"
        a.status = "declined"
        flag_modified(a, "parties")
        es.add_event(a, "declined", p["email"], party=p["id"], ip=ip[:64])
        audit.record(db, p["email"], "agreement.declined", a.title, a.tenant_id, agreement=a.id)
        db.commit()
        return _html(a.title, "<h1>Declined</h1><p>You declined to sign. The sender has been told.</p>")
    try:
        es.sign(a, p, form.get("code", ""), form.get("name", ""), form.get("consent") == "yes", ip, request.headers.get("user-agent", ""))
    except ValueError as exc:
        flag_modified(a, "parties")
        db.commit()
        return _html(a.title, _form(a, p, t, msg=str(exc)), 422)
    flag_modified(a, "parties")
    audit.record(db, p["email"], "agreement.signed", a.title, a.tenant_id, agreement=a.id, completed=a.status == "completed")
    db.commit()
    return _html(a.title, f"<h1>Signed</h1><p>Thank you, {html.escape(p['name'])}. "
                          f"{'Everyone has now signed; you will receive the completion record by email.' if a.status == 'completed' else 'The next signer has been asked.'}</p>")
