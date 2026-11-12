"""Email security: shadow-mode scanning of customers' Microsoft 365 mail (email_scan.py).

Seeing scanned messages and labelling them needs ``respond`` (the people who handle alerts); switching scanning on or
off for a customer needs ``configure``. Everything is limited to the customers the user can see.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit, email_actions, email_model, email_scan, mail_gateway, ratelimit
from ..db import get_db
from ..deps import Principal, current_principal, scoped_tenant
from ..models import BackgroundJob, EmailGatewayDomain, EmailListEntry, EmailModel, EmailScan, EmailScanSetting, M365Connection
from .documentation import owned

router = APIRouter(prefix="/api/console/email-security", tags=["Email security"])
public = APIRouter(prefix="/api/public/email-release", tags=["Email security"])


class SettingIn(BaseModel):
    mode: Literal["off", "shadow", "protect"]
    retentionDays: int | None = Field(default=None, ge=7, le=730)
    actions: dict[str, Literal["quarantine", "junk", "tag", "none"]] | None = None
    notify: dict | None = None


class ReleaseIn(BaseModel):
    allowSender: bool = False


class ListIn(BaseModel):
    tenantId: str
    kind: Literal["allow", "block"]
    match: Literal["sender", "domain", "ip", "url", "hash", "subject"]
    value: str = Field(min_length=3, max_length=320)
    note: str = Field(default="", max_length=300)
    expiresAt: datetime | None = None


class LabelIn(BaseModel):
    label: Literal["phish", "malware", "spam", "safe", ""]


@router.get("/overview")
def overview(tenant_id: str | None = None, days: int = Query(7, ge=1, le=90),
             principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    return email_scan.overview(db, scoped_tenant(principal, tenant_id), days)


@router.get("/connections")
def connections(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Every Microsoft 365 connection the user can see, with its email security setting."""
    principal.require("respond")
    tenants = scoped_tenant(principal, tenant_id)
    rows = db.execute(select(M365Connection).where(M365Connection.tenant_id.in_(tenants))).scalars().all()
    settings = {s.connection_id: s for s in db.execute(select(EmailScanSetting).where(
        EmailScanSetting.connection_id.in_([r.id for r in rows]))).scalars()} if rows else {}
    return [email_scan.setting_view(settings.get(r.id), r) for r in sorted(rows, key=lambda r: (r.tenant_name or r.name).lower())]


@router.put("/connections/{connection_id}")
def configure(connection_id: str, body: SettingIn, principal: Principal = Depends(current_principal),
              db: Session = Depends(get_db)):
    principal.require("configure")
    connection = owned(db, M365Connection, connection_id, principal)
    if body.mode != "off" and (connection.auth_mode or "app") == "gdap":
        raise HTTPException(409, "Reading mail needs an app connection (admin sign-in or the Fenrir app). Microsoft does "
                                 "not let a partner (GDAP) connection read mailboxes.")
    try:
        setting = email_scan.configure(db, connection, body.mode, body.retentionDays, principal.actor, body.actions, body.notify)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    db.commit()
    return email_scan.setting_view(setting, connection)


@router.post("/connections/{connection_id}/scan")
def scan_now(connection_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Run one scan of this connection now (it also runs every minute on its own)."""
    principal.require("configure")
    connection = owned(db, M365Connection, connection_id, principal)
    setting = db.execute(select(EmailScanSetting).where(EmailScanSetting.connection_id == connection.id)).scalar_one_or_none()
    if setting is None or setting.mode not in ("shadow", "protect"):
        raise HTTPException(409, "Turn on email security for this customer first.")
    ratelimit.check(f"email-scan:{connection.id}", 4, 300)
    from time import monotonic

    with httpx.Client(timeout=20, follow_redirects=False) as client:
        result = email_scan.run_one(db, setting, email_scan.load_intel(db), client, monotonic() + 45)
    return {**result, "setting": email_scan.setting_view(db.get(EmailScanSetting, setting.id), connection)}


def _search(db: Session, principal: Principal, tenant_id: str | None, f: dict, limit: int) -> list[EmailScan]:
    """Explorer search: every filter is optional and they combine."""
    query = select(EmailScan).where(EmailScan.tenant_id.in_(scoped_tenant(principal, tenant_id)))
    verdict = f.get("verdict") or ""
    if verdict == "flagged":
        query = query.where(EmailScan.verdict.in_(("phish", "malware")))
    elif verdict:
        query = query.where(EmailScan.verdict == verdict)
    for key, column in (("agreement", EmailScan.agreement), ("source", EmailScan.source), ("folder", EmailScan.folder),
                        ("actionStatus", EmailScan.action_status), ("microsoftVerdict", EmailScan.microsoft_verdict)):
        if f.get(key):
            query = query.where(column == f[key])
    if f.get("action"):
        query = query.where(EmailScan.action == f["action"])
    label = f.get("label") or ""
    if label == "any":
        query = query.where(EmailScan.label != "")
    elif label:
        query = query.where(EmailScan.label == label)
    if f.get("since"):
        query = query.where(EmailScan.received_at >= f["since"].replace(tzinfo=None))
    if f.get("until"):
        query = query.where(EmailScan.received_at <= f["until"].replace(tzinfo=None))
    for key, column in (("sender", EmailScan.sender_address), ("recipient", EmailScan.mailbox),
                        ("senderDomain", EmailScan.sender_domain), ("subject", EmailScan.subject),
                        ("messageId", EmailScan.internet_message_id)):
        if (f.get(key) or "").strip():
            query = query.where(column.ilike(f"%{f[key].strip()[:200]}%"))
    if (f.get("q") or "").strip():
        like = f"%{f['q'].strip()[:100]}%"
        query = query.where(or_(EmailScan.subject.ilike(like), EmailScan.sender_address.ilike(like),
                                EmailScan.mailbox.ilike(like), EmailScan.sender_domain.ilike(like),
                                EmailScan.internet_message_id.ilike(like)))
    if f.get("minScore") is not None:
        query = query.where(EmailScan.score >= f["minScore"])
    rows = db.execute(query.order_by(EmailScan.received_at.desc()).limit(limit if not _deep(f) else min(5000, limit * 20))).scalars().all()
    if _deep(f):  # filters on the evidence (JSON): checked here, on the newest matches
        rows = [r for r in rows if _deep_match(r, f)][:limit]
    return rows


def _deep(f: dict) -> bool:
    return any((f.get(k) or "").strip() for k in ("ip", "attachment", "hash", "link", "classification", "decidedBy", "country"))


def _deep_match(row: EmailScan, f: dict) -> bool:
    d = row.details or {}
    origin = d.get("origin") or {}
    decision = d.get("decision") or {}
    checks = {
        "ip": lambda v: v in str(origin.get("ip") or "") or v in str((row.microsoft or {}).get("peer") or ""),
        "country": lambda v: v.upper() == str(origin.get("country") or (row.microsoft or {}).get("country") or "").upper(),
        "attachment": lambda v: any(v.lower() in str(a.get("name") or "").lower() for a in row.attachments or []),
        "hash": lambda v: any(v.lower() == str(a.get("sha256") or "").lower() for a in row.attachments or []),
        "link": lambda v: any(v.lower() in str(l).lower() for l in row.link_domains or [])
        or any(v.lower() in str(l.get("url") or "").lower() for l in d.get("links") or []),
        "classification": lambda v: decision.get("classification") == v,
        "decidedBy": lambda v: v.lower() in str(decision.get("decidedBy") or "").lower(),
    }
    return all(check(f[key].strip()) for key, check in checks.items() if (f.get(key) or "").strip())


def _filters(verdict: str, agreement: str, label: str, q: str, since: datetime | None, until: datetime | None, sender: str,
             recipient: str, sender_domain: str, subject: str, message_id: str, ip: str, attachment: str, hash: str,
             link: str, classification: str, decided_by: str, action: str, action_status: str, source: str, folder: str,
             country: str, microsoft_verdict: str, min_score: int | None) -> dict:
    return {"verdict": verdict, "agreement": agreement, "label": label, "q": q, "since": since, "until": until,
            "sender": sender, "recipient": recipient, "senderDomain": sender_domain, "subject": subject,
            "messageId": message_id, "ip": ip, "attachment": attachment, "hash": hash, "link": link,
            "classification": classification, "decidedBy": decided_by, "action": action, "actionStatus": action_status,
            "source": source, "folder": folder, "country": country, "microsoftVerdict": microsoft_verdict, "minScore": min_score}


@router.get("/messages")
def messages(tenant_id: str | None = None, verdict: str = "", agreement: str = "", label: str = "", q: str = "",
             since: datetime | None = None, until: datetime | None = None, sender: str = "", recipient: str = "",
             sender_domain: str = "", subject: str = "", message_id: str = "", ip: str = "", attachment: str = "",
             hash: str = "", link: str = "", classification: str = "", decided_by: str = "", action: str = "",
             action_status: str = "", source: str = "", folder: str = "", country: str = "", microsoft_verdict: str = "",
             min_score: int | None = None, limit: int = Query(100, ge=1, le=500),
             principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Explorer: search every checked message by sender, recipient, subject, Message-ID, IP, country, attachment name
    or hash, link, verdict, classification, the policy or rule that decided, action and more."""
    principal.require("respond")
    f = _filters(verdict, agreement, label, q, since, until, sender, recipient, sender_domain, subject, message_id, ip,
                 attachment, hash, link, classification, decided_by, action, action_status, source, folder, country,
                 microsoft_verdict, min_score)
    return [email_scan.scan_view(r) for r in _search(db, principal, tenant_id, f, limit)]


@router.get("/messages.csv")
def messages_csv(tenant_id: str | None = None, verdict: str = "", agreement: str = "", label: str = "", q: str = "",
                 since: datetime | None = None, until: datetime | None = None, sender: str = "", recipient: str = "",
                 sender_domain: str = "", subject: str = "", message_id: str = "", ip: str = "", attachment: str = "",
                 hash: str = "", link: str = "", classification: str = "", decided_by: str = "", action: str = "",
                 action_status: str = "", source: str = "", folder: str = "", country: str = "", microsoft_verdict: str = "",
                 min_score: int | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The same search as a spreadsheet (up to 5,000 rows)."""
    import csv
    import io

    principal.require("respond")
    f = _filters(verdict, agreement, label, q, since, until, sender, recipient, sender_domain, subject, message_id, ip,
                 attachment, hash, link, classification, decided_by, action, action_status, source, folder, country,
                 microsoft_verdict, min_score)
    rows = _search(db, principal, tenant_id, f, 5000)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["received_utc", "mailbox", "sender", "sender_name", "subject", "message_id", "source", "folder", "verdict",
                     "score", "classification", "decided_by", "action", "action_status", "microsoft_verdict", "originating_ip",
                     "country", "spf", "dkim", "dmarc", "attachments", "link_domains", "top_reason", "label"])
    for r in rows:
        d = r.details or {}
        origin, decision, ms = d.get("origin") or {}, d.get("decision") or {}, r.microsoft or {}
        cells = [r.received_at.isoformat(), r.mailbox, r.sender_address, r.sender_name, r.subject, r.internet_message_id,
                 r.source or "graph", r.folder, r.verdict, r.score, decision.get("classification", ""), decision.get("decidedBy", ""),
                 r.action or "", r.action_status or "", r.microsoft_verdict, origin.get("ip") or ms.get("peer", ""),
                 origin.get("country") or ms.get("country", ""), ms.get("spf", ""), ms.get("dkim", ""), ms.get("dmarc", ""),
                 "; ".join(a.get("name", "") for a in r.attachments or []), "; ".join(r.link_domains or []),
                 (r.reasons or [{}])[0].get("detail", "") if r.reasons else "", r.label]
        # Spreadsheet formula injection: text starting with = + - @ is prefixed so Excel shows it as text.
        writer.writerow(["'" + c if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in cells])
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="fenrir-email-explorer.csv"'})


@router.get("/messages/{scan_id}")
def message(scan_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    return email_scan.scan_view(owned(db, EmailScan, scan_id, principal), full=True)


@router.put("/messages/{scan_id}/label")
def set_label(scan_id: str, body: LabelIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """A technician's call on a message: what it really was. These labels are what a model is trained on later."""
    principal.require("respond")
    row = owned(db, EmailScan, scan_id, principal)
    email_scan.label(db, row, body.label, principal.actor)
    db.commit()
    return email_scan.scan_view(row, full=True)


@router.post("/messages/{scan_id}/release")
def release(scan_id: str, body: ReleaseIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Bring a quarantined or junked message back to the user's Inbox (and optionally allow its sender from now on)."""
    principal.require("respond")
    row = owned(db, EmailScan, scan_id, principal)
    try:
        email_actions.release(db, row, principal.actor)
    except email_actions.ActionError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from None
    except httpx.HTTPError:
        db.rollback()
        raise HTTPException(502, "Microsoft did not accept the release. Try again in a minute.") from None
    if body.allowSender and row.sender_address:
        _add_entry(db, row.tenant_id, "allow", "sender", row.sender_address, f"Released by {principal.actor}", principal.actor)
    db.commit()
    return email_scan.scan_view(row, full=True)


def _add_entry(db: Session, tenant_id: str, kind: str, match: str, value: str, note: str, actor: str,
               expires_at: datetime | None = None) -> EmailListEntry:
    import ipaddress
    import re as _re

    value = value.strip().lower().lstrip("@") if match != "subject" else value.strip().lower()
    if match == "sender" and ("@" not in value or " " in value):
        raise HTTPException(400, "Enter a full email address, like accounts@supplier.co.uk")
    if match == "domain" and ("@" in value or "." not in value or " " in value):
        raise HTTPException(400, "Enter a domain, like supplier.co.uk")
    if match == "ip":
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise HTTPException(400, "Enter an IP address or range, like 203.0.113.7 or 203.0.113.0/24") from None
    if match == "url":
        value = value.removeprefix("https://").removeprefix("http://").split("/")[0]
        if "." not in value or " " in value:
            raise HTTPException(400, "Enter the link's domain, like bad-site.example")
    if match == "hash" and not _re.fullmatch(r"[0-9a-f]{64}", value):
        raise HTTPException(400, "Enter a SHA-256 hash (64 hexadecimal characters)")
    if match == "subject" and len(value) < 3:
        raise HTTPException(400, "Enter at least three characters of the subject")
    existing = db.execute(select(EmailListEntry).where(EmailListEntry.tenant_id == tenant_id, EmailListEntry.kind == kind,
                                                       EmailListEntry.match == match, EmailListEntry.value == value)).scalar_one_or_none()
    if existing:
        return existing
    other = "block" if kind == "allow" else "allow"
    db.query(EmailListEntry).filter_by(tenant_id=tenant_id, kind=other, match=match, value=value).delete()
    entry = EmailListEntry(tenant_id=tenant_id, kind=kind, match=match, value=value, note=note[:300], created_by=actor,
                           expires_at=expires_at.replace(tzinfo=None) if expires_at else None, hits=0)
    db.add(entry)
    audit.record(db, actor, f"email_security.{kind}_listed", value, tenant_id, match=match)
    return entry


def _entry_view(entry: EmailListEntry) -> dict:
    from ..models import utcnow

    return {"id": entry.id, "tenantId": entry.tenant_id, "kind": entry.kind, "match": entry.match, "value": entry.value,
            "note": entry.note, "createdBy": entry.created_by, "createdAt": entry.created_at.isoformat() + "Z",
            "expiresAt": entry.expires_at.isoformat() + "Z" if entry.expires_at else None,
            "expired": bool(entry.expires_at and entry.expires_at <= utcnow()), "hits": entry.hits or 0,
            "lastHitAt": entry.last_hit_at.isoformat() + "Z" if entry.last_hit_at else None}


@router.get("/lists")
def lists(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("respond")
    rows = db.execute(select(EmailListEntry).where(EmailListEntry.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(EmailListEntry.kind, EmailListEntry.value)).scalars().all()
    return [_entry_view(r) for r in rows]


@router.post("/lists")
def add_list_entry(body: ListIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Allow or block a sender address or domain for a customer. An entry on the MSP's own tenant covers every customer."""
    principal.require("configure")
    principal.check_tenant(body.tenantId)
    entry = _add_entry(db, body.tenantId, body.kind, body.match, body.value, body.note, principal.actor, body.expiresAt)
    db.commit()
    return _entry_view(entry)


@router.delete("/lists/{entry_id}")
def remove_list_entry(entry_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("configure")
    entry = owned(db, EmailListEntry, entry_id, principal)
    audit.record(db, principal.actor, f"email_security.{entry.kind}_unlisted", entry.value, entry.tenant_id, match=entry.match)
    db.delete(entry)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- mailbox owners asking for a message back

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Held-back message</title>
<style>body{{font-family:system-ui,sans-serif;max-width:560px;margin:48px auto;padding:0 16px;color:#1f2937}}
button{{font-size:16px;padding:10px 18px;border-radius:6px;border:0;background:#2563eb;color:#fff;cursor:pointer}}
.muted{{color:#6b7280}}</style></head><body>{body}</body></html>"""


def _page(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(PAGE.format(body=body), status_code=status, headers={"Cache-Control": "no-store"})


def _requested_scan(db: Session, scan_id: str, t: str) -> EmailScan | None:
    row = db.get(EmailScan, scan_id)
    return row if row is not None and email_actions.valid_token(scan_id, t) else None


@public.get("/{scan_id}", response_class=HTMLResponse)
def release_page(scan_id: str, t: str = "", db: Session = Depends(get_db)):
    """Shows the message and a button. Opening the link changes nothing, so link scanners cannot request releases."""
    from html import escape

    row = _requested_scan(db, scan_id, t)
    if row is None:
        return _page("<h1>Link not valid</h1><p>This link has expired or is incomplete. Ask your IT team for help.</p>", 404)
    if row.action_status == "release_requested":
        return _page("<h1>Already requested</h1><p>Your IT team has been asked to check this message.</p>")
    if row.action_status == "released":
        return _page("<h1>Released</h1><p>This message is back in your Inbox.</p>")
    return _page(f"<h1>Ask for this message back?</h1><p><b>From:</b> {escape(row.sender_address)}<br><b>Subject:</b> "
                 f"{escape(row.subject)}<br><b>Received:</b> {row.received_at:%d %b %Y %H:%M} UTC</p>"
                 "<p class=\"muted\">It was held back because it looks like phishing or malware. Only ask for it if you "
                 "were expecting it. IT will check it before it reaches your Inbox.</p>"
                 f"<form method=\"post\" action=\"?t={escape(t)}\">"
                 "<button type=\"submit\">Ask IT to release it</button></form>")


@public.post("/{scan_id}", response_class=HTMLResponse)
def request_release(scan_id: str, t: str = "", db: Session = Depends(get_db)):
    ratelimit.check(f"email-release:{scan_id}", 5, 3600)
    row = _requested_scan(db, scan_id, t)
    if row is None:
        return _page("<h1>Link not valid</h1><p>This link has expired or is incomplete. Ask your IT team for help.</p>", 404)
    if email_actions.request_release(db, row):
        db.commit()
    return _page("<h1>Request sent</h1><p>Your IT team has been asked to check this message. If it is safe they will "
                 "release it to your Inbox.</p>")


# --------------------------------------------------------------------------- the learned model

@router.get("/model")
def model(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The model in use (if any), the latest version and its measurements, and the history."""
    principal.require("respond")
    rows = db.execute(select(EmailModel).order_by(EmailModel.version.desc()).limit(20)).scalars().all()
    current = next((r for r in rows if r.active), None)
    # Labels: only the customers this user can see. The shared model's example counts span every customer, so only
    # MSP staff see them; a customer's own users see whether a model is in use and how accurate it is.
    labels = dict(db.execute(select(EmailScan.label, func.count()).where(
        EmailScan.label != "", EmailScan.tenant_id.in_(list(principal.tenant_ids))).group_by(EmailScan.label)).all())
    msp = principal.can("manage_tenants")

    def shown(row):
        out = email_model.view(row)
        if out is not None and not msp:
            out.update(samples=None, positives=None, labelled=None, strongestSignals=[],
                       metrics={k: v for k, v in (out.get("metrics") or {}).items() if k in ("precision", "recall")})
        return out

    return {"active": shown(current), "latest": shown(rows[0] if rows else None),
            "history": [shown(r) for r in rows], "labels": labels,
            "requirements": {"samples": email_model.MIN_SAMPLES, "positives": email_model.MIN_POSITIVES,
                             "precision": email_model.MIN_PRECISION, "recall": email_model.MIN_RECALL,
                             "threshold": email_model.THRESHOLD}}


@router.post("/model/train")
def train_model(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Train a new version now. It is used only if it measures well enough on messages it did not learn from."""
    principal.require("configure")
    if not principal.can("platform") and not principal.can("manage_tenants"):
        raise HTTPException(403, "Only MSP administrators can retrain the shared model")
    ratelimit.check("email-model-train", 3, 600)
    row = email_model.train(db, principal.actor)
    audit.record(db, principal.actor, "email_security.model_trained", row.id, None, version=row.version, active=row.active)
    db.commit()
    return email_model.view(row)


# --------------------------------------------------------------------------- the mail gateway

class GatewayDomainIn(BaseModel):
    tenantId: str | None = None
    domain: str | None = Field(default=None, max_length=253)
    destination: str | None = Field(default=None, max_length=255)
    destinationPort: int | None = Field(default=None, ge=1, le=65535)
    requireTls: bool | None = None
    rejectUnknownRecipients: bool | None = None
    tagSubject: bool | None = None
    actions: dict[str, Literal["quarantine", "tag", "deliver"]] | None = None
    notify: dict | None = None
    retentionDays: int | None = Field(default=None, ge=7, le=730)
    enabled: bool | None = None


class ConnectIn(BaseModel):
    lockdown: bool = False


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _gateway_ips() -> list[str]:
    import ipaddress

    out = []
    for part in mail_gateway.env("FENRIR_GATEWAY_PUBLIC_IPS").split(","):
        try:
            out.append(str(ipaddress.ip_address(part.strip())))
        except ValueError:
            continue
    return out


@router.get("/gateway")
def gateway(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The domains routed through the gateway, and whether the gateway process is running."""
    principal.require("respond")
    rows = db.execute(select(EmailGatewayDomain).where(EmailGatewayDomain.tenant_id.in_(scoped_tenant(principal, tenant_id)))
                      .order_by(EmailGatewayDomain.domain)).scalars().all()
    job = db.get(BackgroundJob, "email.gateway")
    return {"domains": [mail_gateway.domain_view(r) for r in rows],
            "status": {"lastRunAt": job.last_run_at.isoformat() + "Z" if job and job.last_run_at else None,
                       "ok": bool(job.ok) if job else None, "error": job.error if job else "",
                       "hostname": mail_gateway.env("FENRIR_GATEWAY_HOSTNAME") or None, "publicIps": _gateway_ips()}}


def _apply(row: EmailGatewayDomain, body: GatewayDomainIn) -> None:
    if body.destination is not None:
        destination = body.destination.strip().lower().rstrip(".")
        if not mail_gateway.DOMAIN.match(destination) and not _is_ip(destination):
            raise HTTPException(400, "The destination must be a host name, like contoso-co-uk.mail.protection.outlook.com")
        row.destination = destination
    for field, attribute in (("destinationPort", "destination_port"), ("requireTls", "require_tls"),
                             ("rejectUnknownRecipients", "reject_unknown_recipients"), ("tagSubject", "tag_subject"),
                             ("retentionDays", "retention_days"), ("enabled", "enabled")):
        value = getattr(body, field)
        if value is not None:
            setattr(row, attribute, value)
    if body.actions is not None:
        row.actions = {**mail_gateway.actions_for(row), **{k: v for k, v in body.actions.items() if k in mail_gateway.DEFAULT_ACTIONS}}
    if body.notify is not None:
        email = str(body.notify.get("alertEmail") or "").strip()
        if email and "@" not in email:
            raise HTTPException(400, "The alert email address is not valid")
        row.notify = {"digest": bool(body.notify.get("digest")), "alertEmail": email, "openTicket": bool(body.notify.get("openTicket"))}


@router.post("/gateway/domains")
def add_gateway_domain(body: GatewayDomainIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Route a customer domain through the gateway. The domain must be verified in the customer's Microsoft 365."""
    principal.require("configure")
    if not body.tenantId or not body.domain:
        raise HTTPException(400, "Choose the customer and enter the domain")
    principal.check_tenant(body.tenantId)
    domain = body.domain.strip().lower().rstrip(".")
    if not mail_gateway.DOMAIN.match(domain):
        raise HTTPException(400, "Enter a domain, like contoso.co.uk")
    if domain not in mail_gateway.verified_domains(db, body.tenantId):
        raise HTTPException(400, f"{domain} is not a verified domain in this customer's Microsoft 365. Sync the Microsoft 365 "
                                 "connection, or verify the domain in Microsoft 365 first.")
    if db.execute(select(EmailGatewayDomain).where(EmailGatewayDomain.domain == domain)).scalar_one_or_none():
        raise HTTPException(409, f"{domain} is already routed through the gateway")
    row = EmailGatewayDomain(tenant_id=body.tenantId, domain=domain, destination=mail_gateway.default_destination(domain),
                             actions=dict(mail_gateway.DEFAULT_ACTIONS), notify={}, m365_connector={}, created_by=principal.actor)
    _apply(row, body)
    db.add(row)
    audit.record(db, principal.actor, "email_security.gateway_domain_added", domain, body.tenantId, destination=row.destination)
    db.commit()
    return mail_gateway.domain_view(row)


@router.put("/gateway/domains/{domain_id}")
def update_gateway_domain(domain_id: str, body: GatewayDomainIn, principal: Principal = Depends(current_principal),
                          db: Session = Depends(get_db)):
    principal.require("configure")
    row = owned(db, EmailGatewayDomain, domain_id, principal)
    _apply(row, body)
    audit.record(db, principal.actor, "email_security.gateway_domain_changed", row.domain, row.tenant_id)
    db.commit()
    return mail_gateway.domain_view(row)


@router.delete("/gateway/domains/{domain_id}")
def remove_gateway_domain(domain_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Stop accepting mail for the domain. Change its MX record back to Microsoft 365 first."""
    principal.require("configure")
    row = owned(db, EmailGatewayDomain, domain_id, principal)
    audit.record(db, principal.actor, "email_security.gateway_domain_removed", row.domain, row.tenant_id)
    db.delete(row)
    db.commit()
    return {"ok": True}


@router.post("/gateway/domains/{domain_id}/connect-m365")
def connect_m365(domain_id: str, body: ConnectIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Create the customer's Microsoft 365 inbound connector for the gateway (Exchange Online admin access needed)."""
    principal.require("m365_admin")
    row = owned(db, EmailGatewayDomain, domain_id, principal)
    ratelimit.check(f"email-gateway-connect:{row.id}", 3, 600)
    try:
        result = mail_gateway.connect_m365(db, row, _gateway_ips(), body.lockdown, principal.actor)
    except email_actions.ActionError as exc:
        db.commit()  # keep the failure on the domain
        raise HTTPException(409, str(exc)) from None
    db.commit()
    return {"m365Connector": result, "domain": mail_gateway.domain_view(row)}


# --------------------------------------------------------------------------- the original message, for analysis

@router.get("/messages/{scan_id}/original")
def original(scan_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The message exactly as received (.eml), for analysis in a mail client or sandbox. Mailbox messages are fetched
    from Microsoft 365 on demand; gateway messages are available while Fenrir holds them in quarantine. Every download
    is in the audit log. It may contain malware: open it only somewhere safe."""
    principal.require("respond")
    row = owned(db, EmailScan, scan_id, principal)
    ratelimit.check(f"email-original:{principal.actor}", 30, 600)
    if (row.source or "graph") == "gateway":
        from ..models import EmailQuarantine
        from .. import crypto

        held = db.execute(select(EmailQuarantine).where(EmailQuarantine.scan_id == row.id)).scalar_one_or_none()
        if held is None:
            raise HTTPException(404, "Fenrir only keeps gateway messages it holds in quarantine; this one was delivered.")
        raw = crypto.decrypt_bytes(held.envelope, f"email-quarantine:{row.id}")
    else:
        from urllib.parse import quote

        from .. import m365

        connection = db.get(M365Connection, row.connection_id)
        if connection is None:
            raise HTTPException(404, "The customer's Microsoft 365 connection no longer exists.")
        try:
            user_id = email_actions._user_id(connection, row.mailbox)
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                token = m365.access_token(client, connection)
                response = client.get(f"{m365.GRAPH}/users/{quote(user_id)}/messages/"
                                      f"{quote(row.moved_message_id or row.message_id, safe='')}/$value",
                                      headers={"Authorization": "Bearer " + token})
        except email_actions.ActionError as exc:
            raise HTTPException(404, str(exc)) from None
        except httpx.HTTPError:
            raise HTTPException(502, "Microsoft 365 could not be reached.") from None
        if response.status_code == 404:
            raise HTTPException(404, "The message is no longer in the mailbox.")
        if response.status_code >= 400:
            raise HTTPException(502, f"Microsoft 365 would not provide the message (HTTP {response.status_code}).")
        raw = response.content
    audit.record(db, principal.actor, "email_security.original_downloaded", row.id, row.tenant_id, mailbox=row.mailbox,
                 subject=row.subject[:120])
    db.commit()
    return Response(raw, media_type="message/rfc822",
                    headers={"Content-Disposition": f'attachment; filename="fenrir-{row.id}.eml"', "Cache-Control": "no-store",
                             "X-Content-Type-Options": "nosniff"})


# --------------------------------------------------------------------------- the message body, safely

@router.get("/messages/{scan_id}/content")
def content(scan_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """The body, made safe to look at (no scripts, styles, remote images or live links) with the suspicious wording and
    links highlighted. Kept copies are used first; mailbox messages are otherwise read from Microsoft 365 now. Audited."""
    from .. import crypto, email_content

    principal.require("respond")
    row = owned(db, EmailScan, scan_id, principal)
    ratelimit.check(f"email-content:{principal.actor}", 120, 600)
    try:
        kept = email_content.stored(db, row)
    except crypto.VaultError:
        kept = None
    if kept is not None:
        html, source = kept.get("html", ""), "kept"
    elif (row.source or "graph") == "gateway":
        from ..models import EmailQuarantine

        held = db.execute(select(EmailQuarantine).where(EmailQuarantine.scan_id == row.id)).scalar_one_or_none()
        if held is None:
            raise HTTPException(404, "Fenrir did not keep this message's body (it was clean and delivered). Change the policy's "
                                     "'keep message content' setting to keep more.")
        message, _ = mail_gateway.parse(crypto.decrypt_bytes(held.envelope, f"email-quarantine:{row.id}"), "")
        html, source = message.body_html, "quarantine"
    else:
        from urllib.parse import quote

        from .. import m365

        connection = db.get(M365Connection, row.connection_id)
        if connection is None:
            raise HTTPException(404, "The customer's Microsoft 365 connection no longer exists.")
        try:
            user_id = email_actions._user_id(connection, row.mailbox)
            with httpx.Client(timeout=30, follow_redirects=False) as client:
                token = m365.access_token(client, connection)
                response = client.get(f"{m365.GRAPH}/users/{quote(user_id)}/messages/"
                                      f"{quote(row.moved_message_id or row.message_id, safe='')}?$select=body",
                                      headers={"Authorization": "Bearer " + token, "Prefer": 'outlook.body-content-type="html"'})
        except email_actions.ActionError as exc:
            raise HTTPException(404, str(exc)) from None
        except httpx.HTTPError:
            raise HTTPException(502, "Microsoft 365 could not be reached.") from None
        if response.status_code == 404:
            raise HTTPException(404, "The message is no longer in the mailbox, and Fenrir did not keep its body.")
        if response.status_code >= 400:
            raise HTTPException(502, f"Microsoft 365 would not provide the message (HTTP {response.status_code}).")
        html, source = str((response.json().get("body") or {}).get("content") or ""), "mailbox"
    audit.record(db, principal.actor, "email_security.content_viewed", row.id, row.tenant_id, mailbox=row.mailbox, source=source)
    db.commit()
    return email_content.view(row, html, source)


# --------------------------------------------------------------------------- campaigns: related messages together

def _subject_key(subject: str) -> str:
    import re as _re

    text = _re.sub(r"^((re|fw|fwd|aw|sv)\s*:\s*)+", "", (subject or "").strip(), flags=_re.I).lower()
    return _re.sub(r"[0-9]+", "#", _re.sub(r"\s+", " ", text))[:120]


@router.get("/campaigns")
def campaigns(tenant_id: str | None = None, days: int = Query(7, ge=1, le=90), all_mail: bool = False,
              principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Messages grouped by sender domain and subject (numbers ignored): how many, to whom, how Fenrir and Microsoft
    judged them, and what was done. Only flagged mail by default."""
    from datetime import timedelta

    from ..models import utcnow

    principal.require("respond")
    query = select(EmailScan).where(EmailScan.tenant_id.in_(scoped_tenant(principal, tenant_id)),
                                    EmailScan.received_at >= utcnow() - timedelta(days=days))
    if not all_mail:
        query = query.where(or_(EmailScan.verdict != "clean", EmailScan.microsoft_verdict.in_(("phish", "malware", "spam"))))
    groups: dict[tuple, dict] = {}
    for row in db.execute(query.order_by(EmailScan.received_at.desc()).limit(20000)).scalars():
        key = (row.sender_domain, _subject_key(row.subject))
        g = groups.setdefault(key, {"senderDomain": row.sender_domain, "subjectKey": key[1], "subject": row.subject,
                                    "messages": 0, "recipients": set(), "tenants": set(), "verdicts": {}, "actions": {},
                                    "first": row.received_at, "last": row.received_at, "senders": set(), "maxScore": 0})
        g["messages"] += 1
        g["recipients"].add(row.mailbox)
        g["tenants"].add(row.tenant_id)
        g["senders"].add(row.sender_address)
        g["verdicts"][row.verdict] = g["verdicts"].get(row.verdict, 0) + 1
        if row.action:
            g["actions"][row.action] = g["actions"].get(row.action, 0) + 1
        g["first"], g["last"] = min(g["first"], row.received_at), max(g["last"], row.received_at)
        g["maxScore"] = max(g["maxScore"], row.score or 0)
    out = []
    for g in groups.values():
        out.append({**g, "recipients": len(g["recipients"]), "tenants": len(g["tenants"]), "senders": sorted(g["senders"])[:10],
                    "first": g["first"].isoformat() + "Z", "last": g["last"].isoformat() + "Z"})
    out.sort(key=lambda g: (-g["messages"], -g["maxScore"]))
    return out[:300]


class PurgeIn(BaseModel):
    tenantId: str | None = None
    senderDomain: str = ""
    subjectKey: str = ""
    sender: str = ""
    messageId: str = ""
    days: int = Field(default=7, ge=1, le=90)
    action: Literal["quarantine", "delete"] = "quarantine"
    preview: bool = True


@router.post("/campaigns/purge")
def purge(body: PurgeIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Remove matching messages from every mailbox they reached: to Fenrir's quarantine (can be released) or deleted
    for good. ``preview`` lists what would be touched without changing anything. Needs Mail.ReadWrite."""
    from datetime import timedelta

    from .. import m365
    from ..models import utcnow

    principal.require("configure")
    if not (body.senderDomain or body.sender or body.messageId):
        raise HTTPException(400, "Choose the messages: a sender, a sender domain (with an optional subject) or a Message-ID")
    query = select(EmailScan).where(EmailScan.tenant_id.in_(scoped_tenant(principal, body.tenantId)),
                                    EmailScan.received_at >= utcnow() - timedelta(days=body.days),
                                    or_(EmailScan.source.is_(None), EmailScan.source == "graph"))
    if body.senderDomain:
        query = query.where(EmailScan.sender_domain == body.senderDomain.lower())
    if body.sender:
        query = query.where(EmailScan.sender_address == body.sender.lower())
    if body.messageId:
        query = query.where(EmailScan.internet_message_id == body.messageId)
    rows = [r for r in db.execute(query.limit(2000)).scalars() if not body.subjectKey or _subject_key(r.subject) == body.subjectKey]
    if body.action == "quarantine":  # already quarantined or deleted: nothing to do
        rows = [r for r in rows if r.action_status != "deleted" and not (r.action == "quarantine" and r.action_status == "done")]
    else:
        rows = [r for r in rows if r.action_status != "deleted"]
    if body.preview:
        return {"matched": len(rows), "mailboxes": sorted({r.mailbox for r in rows})[:200],
                "messages": [email_scan.scan_view(r) for r in rows[:50]]}
    done, failed = 0, []
    by_connection: dict[str, list[EmailScan]] = {}
    for row in rows:
        by_connection.setdefault(row.connection_id, []).append(row)
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        for connection_id, items in by_connection.items():
            connection = db.get(M365Connection, connection_id)
            if connection is None:
                failed += [r.id for r in items]
                continue
            try:
                token = m365.access_token(client, connection)
            except (httpx.HTTPError, ValueError, KeyError):
                failed += [r.id for r in items]
                continue
            state = {}
            for row in items:
                try:
                    user_id = email_actions._user_id(connection, row.mailbox)
                    current = row.moved_message_id or row.message_id
                    if body.action == "delete":
                        email_actions.permanent_delete(client, token, user_id, current)
                        row.action, row.action_status = "delete", "deleted"
                    else:
                        folder = email_actions.quarantine_folder(client, token, user_id, state)
                        row.moved_message_id = email_actions.move(client, token, user_id, current, folder)
                        row.action, row.action_status = "quarantine", "done"
                    row.acted_at, row.action_error = utcnow(), ""
                    done += 1
                except (email_actions.ActionError, httpx.HTTPError) as exc:
                    row.action_error = str(exc)[:300]
                    failed.append(row.id)
    audit.record(db, principal.actor, "email_security.purged", body.senderDomain or body.sender or body.messageId, body.tenantId,
                 purge_action=body.action, done=done, failed=len(failed), subject=body.subjectKey[:80])
    db.commit()
    return {"done": done, "failed": len(failed)}


# --------------------------------------------------------------------------- several messages at once

class BulkIn(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=500)
    op: Literal["release", "delete", "label", "blockSender", "blockDomain", "allowSender"]
    value: str = ""


@router.post("/messages/bulk")
def bulk(body: BulkIn, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Release, delete for good, label, or block/allow the senders of many messages. Each result is reported."""
    from .. import m365
    from ..models import EmailQuarantine, utcnow

    principal.require("configure" if body.op in ("delete", "blockSender", "blockDomain", "allowSender") else "respond")
    results = {"done": 0, "failed": []}
    for scan_id in dict.fromkeys(body.ids):
        row = db.get(EmailScan, scan_id)
        if row is None or row.tenant_id not in principal.tenant_ids:
            results["failed"].append({"id": scan_id, "error": "Not found"})
            continue
        try:
            if body.op == "release":
                email_actions.release(db, row, principal.actor)
            elif body.op == "label":
                email_scan.label(db, row, body.value, principal.actor)
            elif body.op in ("blockSender", "blockDomain", "allowSender"):
                kind = "allow" if body.op == "allowSender" else "block"
                match = "domain" if body.op == "blockDomain" else "sender"
                _add_entry(db, row.tenant_id, kind, match, row.sender_domain if match == "domain" else row.sender_address,
                           f"From message: {row.subject[:200]}", principal.actor)
            elif body.op == "delete":
                if (row.source or "graph") == "gateway":
                    db.query(EmailQuarantine).filter_by(scan_id=row.id).delete()
                else:
                    connection = db.get(M365Connection, row.connection_id)
                    if connection is None:
                        raise email_actions.ActionError("The Microsoft 365 connection no longer exists.")
                    with httpx.Client(timeout=20, follow_redirects=False) as client:
                        token = m365.access_token(client, connection)
                        email_actions.permanent_delete(client, token, email_actions._user_id(connection, row.mailbox),
                                                       row.moved_message_id or row.message_id)
                row.action, row.action_status, row.acted_at = "delete", "deleted", utcnow()
                audit.record(db, principal.actor, "email_security.deleted", row.id, row.tenant_id, mailbox=row.mailbox)
            db.commit()
            results["done"] += 1
        except (email_actions.ActionError, ValueError, httpx.HTTPError, HTTPException) as exc:
            db.rollback()
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
            results["failed"].append({"id": scan_id, "error": str(detail)[:300]})
    return results
