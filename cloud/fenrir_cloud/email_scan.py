"""Email security in shadow mode: read new Microsoft 365 mail, record Microsoft's verdict and Fenrir's, act on nothing.

Every minute (``FENRIR_EMAIL_SCAN_SECONDS``, 30 to 3600, default 60), for each Microsoft 365 connection with email
security in shadow or protect mode:

1. Each licensed, enabled member mailbox is read through Microsoft Graph (application permission ``Mail.Read``):
   new messages in Inbox and Junk Email since the last run, with their headers and body, and the names, sizes and
   SHA-256 hashes of up to three attachments of 5 MB or less.
2. ``email_security.analyse`` gives Microsoft's verdict (from its headers) and Fenrir's (with reasons).
3. One ``EmailScan`` row is stored per message and mailbox: sender, subject, link domains, attachment names and
   hashes, both verdicts and the reasons. The body is never stored.

Nothing in the mailbox changes: shadow mode only compares. Technicians can label a message phish, malware, spam or
safe; those labels, with Microsoft's verdicts, are what a model is trained on later.

The first run looks back 24 hours. Each mailbox reads at most ``PER_MAILBOX`` messages per folder per run and the
whole pass stops after ``RUN_SECONDS``; the rest follows next run, oldest first, so nothing is skipped. Rows older
than the connection's retention (default 90 days) are deleted.
"""
from __future__ import annotations

import base64
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from time import monotonic
from urllib.parse import quote

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import audit, crypto, email_actions, email_content, email_policy, email_security, m365
from .models import EmailScan, EmailScanSetting, Indicator, M365Connection, utcnow

log = logging.getLogger("fenrir.email")

FOLDERS = ("inbox", "junkemail")
FIRST_WINDOW = timedelta(hours=24)
OVERLAP = timedelta(minutes=10)  # Microsoft can file a message a little after its received time
PER_MAILBOX = 100
MAX_MAILBOXES = 500
RUN_SECONDS = 60
ATTACHMENT_HASH_LIMIT = 5 * 1024 * 1024
ATTACHMENTS_HASHED = 3
SELECT = ("id,internetMessageId,receivedDateTime,subject,from,sender,replyTo,hasAttachments,internetMessageHeaders,"
          "body,categories")
MODES = ("off", "shadow", "protect")
LABELS = ("phish", "malware", "spam", "safe")


class ScanError(Exception):
    pass


# --------------------------------------------------------------------------- what Fenrir knows

def load_intel(db: Session) -> dict:
    """Threat intel for every customer, read once per run: {tenant_id or None: {urls, domains, hashes, allow}}."""
    now = utcnow()
    out: dict = {}
    rows = db.execute(select(Indicator.tenant_id, Indicator.type, Indicator.value, Indicator.verdict, Indicator.category)
                      .where(Indicator.type.in_(("url", "domain", "sha256", "ip")))
                      .where((Indicator.expires_at.is_(None)) | (Indicator.expires_at > now))).all()
    for tenant_id, kind, value, verdict, category in rows:
        bucket = out.setdefault(tenant_id, {"urls": set(), "domains": {}, "hashes": {}, "allow": set(), "ips": set()})
        value = str(value or "").strip().lower()
        if not value:
            continue
        if verdict == "allow":
            if kind == "domain":
                bucket["allow"].add(email_security.registrable(value))
            continue
        if kind == "url":
            bucket["urls"].add(value.rstrip("/"))
        elif kind == "domain":
            bucket["domains"][value.rstrip(".")] = category or "malicious"
        elif kind == "sha256":
            bucket["hashes"][value] = category or "malware"
        elif kind == "ip" and verdict == "malicious":
            bucket["ips"].add(value)
    return out


def build_context(db: Session, connection: M365Connection, intel: dict) -> email_security.Context:
    snapshot = connection.snapshot or {}
    domains = {str(d.get("id") or "").lower() for d in snapshot.get("domains") or [] if d.get("isVerified")}
    for org in snapshot.get("organization") or []:
        domains |= {str(d.get("name") or "").lower() for d in org.get("verifiedDomains") or []}
    domains.discard("")
    people = {}
    for user in snapshot.get("users") or []:
        name = email_security.normalise_name(user.get("displayName") or "")
        if name and len(name) >= 5 and (user.get("userType") or "Member") == "Member":
            people[name] = str(user.get("mail") or user.get("userPrincipalName") or "")
    merged = {"urls": set(), "domains": {}, "hashes": {}, "allow": set()}
    for key in (None, connection.tenant_id):
        bucket = intel.get(key) or {}
        merged["urls"] |= bucket.get("urls", set())
        merged["domains"].update(bucket.get("domains", {}))
        merged["hashes"].update(bucket.get("hashes", {}))
        merged["allow"] |= bucket.get("allow", set())
    known = set(db.execute(select(EmailScan.sender_domain).where(
        EmailScan.connection_id == connection.id, EmailScan.received_at >= utcnow() - timedelta(days=90))
        .distinct().limit(50000)).scalars())
    lists = list_entries(db, connection.tenant_id)
    from . import email_model

    return email_security.Context(own_domains=domains, people=people, bad_urls=merged["urls"],
                                  bad_domains=merged["domains"], bad_hashes=merged["hashes"],
                                  allowed_domains=merged["allow"], known_senders={k for k in known if k},
                                  allow_senders=lists[("allow", "sender")], allow_sender_domains=lists[("allow", "domain")],
                                  block_senders=lists[("block", "sender")], block_sender_domains=lists[("block", "domain")],
                                  model=email_model.active(db))


def record_hits(db: Session, tenant_id: str, row: EmailScan, decision: dict) -> None:
    """Count a hit on each allow or block entry that matched this message (shown on the Lists tab)."""
    from .models import EmailListEntry, Tenant

    sources = {t.get("source") for t in decision.get("trail") or []}
    codes = {r.get("code") for r in row.reasons or []}
    kinds = ({"block"} if "Block list" in sources or "list.block" in codes else set()) | \
            ({"allow"} if "Allow list" in sources or "list.allow" in codes else set())
    if not kinds:
        return
    chain, current = [], db.get(Tenant, tenant_id)
    while current is not None and len(chain) < 10:
        chain.append(current.id)
        current = db.get(Tenant, current.parent_id) if current.parent_id else None
    domain_parts = row.sender_domain.split(".") if row.sender_domain else []
    domains = {".".join(domain_parts[i:]) for i in range(len(domain_parts) - 1)}
    hashes = {str(a.get("sha256") or "").lower() for a in row.attachments or [] if a.get("sha256")}
    subject = (row.subject or "").lower()
    for entry in db.execute(select(EmailListEntry).where(EmailListEntry.tenant_id.in_(chain), EmailListEntry.kind.in_(kinds))).scalars():
        value = entry.value
        hit = (entry.match == "sender" and value == row.sender_address) or (entry.match == "domain" and value in domains) \
            or (entry.match == "url" and any(value == d or d.endswith("." + value) for d in row.link_domains or [])) \
            or (entry.match == "hash" and value in hashes) or (entry.match == "subject" and value in subject) \
            or (entry.match == "ip" and email_policy._in_ranges(str(((row.details or {}).get("origin") or {}).get("ip") or ""), [value]))
        if hit:
            entry.hits = (entry.hits or 0) + 1
            entry.last_hit_at = utcnow()


def list_entries(db: Session, tenant_id: str) -> dict:
    """The allow and block lists that apply to a customer: its own, and those of every tenant above it (the MSP's)."""
    from .models import EmailListEntry, Tenant

    chain, current = [], db.get(Tenant, tenant_id)
    while current is not None and len(chain) < 10:
        chain.append(current.id)
        current = db.get(Tenant, current.parent_id) if current.parent_id else None
    out = {(k, m): set() for k in ("allow", "block") for m in ("sender", "domain", "ip", "url", "hash", "subject")}
    now = utcnow()
    for kind, match, value in db.execute(select(EmailListEntry.kind, EmailListEntry.match, EmailListEntry.value)
                                         .where(EmailListEntry.tenant_id.in_(chain or [tenant_id]))
                                         .where((EmailListEntry.expires_at.is_(None)) | (EmailListEntry.expires_at > now))).all():
        if (kind, match) in out:
            out[(kind, match)].add(str(value).lower())
    return out


def mailboxes(connection: M365Connection) -> list[dict]:
    """Licensed, enabled member accounts with a mailbox address, from the last directory sync."""
    out = []
    for user in (connection.snapshot or {}).get("users") or []:
        if user.get("accountEnabled") is False or not user.get("assignedLicenses") or not user.get("mail"):
            continue
        if (user.get("userType") or "Member") != "Member":
            continue
        out.append({"id": str(user.get("id") or ""), "address": str(user.get("mail")).lower()})
    return [m for m in out if m["id"]][:MAX_MAILBOXES]


# --------------------------------------------------------------------------- reading mail

def _iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat() + "Z"


def _when(value) -> datetime | None:
    """A Microsoft timestamp as naive UTC (how Fenrir stores times)."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def _address(value) -> tuple[str, str]:
    email = (value or {}).get("emailAddress") or {}
    return str(email.get("address") or "").strip().lower(), str(email.get("name") or "").strip()


def _get(client: httpx.Client, url: str, token: str) -> dict:
    response = client.get(url, headers={"Authorization": "Bearer " + token, "Prefer": 'outlook.body-content-type="html"'})
    response.raise_for_status()
    return response.json()


def _attachments(client: httpx.Client, token: str, user_id: str, message_id: str) -> list[dict]:
    base = f"{m365.GRAPH}/users/{quote(user_id)}/messages/{quote(message_id, safe='')}/attachments"
    listed = _get(client, base + "?$select=id,name,contentType,size,isInline", token).get("value") or []
    out, hashed = [], 0
    for item in listed[:20]:
        if item.get("isInline"):
            continue
        entry = {"name": str(item.get("name") or "")[:200], "contentType": str(item.get("contentType") or "")[:100],
                 "size": int(item.get("size") or 0)}
        is_file = str(item.get("@odata.type") or "").endswith("fileAttachment")
        if is_file and hashed < ATTACHMENTS_HASHED and 0 < entry["size"] <= ATTACHMENT_HASH_LIMIT:
            try:
                full = _get(client, f"{base}/{quote(str(item.get('id')), safe='')}", token)
                content = base64.b64decode(full.get("contentBytes") or "", validate=False)
                entry["sha256"] = hashlib.sha256(content).hexdigest()
                members, encrypted = email_security.archive_members(entry["name"], content)
                if members or encrypted:
                    entry["members"], entry["encrypted"] = members[:100], encrypted
                hashed += 1
            except (httpx.HTTPError, ValueError):
                pass
        out.append(entry)
    return out


def _message(item: dict, mailbox: str, folder: str, attachments: list[dict]) -> email_security.Message:
    sender, name = _address(item.get("from") or item.get("sender"))
    headers = {}
    for header in item.get("internetMessageHeaders") or []:
        if isinstance(header, dict) and header.get("name"):
            headers[str(header["name"]).lower()] = str(header.get("value") or "")
    return email_security.Message(
        mailbox=mailbox, folder=folder, sender_address=sender, sender_name=name,
        reply_to=[_address(r)[0] for r in item.get("replyTo") or [] if _address(r)[0]],
        subject=str(item.get("subject") or ""), headers=headers,
        body_html=str(((item.get("body") or {}).get("content")) or "")[:500_000], attachments=attachments)


def scan_connection(db: Session, setting: EmailScanSetting, connection: M365Connection, intel: dict,
                    client: httpx.Client, deadline: float) -> int:
    """Read and score new mail for one connection. Returns how many messages were stored."""
    token = m365.access_token(client, connection)
    ctx = build_context(db, connection, intel)
    policy, policy_meta = email_policy.resolve(db, connection.tenant_id)
    ctx.policy = policy
    lists = list_entries(db, connection.tenant_id)
    bad_ips = set((intel.get(None) or {}).get("ips", set())) | set((intel.get(connection.tenant_id) or {}).get("ips", set()))
    state = dict(setting.state or {})
    boxes = mailboxes(connection)
    if not boxes:
        raise ScanError("No licensed mailboxes found yet. Sync the Microsoft 365 connection first.")
    start = int(state.get("_next") or 0) % len(boxes)
    order = boxes[start:] + boxes[:start]
    stored, moved = 0, 0
    new_rows: list[EmailScan] = []
    now = utcnow()
    for index, box in enumerate(order):
        if monotonic() >= deadline:
            state["_next"] = (start + index) % len(boxes)
            break
        cursors = dict(state.get(box["id"]) or {})
        if cursors.get("skip") and now - (_when(cursors.get("skippedAt")) or now) < timedelta(hours=24):
            continue
        skipped = False
        for folder in FOLDERS:
            since = (_when(cursors.get(folder)) or (now - FIRST_WINDOW + OVERLAP)) - OVERLAP
            condition = quote(f"receivedDateTime ge {_iso(since)}", safe="")
            url = (f"{m365.GRAPH}/users/{quote(box['id'])}/mailFolders/{folder}/messages?$filter={condition}"
                   f"&$orderby=receivedDateTime%20asc&$top=25&$select={SELECT}")
            try:
                seen = set(db.execute(select(EmailScan.message_id).where(
                    EmailScan.connection_id == connection.id, EmailScan.mailbox == box["address"],
                    EmailScan.received_at >= since - timedelta(minutes=1))).scalars())
                taken, newest = 0, None
                while url and taken < PER_MAILBOX and monotonic() < deadline:
                    page = _get(client, url, token)
                    for item in page.get("value") or []:
                        received = _when(item.get("receivedDateTime"))
                        if not received or not item.get("id"):
                            continue
                        newest = received if newest is None or received > newest else newest
                        if item["id"] in seen:
                            continue
                        seen.add(item["id"])
                        attachments = _attachments(client, token, box["id"], item["id"]) if item.get("hasAttachments") else []
                        message = _message(item, box["address"], folder, attachments)
                        result = email_security.analyse(message, ctx)
                        row = _row(connection, box["address"], folder, item, received, attachments, result)
                        row.details = _details(item, attachments, ctx, bad_ips)
                        decision = email_policy.decide(message, result, policy, {
                            "gateway": False, "recipients": [box["address"]], "ownDomains": ctx.own_domains, "lists": lists,
                            "details": row.details}, policy_meta)
                        row.details = {**(row.details or {}), "decision": decision}
                        db.add(row)
                        db.flush()
                        new_rows.append(row)
                        ctx.known_senders.add(result["sender_domain"])
                        record_hits(db, connection.tenant_id, row, decision)
                        if email_content.should_keep(policy, row.verdict, decision["action"], decision):
                            email_content.keep(db, row, message.body_html, message.subject)
                        planned = decision["action"]
                        if email_actions.acting(setting) and setting.protect_since and received >= setting.protect_since:
                            if planned in ("quarantine", "junk", "reject") and moved >= email_actions.BRAKE:
                                email_actions.apply_brake(db, setting, moved + 1)
                            elif planned != "deliver":
                                done = email_actions.act(client, token, setting, box["id"], row,
                                                         list(item.get("categories") or []), state, planned,
                                                         decision["categories"] or None)
                                moved += done in ("quarantine", "junk")
                        elif planned != "deliver":
                            row.action, row.action_status = "", ""  # shadow: recorded in the decision only
                        stored += 1
                        taken += 1
                    url = page.get("@odata.nextLink")
                    if url and not url.startswith(m365.GRAPH + "/"):
                        raise ScanError("Microsoft returned an unexpected paging link.")
                if newest:
                    cursors[folder] = _iso(newest)
                elif folder not in cursors:
                    cursors[folder] = _iso(now)
            except httpx.HTTPStatusError as exc:
                code = exc.response.status_code
                if code == 403:
                    raise ScanError("Fenrir does not have permission to read mail (Mail.Read). In Microsoft 365, "
                                    "update this connection's permissions and have an admin approve them.") from None
                if code == 404:  # no Exchange mailbox (licence without Exchange, or not provisioned yet)
                    cursors.update(skip=True, skippedAt=_iso(now))
                    skipped = True
                    break
                if code == 429:
                    state[box["id"]] = cursors
                    setting.state = state
                    raise ScanError("Microsoft is throttling mail reads for this tenant; Fenrir carries on next run.") from None
                raise
        if not skipped:
            cursors.pop("skip", None)
            cursors.pop("skippedAt", None)
        state[box["id"]] = cursors
    else:
        state["_next"] = 0
    changed = email_actions.recheck(db, setting, connection, ctx, client, token, state)
    setting.state = state
    db.flush()
    email_actions.report_run(db, setting, new_rows + changed)
    email_actions.send_digests(db, setting)
    return stored


def _details(item: dict, attachments: list[dict], ctx: email_security.Context, bad_ips: set[str]) -> dict:
    """The evidence for the console: headers, path, originating IP and so on (email_forensics.py). Never fails a scan."""
    from . import email_forensics

    try:
        headers = email_forensics.header_list([(h.get("name", ""), h.get("value", ""))
                                               for h in item.get("internetMessageHeaders") or [] if isinstance(h, dict)])
        return email_forensics.build(headers=headers, html=str(((item.get("body") or {}).get("content")) or ""),
                                     attachments=attachments, ctx=ctx, bad_ips=bad_ips)
    except Exception as exc:  # noqa: BLE001 - evidence is a bonus; the verdict is already stored
        log.warning("email evidence could not be built: %s", exc)
        return {}


def _row(connection: M365Connection, mailbox: str, folder: str, item: dict, received: datetime, attachments: list[dict],
         result: dict) -> EmailScan:
    ms = result["microsoft"]
    sender, name = _address(item.get("from") or item.get("sender"))
    return EmailScan(
        tenant_id=connection.tenant_id, connection_id=connection.id, mailbox=mailbox[:320], message_id=str(item["id"])[:200],
        internet_message_id=str(item.get("internetMessageId") or "")[:300], received_at=received, folder=folder,
        sender_address=sender[:320], sender_name=name[:200], sender_domain=result["sender_domain"][:255],
        subject=str(item.get("subject") or "")[:300],
        attachments=[{k: a[k] for k in ("name", "size", "sha256") if k in a} for a in attachments][:20],
        link_domains=result["link_domains"], microsoft_verdict=ms["verdict"],
        microsoft={k: v for k, v in ms.items() if k != "verdict"}, verdict=result["verdict"], score=result["score"],
        reasons=result["reasons"], agreement=email_security.agreement(result["verdict"], ms["verdict"]),
        features=result["features"], model_score=result.get("model_score"))


# --------------------------------------------------------------------------- the background job

def scan_interval() -> float:
    """Seconds between scans: FENRIR_EMAIL_SCAN_SECONDS (30 to 3600), default 60."""
    import os

    try:
        return float(min(3600, max(30, int(os.getenv("FENRIR_EMAIL_SCAN_SECONDS", "60")))))
    except ValueError:
        return 60.0


def loop(stop, first_delay: float = 30.0, interval: float | None = None) -> None:
    """Every minute by default, in its own thread, so reading mail never holds up the main scheduler. Each pass is
    recorded as the background job "email.shadow-scan" (Settings > Platform shows its last run and error)."""
    from . import db as database
    from .main import _run_job

    interval = interval or scan_interval()
    delay = first_delay
    while not stop.wait(delay):
        delay = interval
        session = database.session_factory()()
        try:
            _run_job(session, "email.shadow-scan", tick)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            log.warning("email security pass failed: %s", exc)
            session.rollback()
        finally:
            session.close()


def tick(db: Session) -> None:
    """Each pass: scan connections in shadow or protect mode, least recently scanned first; drop rows past retention."""
    settings = db.execute(select(EmailScanSetting).where(EmailScanSetting.mode.in_(("shadow", "protect")))
                          .order_by(EmailScanSetting.last_run_at.is_not(None), EmailScanSetting.last_run_at)).scalars().all()
    if settings:
        intel = load_intel(db)
        deadline = monotonic() + min(RUN_SECONDS, max(20.0, scan_interval() - 10))
        with httpx.Client(timeout=20, follow_redirects=False) as client:
            for setting in settings:
                if monotonic() >= deadline:
                    break
                run_one(db, setting, intel, client, deadline)
    purge(db)
    from . import email_model

    if email_model.maybe_retrain(db):
        db.commit()


def run_one(db: Session, setting: EmailScanSetting, intel: dict, client: httpx.Client, deadline: float) -> dict:
    connection = db.get(M365Connection, setting.connection_id)
    setting.last_run_at = utcnow()
    if connection is None:
        setting.mode, setting.last_error = "off", "The Microsoft 365 connection was removed."
        db.commit()
        return {"stored": 0, "error": setting.last_error}
    try:
        stored = scan_connection(db, setting, connection, intel, client, deadline)
        setting.last_error, setting.last_scanned = "", stored
        db.commit()
        return {"stored": stored, "error": ""}
    except (ScanError, ValueError, KeyError, crypto.VaultError, httpx.HTTPError) as exc:
        db.rollback()
        setting = db.get(EmailScanSetting, setting.id)
        setting.last_run_at = utcnow()
        if isinstance(exc, crypto.VaultError):
            message = "Fenrir could not read this connection's stored credentials. Reconnect the customer under Microsoft 365."
        else:
            message = str(exc) if isinstance(exc, ScanError) else m365.describe_failure(exc)
        setting.last_error = message[:300]
        db.commit()
        return {"stored": 0, "error": setting.last_error}


def purge(db: Session) -> int:
    removed = 0
    for setting in db.execute(select(EmailScanSetting)).scalars().all():
        days = max(7, min(int(setting.retention_days or 90), 730))
        old = select(EmailScan.id).where(EmailScan.connection_id == setting.connection_id,
                                         EmailScan.received_at < utcnow() - timedelta(days=days))
        from .models import EmailContent

        db.execute(delete(EmailContent).where(EmailContent.scan_id.in_(old)))
        removed += db.execute(delete(EmailScan).where(EmailScan.connection_id == setting.connection_id,
                                                      EmailScan.received_at < utcnow() - timedelta(days=days))).rowcount or 0
    if removed:
        db.commit()
    return removed


# --------------------------------------------------------------------------- settings, labels and views

def configure(db: Session, connection: M365Connection, mode: str, retention_days: int | None, actor: str,
              actions: dict | None = None, notify: dict | None = None) -> EmailScanSetting:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    setting = db.execute(select(EmailScanSetting).where(EmailScanSetting.connection_id == connection.id)).scalar_one_or_none()
    if setting is None:
        setting = EmailScanSetting(tenant_id=connection.tenant_id, connection_id=connection.id, state={})
        db.add(setting)
    if retention_days is not None:
        if not 7 <= int(retention_days) <= 730:
            raise ValueError("Keep scans for between 7 and 730 days")
        setting.retention_days = int(retention_days)
    if actions is not None:
        bad = {k: v for k, v in actions.items() if k not in email_actions.DEFAULT_ACTIONS or v not in email_actions.ACTIONS}
        if bad:
            raise ValueError(f"Actions are chosen for malware, phish and suspicious, from {', '.join(email_actions.ACTIONS)}")
        setting.actions = {**email_actions.actions_for(setting), **actions}
    if notify is not None:
        email = str(notify.get("alertEmail") or "").strip()
        if email and ("@" not in email or len(email) > 320):
            raise ValueError("The alert email address is not valid")
        setting.notify = {"digest": bool(notify.get("digest")), "alertEmail": email, "openTicket": bool(notify.get("openTicket"))}
    if mode == "protect" and (setting.mode != "protect" or setting.paused_reason):
        setting.protect_since = utcnow()  # only mail from now on is ever acted on
        setting.paused_reason = ""
    setting.mode, setting.updated_by, setting.updated_at = mode, actor, utcnow()
    if mode != "off":
        setting.last_error = ""
    audit.record(db, actor, "email_security.configured", connection.id, connection.tenant_id, mode=mode,
                 retention_days=setting.retention_days, actions=email_actions.actions_for(setting))
    return setting


def label(db: Session, scan: EmailScan, value: str, actor: str) -> EmailScan:
    if value not in (*LABELS, ""):
        raise ValueError(f"label must be one of {', '.join(LABELS)} (or empty to clear it)")
    scan.label, scan.labelled_by, scan.labelled_at = value, actor if value else "", utcnow() if value else None
    audit.record(db, actor, "email_security.labelled", scan.id, scan.tenant_id, label=value or "cleared")
    return scan


def setting_view(setting: EmailScanSetting | None, connection: M365Connection) -> dict:
    from . import m365_permissions

    allowed = m365_permissions.feature_available(connection.snapshot, "email.security")
    return {
        "connectionId": connection.id, "tenantId": connection.tenant_id, "name": connection.tenant_name or connection.name,
        "authMode": connection.auth_mode or "app", "mode": setting.mode if setting else "off",
        "retentionDays": setting.retention_days if setting else 90,
        "lastRunAt": setting.last_run_at.isoformat() + "Z" if setting and setting.last_run_at else None,
        "lastScanned": setting.last_scanned if setting else 0, "lastError": setting.last_error if setting else "",
        "mailboxes": len(mailboxes(connection)), "permission": allowed,
        "protectPermission": m365_permissions.feature_available(connection.snapshot, "email.protect"),
        "supported": (connection.auth_mode or "app") != "gdap",
        "actions": email_actions.actions_for(setting) if setting else dict(email_actions.DEFAULT_ACTIONS),
        "notify": {"digest": False, "alertEmail": "", "openTicket": False, **((setting.notify or {}) if setting else {})},
        "protectSince": setting.protect_since.isoformat() + "Z" if setting and setting.protect_since else None,
        "pausedReason": (setting.paused_reason or "") if setting else "",
    }


def scan_view(row: EmailScan, full: bool = False) -> dict:
    out = {
        "id": row.id, "tenantId": row.tenant_id, "connectionId": row.connection_id, "mailbox": row.mailbox,
        "receivedAt": row.received_at.isoformat() + "Z", "folder": row.folder, "sender": row.sender_address,
        "senderName": row.sender_name, "subject": row.subject, "verdict": row.verdict, "score": row.score,
        "microsoftVerdict": row.microsoft_verdict, "agreement": row.agreement, "label": row.label,
        "topReason": (row.reasons or [{}])[0].get("detail", "") if row.reasons else "",
        "attachments": len(row.attachments or []), "source": row.source or "graph", "action": row.action or "",
        "actionStatus": row.action_status or "", "modelScore": row.model_score,
    }
    if full:
        out.update(reasons=row.reasons or [], microsoft=row.microsoft or {}, attachmentDetails=row.attachments or [],
                   linkDomains=row.link_domains or [], internetMessageId=row.internet_message_id,
                   labelledBy=row.labelled_by, labelledAt=row.labelled_at.isoformat() + "Z" if row.labelled_at else None,
                   actionError=row.action_error or "", actedAt=row.acted_at.isoformat() + "Z" if row.acted_at else None,
                   releasedBy=row.released_by or "", releasedAt=row.released_at.isoformat() + "Z" if row.released_at else None,
                   releaseRequestedAt=row.release_requested_at.isoformat() + "Z" if row.release_requested_at else None,
                   recipients=row.recipients or [], details=row.details or {},
                   canDownload=bool((row.source or "graph") == "graph" or row.action == "quarantine"
                                    or row.action_status == "failed"))
    return out


def overview(db: Session, tenant_ids: list[str], days: int = 7) -> dict:
    """How Fenrir and Microsoft compare across the customers shown."""
    since = utcnow() - timedelta(days=days)
    base = select(EmailScan.agreement, EmailScan.verdict, EmailScan.microsoft_verdict, EmailScan.label,
                  func.count()).where(EmailScan.tenant_id.in_(tenant_ids), EmailScan.received_at >= since) \
        .group_by(EmailScan.agreement, EmailScan.verdict, EmailScan.microsoft_verdict, EmailScan.label)
    totals = {"scanned": 0, "fenrirFlagged": 0, "microsoftFlagged": 0, "both": 0, "fenrirOnly": 0, "microsoftOnly": 0,
              "suspicious": 0, "microsoftSpam": 0, "labelled": 0, "labelledFenrirRight": 0, "labelledMicrosoftRight": 0}
    for agreement, verdict, microsoft, labelled, count in db.execute(base).all():
        totals["scanned"] += count
        totals["fenrirFlagged"] += count if verdict in email_security.FLAGGED else 0
        totals["microsoftFlagged"] += count if microsoft in email_security.FLAGGED else 0
        totals["both"] += count if agreement == "both" else 0
        totals["fenrirOnly"] += count if agreement == "fenrir_only" else 0
        totals["microsoftOnly"] += count if agreement == "microsoft_only" else 0
        totals["suspicious"] += count if verdict == "suspicious" else 0
        totals["microsoftSpam"] += count if microsoft in {"spam", "bulk"} else 0
        if labelled:
            bad = labelled in {"phish", "malware"}
            totals["labelled"] += count
            totals["labelledFenrirRight"] += count if (verdict in email_security.FLAGGED) == bad else 0
            totals["labelledMicrosoftRight"] += count if (microsoft in email_security.FLAGGED) == bad else 0
    acted = db.execute(select(EmailScan.action, EmailScan.action_status, func.count()).where(
        EmailScan.tenant_id.in_(tenant_ids), EmailScan.received_at >= since, EmailScan.action.in_(("quarantine", "junk", "tag")))
        .group_by(EmailScan.action, EmailScan.action_status)).all()
    totals["quarantined"] = sum(c for a, st, c in acted if a == "quarantine" and st in ("done", "release_requested", "released"))
    totals["junked"] = sum(c for a, st, c in acted if a == "junk" and st in ("done", "released"))
    totals["tagged"] = sum(c for a, st, c in acted if a == "tag" and st == "done")
    totals["released"] = sum(c for a, st, c in acted if st == "released")
    totals["releaseRequests"] = sum(c for a, st, c in acted if st == "release_requested")
    totals["actionFailures"] = sum(c for a, st, c in acted if st == "failed")
    flagged_any = totals["both"] + totals["fenrirOnly"] + totals["microsoftOnly"]
    totals["agreementPercent"] = round(100 * totals["both"] / flagged_any) if flagged_any else None
    top = db.execute(select(EmailScan.sender_domain, func.count()).where(
        EmailScan.tenant_id.in_(tenant_ids), EmailScan.received_at >= since, EmailScan.verdict.in_(email_security.FLAGGED))
        .group_by(EmailScan.sender_domain).order_by(func.count().desc()).limit(10)).all()
    return {"days": days, **totals, "topFlaggedSenders": [{"domain": d, "count": c} for d, c in top]}
