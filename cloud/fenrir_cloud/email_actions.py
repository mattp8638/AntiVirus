"""Email security, protect mode: act on Fenrir's verdicts in Microsoft 365 mailboxes, and undo it.

Actions, chosen per verdict for each customer (``EmailScanSetting.actions``):

- ``quarantine``: move the message to a hidden "Fenrir Quarantine" folder in the same mailbox. The user cannot see it;
  a technician (or the user, through a release request) can bring it back to the Inbox.
- ``junk``: move it to Junk Email, where the user can still see it.
- ``tag``: add the Outlook category "Fenrir: suspicious" so the user sees a coloured warning; nothing moves.
- ``none``: record the verdict only.

Defaults: malware and phish are quarantined, suspicious mail is tagged. Moving or tagging needs the Graph application
permission ``Mail.ReadWrite``.

Safety:

- Only mail received after protect mode was switched on is ever touched.
- If one run would quarantine or junk more than ``BRAKE`` messages for one customer, Fenrir stops acting for that
  customer, keeps scanning, raises an alert and waits for a technician to resume it: a bad rule or bad intel cannot empty
  every inbox.
- Allow-listed senders are never acted on unless they fail authentication.

People are told: each run that quarantines mail raises one alert summarising it (and can email a contact or open a
ticket); mailbox owners can get a daily digest of what was quarantined for them, with a link to ask IT to release a
message. The link opens a page with a button, so link scanners that open every URL cannot request releases.

Later intel: messages scanned in the last two days are checked again against new threat intel (attachment hashes and
link domains); a match is re-scored and acted on, like Microsoft's zero-hour auto purge.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import timedelta
from html import escape
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, email_security, m365
from .models import Alert, EmailScan, EmailScanSetting, M365Connection, utcnow

log = logging.getLogger("fenrir.email.actions")

ACTIONS = ("quarantine", "junk", "tag", "none")
DEFAULT_ACTIONS = {"malware": "quarantine", "phish": "quarantine", "suspicious": "tag"}
QUARANTINE_FOLDER = "Fenrir Quarantine"
TAG = "Fenrir: suspicious"
BRAKE = 40  # quarantines/junk moves per customer per run before Fenrir stops acting and asks for a person
RECHECK_WINDOW = timedelta(hours=48)


class ActionError(Exception):
    pass


def actions_for(setting: EmailScanSetting) -> dict:
    chosen = dict(DEFAULT_ACTIONS)
    chosen.update({k: v for k, v in (setting.actions or {}).items() if k in DEFAULT_ACTIONS and v in ACTIONS})
    return chosen


def acting(setting: EmailScanSetting) -> bool:
    return setting.mode == "protect" and not (setting.paused_reason or "")


# --------------------------------------------------------------------------- Microsoft Graph

def _call(client: httpx.Client, method: str, url: str, token: str, body: dict | None = None) -> dict:
    response = client.request(method, url, headers={"Authorization": "Bearer " + token}, json=body)
    if response.status_code == 403:
        raise ActionError("Fenrir does not have permission to change mail (Mail.ReadWrite). Update this customer's "
                          "Microsoft 365 permissions and have an admin approve them.")
    if response.status_code == 404:
        raise ActionError("The message is no longer in the mailbox (the user may have moved or deleted it).")
    response.raise_for_status()
    return response.json() if response.content else {}


def quarantine_folder(client: httpx.Client, token: str, user_id: str, state: dict) -> str:
    """The id of the mailbox's hidden Fenrir Quarantine folder, creating it the first time."""
    cached = (state.get(user_id) or {}).get("quarantineFolder")
    if cached:
        return cached
    base = f"{m365.GRAPH}/users/{quote(user_id)}/mailFolders"
    found = _call(client, "GET", f"{base}?includeHiddenFolders=true&$filter="
                  + quote(f"displayName eq '{QUARANTINE_FOLDER}'", safe="") + "&$select=id,displayName", token)
    rows = found.get("value") or []
    folder_id = rows[0]["id"] if rows else _call(client, "POST", base, token,
                                                 {"displayName": QUARANTINE_FOLDER, "isHidden": True})["id"]
    state.setdefault(user_id, {})["quarantineFolder"] = folder_id
    return folder_id


def move(client: httpx.Client, token: str, user_id: str, message_id: str, destination: str) -> str:
    """Move a message; returns its new id (Microsoft gives a moved message a new id)."""
    moved = _call(client, "POST", f"{m365.GRAPH}/users/{quote(user_id)}/messages/{quote(message_id, safe='')}/move",
                  token, {"destinationId": destination})
    return str(moved.get("id") or message_id)


def permanent_delete(client: httpx.Client, token: str, user_id: str, message_id: str) -> None:
    """Delete a message for good (not to Deleted Items), as Defender's hard delete does."""
    _call(client, "POST", f"{m365.GRAPH}/users/{quote(user_id)}/messages/{quote(message_id, safe='')}/permanentDelete", token)


def tag(client: httpx.Client, token: str, user_id: str, message_id: str, existing: list[str],
        extra: list[str] | None = None) -> None:
    categories = list(dict.fromkeys([*existing, *(extra or [TAG])]))[:25]
    _call(client, "PATCH", f"{m365.GRAPH}/users/{quote(user_id)}/messages/{quote(message_id, safe='')}", token,
          {"categories": categories})


# --------------------------------------------------------------------------- acting on one message

def act(client: httpx.Client, token: str, setting: EmailScanSetting, user_id: str, row: EmailScan,
        categories: list[str], state: dict, action: str | None = None, extra_categories: list[str] | None = None) -> str:
    """Carry out the policy's action on one mailbox message. Returns the action taken ("" for none).

    ``action`` comes from the customer's email policy (email_policy.decide); reject means quarantine in a mailbox."""
    action = action if action is not None else actions_for(setting).get(row.verdict, "none")
    action = "quarantine" if action == "reject" else action
    if action in ("none", "deliver") or (row.reasons and row.reasons[0].get("code") == "list.allow" and action != "quarantine"):
        return ""
    if action == "junk" and row.folder == "junkemail":
        row.action, row.action_status = "junk", "skipped"
        return ""
    row.action, row.acted_at = action, utcnow()
    try:
        if action == "quarantine":
            row.moved_message_id = move(client, token, user_id, row.message_id, quarantine_folder(client, token, user_id, state))
        elif action == "junk":
            row.moved_message_id = move(client, token, user_id, row.message_id, "junkemail")
        elif action == "tag":
            tag(client, token, user_id, row.message_id, categories, extra_categories)
        row.action_status, row.action_error = "done", ""
    except (ActionError, httpx.HTTPError) as exc:
        row.action_status = "failed"
        row.action_error = (str(exc) if isinstance(exc, ActionError) else m365.describe_failure(exc))[:300]
    return action if row.action_status == "done" else ""


def release(db: Session, row: EmailScan, actor: str, client: httpx.Client | None = None) -> EmailScan:
    """Bring a quarantined (or junked) message back to the Inbox; for the gateway, also retry one it could not deliver."""
    gateway_retry = (row.source or "graph") == "gateway" and row.action_status == "failed"
    if not gateway_retry and (row.action not in ("quarantine", "junk") or row.action_status not in ("done", "release_requested")):
        raise ActionError("Only quarantined or junked messages can be released.")
    if (row.source or "graph") == "gateway":
        from . import mail_gateway

        mail_gateway.release(db, row, actor)
    else:
        connection = db.get(M365Connection, row.connection_id)
        if connection is None:
            raise ActionError("The customer's Microsoft 365 connection no longer exists.")
        user_id = _user_id(connection, row.mailbox)
        own = client is None
        client = client or httpx.Client(timeout=20, follow_redirects=False)
        try:
            token = m365.access_token(client, connection)
            row.moved_message_id = move(client, token, user_id, row.moved_message_id or row.message_id, "inbox")
        finally:
            if own:
                client.close()
    row.action_status, row.released_by, row.released_at = "released", actor, utcnow()
    audit.record(db, actor, "email_security.released", row.id, row.tenant_id, mailbox=row.mailbox, subject=row.subject[:120])
    return row


def _user_id(connection: M365Connection, address: str) -> str:
    from .email_scan import mailboxes

    for box in mailboxes(connection):
        if box["address"] == address.lower():
            return box["id"]
    raise ActionError(f"{address} is no longer a licensed mailbox in this tenant.")


# --------------------------------------------------------------------------- the brake, alerts and notifications

def apply_brake(db: Session, setting: EmailScanSetting, moved: int) -> bool:
    """Stop acting for this customer if one run moved too much mail. Returns True when it tripped."""
    if moved <= BRAKE:
        return False
    setting.paused_reason = (f"Paused automatically: one scan would have moved {moved} messages (the limit is {BRAKE}). "
                             "Check the Messages tab, then resume protect mode.")[:300]
    db.add(Alert(tenant_id=setting.tenant_id, device_id=None, rule_id="email:brake", title="Email protection paused itself",
                 severity="high", status="new", mitre=["T1566"],
                 details={"category": "email", "summary": setting.paused_reason, "connectionId": setting.connection_id,
                          "key": f"email-brake:{setting.connection_id}:{utcnow().date()}"}))
    audit.record(db, "system:email-security", "email_security.paused", setting.connection_id, setting.tenant_id, moved=moved)
    return True


def report_run(db: Session, setting: EmailScanSetting, rows: list[EmailScan]) -> Alert | None:
    """One alert per run that quarantined or junked mail, listing what and why; plus the customer's chosen email or ticket."""
    acted = [r for r in rows if r.action in ("quarantine", "junk") and r.action_status == "done"]
    if not acted:
        return None
    malware = any(r.verdict == "malware" for r in acted)
    title = f"Email security {'quarantined' if any(r.action == 'quarantine' for r in acted) else 'moved'} {len(acted)} message" \
            + ("s" if len(acted) != 1 else "")
    lines = [f"- {r.mailbox}: \"{r.subject[:80]}\" from {r.sender_address} ({r.verdict}, {r.action}): "
             f"{(r.reasons or [{}])[0].get('detail', '')}" for r in acted[:20]]
    summary = "\n".join(lines) + (f"\n…and {len(acted) - 20} more" if len(acted) > 20 else "")
    alert = Alert(tenant_id=setting.tenant_id, device_id=None, rule_id="email:" + ("malware" if malware else "phish"),
                  title=title, severity="high" if malware else "medium", status="new", mitre=["T1566"],
                  details={"category": "email", "summary": summary, "connectionId": setting.connection_id,
                           "scanIds": [r.id for r in acted[:50]], "key": f"email:{acted[0].id}"})
    db.add(alert)
    notify = setting.notify or {}
    text = f"{title}.\n\n{summary}\n\nRelease anything that was safe from Email security > Messages."
    if notify.get("openTicket"):
        from . import services

        services.open_ticket(db, setting.tenant_id, title[:300], text, priority="P2" if malware else "P3",
                             source="email-security", queue="Security Operations")
    if notify.get("alertEmail"):
        from . import mailer

        try:
            mailer.send(str(notify["alertEmail"]), f"[Fenrir] {title}", text)
        except Exception as exc:  # noqa: BLE001 - mail problems never stop protection
            log.warning("email security alert email failed: %s", exc)
    return alert


# --------------------------------------------------------------------------- user release requests and digests

def release_token(scan_id: str) -> str:
    from .config import get_settings

    secret = (get_settings().secret_key or "").encode()
    return hmac.new(secret, f"email-release:{scan_id}".encode(), hashlib.sha256).hexdigest()[:40]


def valid_token(scan_id: str, token: str) -> bool:
    return bool(token) and hmac.compare_digest(release_token(scan_id), token)


def release_link(scan_id: str) -> str:
    from .config import get_settings

    base = (get_settings().public_base_url or "").rstrip("/")
    return f"{base}/api/public/email-release/{scan_id}?t={release_token(scan_id)}"


def request_release(db: Session, row: EmailScan) -> bool:
    """A mailbox owner asks for a message back. A technician decides; nothing is released automatically."""
    if row.action_status != "done" or row.action not in ("quarantine", "junk"):
        return False
    row.action_status, row.release_requested_at = "release_requested", utcnow()
    db.add(Alert(tenant_id=row.tenant_id, device_id=None, rule_id="email:release-request",
                 title=f"Release requested: \"{row.subject[:80]}\" for {row.mailbox}"[:300], severity="low", status="new",
                 details={"category": "email", "scanIds": [row.id], "key": f"email-release:{row.id}",
                          "summary": f"{row.mailbox} asked for a quarantined message from {row.sender_address} back. "
                                     f"Fenrir's verdict: {row.verdict}. Review it in Email security > Messages."}))
    audit.record(db, row.mailbox, "email_security.release_requested", row.id, row.tenant_id)
    return True


def send_digests(db: Session, setting: EmailScanSetting) -> int:
    """Once a day: tell each mailbox owner what was quarantined for them, with a link to ask for each message back."""
    from . import mailer

    if not (setting.notify or {}).get("digest") or not mailer.configured():
        return 0
    now = utcnow()
    since = setting.digest_sent_at or (now - timedelta(days=1))
    if setting.digest_sent_at and now - setting.digest_sent_at < timedelta(hours=23):
        return 0
    rows = db.execute(select(EmailScan).where(EmailScan.connection_id == setting.connection_id,
                                              EmailScan.action == "quarantine", EmailScan.action_status == "done",
                                              EmailScan.acted_at >= since).order_by(EmailScan.received_at)).scalars().all()
    by_mailbox: dict[str, list[EmailScan]] = {}
    for row in rows:
        by_mailbox.setdefault(row.mailbox, []).append(row)
    sent = 0
    for mailbox, items in by_mailbox.items():
        text_lines, html_rows = [], []
        for row in items[:50]:
            link = release_link(row.id)
            text_lines.append(f"- {row.received_at:%d %b %H:%M}  {row.sender_address}  \"{row.subject[:100]}\"\n  Ask for it back: {link}")
            html_rows.append(f"<tr><td>{row.received_at:%d %b %H:%M}</td><td>{escape(row.sender_address)}</td>"
                             f"<td>{escape(row.subject[:100])}</td><td><a href=\"{escape(link)}\">Ask for it back</a></td></tr>")
        intro = (f"Fenrir held back {len(items)} message{'s' if len(items) != 1 else ''} addressed to you because they look "
                 "like phishing or malware. If you were expecting one of them, ask for it back and IT will check it.")
        try:
            mailer.send(mailbox, f"Messages held back for you ({len(items)})", intro + "\n\n" + "\n".join(text_lines),
                        html=f"<p>{escape(intro)}</p><table cellpadding=\"6\"><tr><th>Received</th><th>From</th>"
                             f"<th>Subject</th><th></th></tr>{''.join(html_rows)}</table>")
            sent += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("email security digest to %s failed: %s", mailbox, exc)
    setting.digest_sent_at = now
    return sent


# --------------------------------------------------------------------------- later intel (zero-hour re-check)

def recheck(db: Session, setting: EmailScanSetting, connection: M365Connection, ctx: email_security.Context,
            client: httpx.Client, token: str, state: dict) -> list[EmailScan]:
    """Re-score recent messages that new threat intel now names (an attachment hash or a link domain) and act on them."""
    rows = db.execute(select(EmailScan).where(
        EmailScan.connection_id == connection.id, EmailScan.received_at >= utcnow() - RECHECK_WINDOW,
        EmailScan.verdict.in_(("clean", "suspicious")))).scalars().all()
    changed = []
    for row in rows:
        hits = [a for a in row.attachments or [] if str(a.get("sha256") or "").lower() in ctx.bad_hashes]
        domains = [d for d in row.link_domains or [] if d in ctx.bad_domains and d not in ctx.allowed_domains]
        if not hits and not domains:
            continue
        reasons = list(row.reasons or [])
        if hits:
            reasons.insert(0, {"code": "intel.retro", "points": 100,
                               "detail": f"Attachment {hits[0].get('name')} was named as malware after delivery "
                                         f"({ctx.bad_hashes[str(hits[0]['sha256']).lower()]})"})
            row.verdict = "malware"
        else:
            reasons.insert(0, {"code": "intel.retro", "points": 70,
                               "detail": f"Links to {domains[0]}, added to threat intelligence after delivery"})
            row.verdict = "phish"
        row.reasons, row.score = reasons, min(100, row.score + reasons[0]["points"])
        row.agreement = email_security.agreement(row.verdict, row.microsoft_verdict)
        policy = getattr(ctx, "policy", None) or {}
        malware_policy = policy.get("antimalware") or {}
        if malware_policy and not malware_policy.get("zeroHour", True):
            changed.append(row)
            continue
        action = (malware_policy.get("action", "quarantine") if row.verdict == "malware"
                  else ((policy.get("antispam") or {}).get("actions") or {}).get("phish", "quarantine"))
        if acting(setting) and row.source in (None, "graph") and setting.protect_since and row.received_at >= setting.protect_since:
            try:
                act(client, token, setting, _user_id(connection, row.mailbox), row, [], state, action)
            except ActionError as exc:
                row.action_status, row.action_error = "failed", str(exc)[:300]
        changed.append(row)
    return changed
