"""Email security: a message's body, kept encrypted and shown safely, with the reasons highlighted.

What is kept depends on the customer's policy (``quarantine.keepContent``): ``flagged`` (default: anything not clean,
anything acted on, anything a mail flow rule matched), ``all``, or ``none``. Bodies are encrypted with the vault key,
deleted with their scan (retention), and every view is in the audit log. Mailbox messages that were not kept can still
be read on demand from Microsoft 365 while they are in the mailbox.

``safe_html`` rebuilds the HTML from an allow-list of harmless tags with **no attributes at all**: no scripts, styles,
forms, frames, event handlers or remote images (images become "[image]" markers), and links become their text
followed by where they really go. The console also shows it inside a sandboxed frame with scripts disabled.
"""
from __future__ import annotations

import json
import re
from html import escape
from html.parser import HTMLParser

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import crypto, email_security

MAX_TEXT = 200_000
MAX_HTML = 500_000
SAFE_TAGS = {"p", "br", "div", "span", "table", "thead", "tbody", "tfoot", "tr", "td", "th", "b", "i", "u", "strong", "em",
             "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "code", "hr", "font", "center",
             "small", "sup", "sub", "s", "strike", "caption", "dl", "dt", "dd"}
DROP_WITH_CONTENT = {"script", "style", "head", "title", "iframe", "object", "embed", "noscript", "template", "svg", "math",
                     "form", "select", "textarea", "button"}
VOID = {"br", "hr", "img", "input", "meta", "link", "area", "base", "col", "wbr", "source", "track"}


class _Sanitiser(HTMLParser):
    def __init__(self, flagged_hosts: set[str]):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.drop = 0
        self.links: list[str | None] = []
        self.flagged = flagged_hosts

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in DROP_WITH_CONTENT:
            if tag not in VOID:
                self.drop += 1
            return
        if self.drop:
            return
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag == "img":
            alt = values.get("alt", "").strip()
            host = email_security._host(values.get("src", "")) if values.get("src", "").startswith("http") else ""
            label = "image" + (f": {alt}" if alt else "") + (f" from {host}" if host else "")
            self.out.append(f'<span class="fenrir-img">[{escape(label[:120])}]</span>')
        elif tag == "a":
            self.links.append(values.get("href", ""))
            self.out.append('<span class="fenrir-link">')
        elif tag in SAFE_TAGS:
            self.out.append(f"<{tag}>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in DROP_WITH_CONTENT:
            self.drop = max(0, self.drop - 1)
            return
        if self.drop:
            return
        if tag == "a":
            href = self.links.pop() if self.links else ""
            if href:
                host = email_security._host(href)
                css = "fenrir-dest fenrir-flag" if host and host in self.flagged else "fenrir-dest"
                self.out.append(f'</span><span class="{css}"> [→ {escape(href[:300])}]</span>')
            else:
                self.out.append("</span>")
        elif tag in SAFE_TAGS and tag not in VOID:
            self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.drop:
            self.out.append(highlight(escape(data)))


def highlight(escaped_text: str) -> str:
    """Wrap the scam wording Fenrir looks for in <mark>, with the reason as a tooltip. Input is already escaped."""
    for pattern, why in email_security.PHRASE_PATTERNS:
        escaped_text = pattern.sub(lambda m: f'<mark title="{escape(why)}">{m.group(0)}</mark>', escaped_text)
    return escaped_text


def safe_html(html: str, flagged_hosts: set[str] | None = None) -> str:
    parser = _Sanitiser(flagged_hosts or set())
    try:
        parser.feed(html[:MAX_HTML])
        parser.close()
    except Exception:  # noqa: BLE001 - a body that will not parse is shown as text instead
        return "<pre>" + highlight(escape(email_security.plain_text(html))) + "</pre>"
    return "".join(parser.out)


def text_of(html: str) -> str:
    return email_security.plain_text(html)[:MAX_TEXT]


def should_keep(policy: dict, verdict: str, action: str, decision: dict) -> bool:
    mode = (policy.get("quarantine") or {}).get("keepContent", "flagged")
    if mode == "all":
        return True
    if mode == "none":
        return False
    rules = any(t.get("source", "").startswith("Mail flow rule") for t in decision.get("trail") or [])
    return verdict != "clean" or action not in ("", "deliver") or rules


def keep(db: Session, scan, html: str, subject: str = "") -> None:
    """Store the body for this scan, encrypted."""
    from .models import EmailContent

    if db.execute(select(EmailContent.id).where(EmailContent.scan_id == scan.id)).first():
        return
    payload = json.dumps({"html": html[:MAX_HTML], "subject": subject[:300]})
    db.add(EmailContent(scan_id=scan.id, tenant_id=scan.tenant_id, envelope=crypto.encrypt(payload, f"email-content:{scan.id}")))


def stored(db: Session, scan) -> dict | None:
    from .models import EmailContent

    row = db.execute(select(EmailContent).where(EmailContent.scan_id == scan.id)).scalar_one_or_none()
    if row is None:
        return None
    return json.loads(crypto.decrypt(row.envelope, f"email-content:{scan.id}"))


def view(scan, html: str, source: str) -> dict:
    """The body for the console: safe HTML with highlights, plain text, and where it came from."""
    flagged = {l.get("host") for l in ((scan.details or {}).get("links") or []) if l.get("flags")}
    phrases = [why for pattern, why in email_security.PHRASE_PATTERNS if pattern.search(text_of(html))]
    return {"html": safe_html(html, flagged), "text": text_of(html), "source": source, "phrases": phrases,
            "flaggedHosts": sorted(h for h in flagged if h)}


def purge_for(db: Session, scan_ids: list[str]) -> None:
    from sqlalchemy import delete

    from .models import EmailContent

    if scan_ids:
        db.execute(delete(EmailContent).where(EmailContent.scan_id.in_(scan_ids)))


def strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text)
