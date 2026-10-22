"""Outbound email over SMTP. Unconfigured deployments keep messages in memory (visible to tests and logs)."""

from __future__ import annotations

import logging
import os
import smtplib
import threading
from collections import deque
from email.message import EmailMessage
from email.utils import make_msgid

log = logging.getLogger("fenrir.mail")

# Last messages "sent", newest last. Useful when SMTP is not configured and in tests.
OUTBOX: deque[dict] = deque(maxlen=200)


def sender() -> str:
    return os.getenv("FENRIR_SMTP_FROM", "support@fenrir.local")


def configured() -> bool:
    return bool(os.getenv("FENRIR_SMTP_HOST"))


def _deliver(message: EmailMessage) -> None:
    host = os.getenv("FENRIR_SMTP_HOST", "")
    port = int(os.getenv("FENRIR_SMTP_PORT", "587"))
    user = os.getenv("FENRIR_SMTP_USER", "")
    password = os.getenv("FENRIR_SMTP_PASSWORD", "")
    try:
        if port == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=20)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
            if os.getenv("FENRIR_SMTP_STARTTLS", "true").lower() != "false":
                server.starttls()
        with server:
            if user:
                server.login(user, password)
            server.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:  # pragma: no cover - network dependent
        log.warning("email to %s failed: %s", message["To"], exc)


def send(to: str, subject: str, body: str, *, reply_to: str | None = None, in_reply_to: str | None = None,
         html: str | None = None) -> str:
    """Queue an email. Returns its Message-ID so replies can be threaded back to a ticket."""
    message = EmailMessage()
    message["From"] = sender()
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = make_msgid(domain=sender().split("@")[-1])
    message["Auto-Submitted"] = "auto-generated"
    if reply_to:
        message["Reply-To"] = reply_to
    if in_reply_to:
        message["In-Reply-To"] = in_reply_to
        message["References"] = in_reply_to
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")
    OUTBOX.append({"to": to, "subject": subject, "body": body, "messageId": message["Message-ID"]})
    if configured():
        threading.Thread(target=_deliver, args=(message,), daemon=True).start()
    else:
        log.info("SMTP not configured; email to %s kept in outbox: %s", to, subject)
    return message["Message-ID"]
