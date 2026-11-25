"""Agreements and electronic signature (GRC-09).

* The agreement's text is frozen when it is created, with its SHA-256; every signer sees that hash.
* Parties sign in order (sequential) or in any order (parallel). Each gets a personal link by email; links expire
  with the agreement.
* A typed name is not enough: before signing, the signer asks for a one-time code sent to their email address and
  enters it (proof they control the address the agreement was sent to), ticks their consent, and types their name.
* Every event (created, sent, viewed, code sent, signed, declined, completed, voided, expired) is appended to a hash
  chain: each event's hash covers the previous hash, so changing or removing any event breaks the chain. The
  completion certificate is the document hash plus the chain, and anyone with it can check it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from datetime import timedelta

from . import mailer
from .config import get_settings
from .models import Agreement, utcnow

VAR = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")
CODE_MINUTES = 15
MAX_CODE_TRIES = 5


def sha(s: str | bytes) -> str:
    return hashlib.sha256(s if isinstance(s, bytes) else s.encode()).hexdigest()


def render(template: str, values: dict) -> str:
    missing = sorted({m for m in VAR.findall(template) if not str(values.get(m) or "").strip()})
    if missing:
        raise ValueError("fill in: " + ", ".join(missing))
    return VAR.sub(lambda m: str(values[m.group(1)]), template)


def add_event(a: Agreement, kind: str, actor: str, **details) -> dict:
    prev = a.events[-1]["hash"] if a.events else sha(f"agreement:{a.id}:{a.sha256}")
    ev = {"seq": len(a.events or []) + 1, "at": utcnow().isoformat(), "kind": kind, "actor": actor, "details": details,
          "prev": prev}
    ev["hash"] = sha(json.dumps(ev, sort_keys=True, separators=(",", ":")))
    a.events = (a.events or []) + [ev]
    return ev


def verify_chain(agreement_id: str, doc_sha: str, events: list[dict]) -> bool:
    prev = sha(f"agreement:{agreement_id}:{doc_sha}")
    for i, ev in enumerate(events):
        body = {k: v for k, v in ev.items() if k != "hash"}
        if ev.get("prev") != prev or ev.get("seq") != i + 1 or sha(json.dumps(body, sort_keys=True, separators=(",", ":"))) != ev.get("hash"):
            return False
        prev = ev["hash"]
    return True


def link_for(a: Agreement, party: dict) -> str:
    token = secrets.token_urlsafe(32)
    party["tokenHash"] = sha(token)
    return f"{get_settings().public_base_url.rstrip('/')}/sign/{a.id}?t={token}"


def due_parties(a: Agreement) -> list[dict]:
    """Who may sign now: everyone unsigned (parallel), or the lowest unsigned order (sequential)."""
    waiting = [p for p in a.parties if p["status"] not in ("signed",)]
    if a.order == "parallel" or not waiting:
        return waiting
    first = min(p["order"] for p in waiting)
    return [p for p in waiting if p["order"] == first]


def invite(a: Agreement, parties: list[dict]) -> None:
    for p in parties:
        if p.get("invited"):
            continue
        url = link_for(a, p)
        p["invited"] = True
        mailer.send(p["email"], f"Please sign: {a.title}",
                    f"{p['name']}, you are asked to sign \"{a.title}\". Open your personal link to read and sign it"
                    f"{f' before {a.expires_at.date()}' if a.expires_at else ''}:\n\n{url}\n\nDocument SHA-256: {a.sha256}\n")
        add_event(a, "sent", "system", party=p["id"], email=p["email"])


def party_by_token(a: Agreement, token: str) -> dict | None:
    h = sha(token or "")
    return next((p for p in a.parties if p.get("tokenHash") and hmac.compare_digest(p["tokenHash"], h)), None)


def send_code(a: Agreement, p: dict) -> None:
    code = f"{secrets.randbelow(10**6):06d}"
    p["codeHash"], p["codeExpires"], p["codeTries"] = sha(f"{p['id']}:{code}"), (utcnow() + timedelta(minutes=CODE_MINUTES)).isoformat(), 0
    mailer.send(p["email"], f"Your signing code for {a.title}",
                f"Your code is {code}. It works for {CODE_MINUTES} minutes. If you did not ask for it, ignore this email.\n")
    add_event(a, "code_sent", p["email"], party=p["id"])


def sign(a: Agreement, p: dict, code: str, typed_name: str, consent: bool, ip: str, agent: str) -> None:
    if a.status != "sent":
        raise ValueError("this agreement is not open for signature")
    if a.expires_at and a.expires_at < utcnow():
        raise ValueError("this agreement has expired")
    if p not in due_parties(a):
        raise ValueError("it is not your turn to sign yet")
    if not consent:
        raise ValueError("tick that you agree to sign electronically")
    if typed_name.strip().lower() != p["name"].strip().lower():
        raise ValueError("type your full name as it appears on the agreement")
    if not p.get("codeHash") or not p.get("codeExpires") or p["codeExpires"] < utcnow().isoformat():
        raise ValueError("ask for a new code")
    p["codeTries"] = p.get("codeTries", 0) + 1
    if p["codeTries"] > MAX_CODE_TRIES:
        p["codeHash"] = None
        raise ValueError("too many attempts: ask for a new code")
    if not hmac.compare_digest(p["codeHash"], sha(f"{p['id']}:{code.strip()}")):
        raise ValueError("the code is not right")
    p.update(status="signed", signedAt=utcnow().isoformat(), ip=ip[:64], userAgent=agent[:300], typedName=typed_name.strip(),
             codeHash=None, tokenHash=None)
    add_event(a, "signed", p["email"], party=p["id"], name=p["name"], ip=ip[:64], document=a.sha256, emailVerified=True)
    if all(x["status"] == "signed" for x in a.parties):
        a.status, a.completed_at = "completed", utcnow()
        add_event(a, "completed", "system", signers=[x["email"] for x in a.parties])
        cert = certificate(a)
        for x in a.parties:
            mailer.send(x["email"], f"Completed: {a.title}",
                        f"Everyone has signed \"{a.title}\".\nDocument SHA-256: {a.sha256}\nCompletion record SHA-256: {cert['sha256']}\n",
                        attachments=[(f"{a.id}-certificate.json", "application/json", json.dumps(cert, indent=1).encode())])
    else:
        invite(a, due_parties(a))


def certificate(a: Agreement) -> dict:
    doc = {"format": "fenrir-signature-certificate", "version": 1, "agreement": a.id, "title": a.title,
           "documentSha256": a.sha256, "status": a.status, "completedAt": a.completed_at.isoformat() if a.completed_at else None,
           "signers": [{"name": p["name"], "email": p["email"], "role": p.get("role", ""), "order": p["order"],
                        "status": p["status"], "signedAt": p.get("signedAt"), "ip": p.get("ip"), "emailVerified": p["status"] == "signed"}
                       for p in a.parties],
           "events": a.events, "chainValid": verify_chain(a.id, a.sha256, a.events or [])}
    doc["sha256"] = sha(json.dumps(doc, sort_keys=True, separators=(",", ":")))
    return doc
