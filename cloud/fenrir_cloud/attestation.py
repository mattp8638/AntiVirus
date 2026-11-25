"""Policy acknowledgement by staff (GRC-08): assignments of a policy to people (client-portal users of the customer),
acknowledgement of the approved version with the SHA-256 of the exact text shown, re-acknowledgement when a new
version is approved, exceptions with a reason and an end date, and reminders."""

from __future__ import annotations

import hashlib
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, mailer
from .models import GrcPolicy, GrcPolicyVersion, PolicyAcknowledgement, PolicyAttestation, User, utcnow

REMIND_EVERY_DAYS = 7
MAX_REMINDERS = 6


def text_sha256(title: str, body: str) -> str:
    """What a person acknowledges: the title and text of the version, as shown."""
    return hashlib.sha256(f"{title}\n\n{body}".encode()).hexdigest()


def approved_text(db: Session, policy: GrcPolicy) -> tuple[int, str, str] | None:
    if not policy.approved_version or policy.status == "retired":
        return None
    v = db.execute(select(GrcPolicyVersion).where(GrcPolicyVersion.policy_id == policy.id,
                                                  GrcPolicyVersion.version == policy.approved_version)).scalar_one_or_none()
    if v is None:
        return None
    return v.version, v.title, v.body


def status(a: PolicyAttestation, policy: GrcPolicy, now=None) -> str:
    now = now or utcnow()
    if a.removed:
        return "removed"
    if a.exception and a.exception.get("until") and a.exception["until"] >= now.date().isoformat():
        return "exception"
    if policy.approved_version and a.acknowledged_version == policy.approved_version:
        return "current"
    # Due from the later of the assignment and the approval of the version now in force.
    since = max(filter(None, [a.assigned_at, policy.approved_at]))
    return "overdue" if now > since + timedelta(days=a.due_days) else "outstanding"


def assign(db: Session, policy: GrcPolicy, users: list[User], due_days: int, actor: str) -> int:
    n = 0
    for u in users:
        a = db.execute(select(PolicyAttestation).where(PolicyAttestation.policy_id == policy.id,
                                                       PolicyAttestation.user_id == u.id)).scalar_one_or_none()
        if a is None:
            db.add(PolicyAttestation(tenant_id=policy.tenant_id, policy_id=policy.id, user_id=u.id, email=u.email,
                                     assigned_by=actor, due_days=due_days))
            n += 1
        elif a.removed:
            a.removed, a.assigned_at, a.assigned_by, a.due_days = False, utcnow(), actor, due_days
            n += 1
    return n


def acknowledge(db: Session, a: PolicyAttestation, policy: GrcPolicy, user: User, version: int, sha: str,
                ip: str, agent: str) -> PolicyAcknowledgement:
    cur = approved_text(db, policy)
    if cur is None:
        raise ValueError("this policy has no approved version to acknowledge")
    v, title, body = cur
    if version != v:
        raise ValueError("a newer version of this policy has been approved: read it again")
    if sha != text_sha256(title, body):
        raise ValueError("the text you read is not the approved text: reload it")
    row = PolicyAcknowledgement(tenant_id=a.tenant_id, attestation_id=a.id, policy_id=policy.id, user_id=user.id,
                                email=user.email, version=v, title=title, sha256=sha, ip=ip[:64], user_agent=agent[:300])
    db.add(row)
    a.acknowledged_version, a.acknowledged_at = v, row.at or utcnow()
    audit.record(db, user.email, "grc.policy_acknowledged", title, a.tenant_id, policy=policy.id, version=v, sha256=sha)
    return row


def remind(db: Session) -> int:
    """Hourly: people outstanding or overdue on an approved policy get a reminder every 7 days (6 at most)."""
    now = utcnow()
    sent = 0
    for a in db.execute(select(PolicyAttestation).where(PolicyAttestation.removed.is_(False))).scalars():
        policy = db.get(GrcPolicy, a.policy_id)
        if policy is None or not policy.approved_version or status(a, policy, now) not in ("outstanding", "overdue"):
            continue
        if a.reminders >= MAX_REMINDERS or (a.last_reminded_at and now - a.last_reminded_at < timedelta(days=REMIND_EVERY_DAYS)):
            continue
        if now - max(a.assigned_at, policy.approved_at or a.assigned_at) < timedelta(days=1):
            continue  # give people a day before the first reminder
        mailer.send(a.email, f"Please read and acknowledge: {policy.title}",
                    f"You have been asked to read and acknowledge the policy \"{policy.title}\" (version "
                    f"{policy.approved_version}). Sign in to the portal and open Policies to read it.\n")
        a.last_reminded_at, a.reminders = now, a.reminders + 1
        sent += 1
    db.commit()
    return sent
