"""People and training (ISO 27001 5.3, 7.2, 7.3): named ISMS roles and their holders, the RACI matrix, competence
records and policy acknowledgement campaigns.

Ported from the standalone app's ``packages/programme/src/people.ts``. A campaign asks the people who hold chosen
ISMS roles in the customer (everyone with a role when none is chosen) to read one published document version.
Fenrir staff acknowledge in the console; client portal accounts (who can only hold the staff role) acknowledge in the
client portal. Acknowledgements are append-only and record a hash of the text that was shown. Every change is
audited.
"""

from __future__ import annotations

import hashlib
from datetime import date

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import User, utcnow
from .access import TENANT_ROLES
from .domain._js import js_trim
from .domain.people import RACI_ISSUE_TEXT, RACI_LETTERS, RaciCell, ack_progress, competence_status, raci_issues
from .models import (IsmsAckCampaign, IsmsAcknowledgement, IsmsCompetence, IsmsDocument, IsmsDocumentVersion,
                     IsmsEvidence, IsmsMembership, IsmsOrgRole, IsmsOrgRoleHolder, IsmsRaciActivity,
                     IsmsRaciAssignment)

COMPETENCE_KINDS = ("training", "qualification", "experience", "awareness")


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def _names(db: Session, ids) -> dict[str, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {u.id: (u.name or u.email) for u in db.execute(select(User).where(User.id.in_(ids))).scalars()}


def _members(db: Session, tenant_id: str) -> set[str]:
    from .memberships import active_role
    rows = db.execute(select(User).join(IsmsMembership, IsmsMembership.user_id == User.id)
                      .where(IsmsMembership.tenant_id == tenant_id)).scalars()
    return {u.id for u in rows if active_role(db, u, tenant_id)}


def _assert_members(db: Session, tenant_id: str, user_ids) -> None:
    if set(user_ids) - _members(db, tenant_id):
        raise _error("Everyone named must have an ISMS role in this customer.")


# Roles ------------------------------------------------------------------------------------------------------------

def role_rows(db: Session, tenant_id: str) -> list[dict]:
    roles = db.execute(select(IsmsOrgRole).where(IsmsOrgRole.tenant_id == tenant_id)
                       .order_by(IsmsOrgRole.sort, IsmsOrgRole.name)).scalars().all()
    holders = db.execute(select(IsmsOrgRoleHolder).where(IsmsOrgRoleHolder.tenant_id == tenant_id)).scalars().all()
    names = _names(db, [h.user_id for h in holders])
    out = []
    for r in roles:
        mine = sorted(({"id": h.user_id, "name": names.get(h.user_id, "")} for h in holders if h.role_id == r.id),
                      key=lambda x: x["name"])
        out.append({"id": r.id, "name": r.name, "responsibilities": r.responsibilities, "authorities": r.authorities,
                    "holders": mine})
    return out


def save_role(db: Session, tenant_id: str, actor: str, data: dict, row: IsmsOrgRole | None = None) -> IsmsOrgRole:
    name = js_trim(str(data.get("name") or ""))
    if not 2 <= len(name) <= 120:
        raise _error("Give the role a name of 2 to 120 characters.")
    holder_ids = list(dict.fromkeys(str(x) for x in (data.get("holderIds") or [])))
    _assert_members(db, tenant_id, holder_ids)
    for other in db.execute(select(IsmsOrgRole).where(IsmsOrgRole.tenant_id == tenant_id)).scalars():
        if other.name.lower() == name.lower() and (row is None or other.id != row.id):
            raise _error("A role with that name already exists.")
    resp = js_trim(str(data.get("responsibilities") or ""))[:8000]
    auth = js_trim(str(data.get("authorities") or ""))[:8000]
    if row is None:
        sorts = db.execute(select(IsmsOrgRole.sort).where(IsmsOrgRole.tenant_id == tenant_id)).scalars().all()
        row = IsmsOrgRole(tenant_id=tenant_id, name=name, responsibilities=resp, authorities=auth,
                          sort=max(sorts, default=0) + 1, updated_by=actor)
        db.add(row)
        db.flush()
        action = "isms.role_created"
    else:
        row.name, row.responsibilities, row.authorities = name, resp, auth
        row.updated_by, row.updated_at = actor, utcnow()
        action = "isms.role_updated"
    current = {h.user_id: h for h in db.execute(select(IsmsOrgRoleHolder).where(
        IsmsOrgRoleHolder.role_id == row.id)).scalars()}
    for uid, h in current.items():
        if uid not in holder_ids:
            db.delete(h)
    for uid in holder_ids:
        if uid not in current:
            db.add(IsmsOrgRoleHolder(tenant_id=tenant_id, role_id=row.id, user_id=uid, updated_by=actor))
    audit.record(db, actor, action, row.name, tenant_id, id=row.id, holders=holder_ids)
    return row


def delete_role(db: Session, row: IsmsOrgRole, actor: str) -> None:
    for model in (IsmsOrgRoleHolder, IsmsRaciAssignment):
        for x in db.execute(select(model).where(model.role_id == row.id)).scalars():
            db.delete(x)
    db.flush()
    db.delete(row)
    audit.record(db, actor, "isms.role_deleted", row.name, row.tenant_id, id=row.id)


# RACI -------------------------------------------------------------------------------------------------------------

def raci(db: Session, tenant_id: str) -> dict:
    activities = db.execute(select(IsmsRaciActivity).where(IsmsRaciActivity.tenant_id == tenant_id)
                            .order_by(IsmsRaciActivity.sort, IsmsRaciActivity.title)).scalars().all()
    roles = db.execute(select(IsmsOrgRole).where(IsmsOrgRole.tenant_id == tenant_id)
                       .order_by(IsmsOrgRole.sort, IsmsOrgRole.name)).scalars().all()
    cells = [RaciCell(c.activity_id, c.role_id, c.letter) for c in db.execute(
        select(IsmsRaciAssignment).where(IsmsRaciAssignment.tenant_id == tenant_id)).scalars()]
    issues = raci_issues([a.id for a in activities], cells)
    return {"activities": [{"id": a.id, "title": a.title} for a in activities],
            "roles": [{"id": r.id, "name": r.name} for r in roles],
            "cells": [{"activityId": c.activity_id, "roleId": c.role_id, "letter": c.letter} for c in cells],
            "issues": [{"activityId": i.activity_id, "problem": i.problem, "text": RACI_ISSUE_TEXT[i.problem]}
                       for i in issues]}


def add_activity(db: Session, tenant_id: str, actor: str, title: str) -> IsmsRaciActivity:
    t = js_trim(title or "")
    if not 2 <= len(t) <= 160:
        raise _error("Describe the activity in 2 to 160 characters.")
    rows = db.execute(select(IsmsRaciActivity).where(IsmsRaciActivity.tenant_id == tenant_id)).scalars().all()
    if any(a.title.lower() == t.lower() for a in rows):
        raise _error("That activity is already in the matrix.")
    row = IsmsRaciActivity(tenant_id=tenant_id, title=t, sort=max((a.sort for a in rows), default=0) + 1,
                           updated_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.raci_activity_added", t, tenant_id, id=row.id)
    return row


def delete_activity(db: Session, row: IsmsRaciActivity, actor: str) -> None:
    for x in db.execute(select(IsmsRaciAssignment).where(IsmsRaciAssignment.activity_id == row.id)).scalars():
        db.delete(x)
    db.flush()
    db.delete(row)
    audit.record(db, actor, "isms.raci_activity_deleted", row.title, row.tenant_id, id=row.id)


def save_raci_row(db: Session, activity: IsmsRaciActivity, actor: str, letters: dict[str, str]) -> None:
    """Replaces one activity's row. At most one role may be accountable."""
    chosen = {str(r): str(lt) for r, lt in (letters or {}).items() if lt}
    if any(lt not in RACI_LETTERS for lt in chosen.values()):
        raise _error("Use R, A, C or I.")
    if sum(1 for lt in chosen.values() if lt == "A") > 1:
        raise _error("Only one role can be accountable for an activity.")
    known = set(db.execute(select(IsmsOrgRole.id).where(IsmsOrgRole.tenant_id == activity.tenant_id)).scalars())
    if set(chosen) - known:
        raise _error("Unknown role in the matrix.")
    current = {c.role_id: c for c in db.execute(select(IsmsRaciAssignment).where(
        IsmsRaciAssignment.activity_id == activity.id)).scalars()}
    for role_id, c in current.items():
        if chosen.get(role_id) != c.letter:
            db.delete(c)
    db.flush()
    for role_id, letter in chosen.items():
        if role_id not in current or current[role_id].letter != letter:
            db.add(IsmsRaciAssignment(tenant_id=activity.tenant_id, activity_id=activity.id, role_id=role_id,
                                      letter=letter, updated_by=actor))
    audit.record(db, actor, "isms.raci_row_saved", activity.title, activity.tenant_id, id=activity.id,
                 letters=chosen)


# Competence -------------------------------------------------------------------------------------------------------

def competence_rows(db: Session, tenant_id: str, user_id: str | None = None) -> list[dict]:
    q = select(IsmsCompetence).where(IsmsCompetence.tenant_id == tenant_id)
    if user_id:
        q = q.where(IsmsCompetence.user_id == user_id)
    rows = db.execute(q).scalars().all()
    names = _names(db, [r.user_id for r in rows])
    ev_ids = [r.evidence_id for r in rows if r.evidence_id]
    evidence = {e.id: e.title for e in db.execute(select(IsmsEvidence).where(IsmsEvidence.id.in_(ev_ids))).scalars()} \
        if ev_ids else {}
    today = utcnow().date().isoformat()
    rows = sorted(rows, key=lambda r: r.achieved_on, reverse=True)
    rows = sorted(rows, key=lambda r: names.get(r.user_id, ""))
    return [{"id": r.id, "userId": r.user_id, "userName": names.get(r.user_id, ""), "kind": r.kind, "title": r.title,
             "achievedOn": r.achieved_on.isoformat(), "expiresOn": r.expires_on.isoformat() if r.expires_on else None,
             "status": competence_status(r.expires_on.isoformat() if r.expires_on else None, today),
             "evidenceTitle": evidence.get(r.evidence_id), "notes": r.notes} for r in rows]


def _day(value, message: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        raise _error(message) from None


def add_competence(db: Session, tenant_id: str, actor: str, data: dict) -> IsmsCompetence:
    title = js_trim(str(data.get("title") or ""))
    if not 2 <= len(title) <= 200:
        raise _error("Name the training, qualification or experience (2 to 200 characters).")
    if data.get("kind") not in COMPETENCE_KINDS:
        raise _error("Choose a type.")
    achieved = _day(data.get("achievedOn"), "Enter the date it was achieved.")
    if achieved > utcnow().date():
        raise _error("The achieved date cannot be in the future.")
    expires = None
    if data.get("expiresOn"):
        expires = _day(data["expiresOn"], "The expiry date must be on or after the achieved date.")
        if expires < achieved:
            raise _error("The expiry date must be on or after the achieved date.")
    user_id = str(data.get("userId") or "")
    _assert_members(db, tenant_id, [user_id])
    evidence_id = data.get("evidenceId") or None
    if evidence_id:
        e = db.get(IsmsEvidence, evidence_id)
        if e is None or e.tenant_id != tenant_id:
            raise _error("Evidence not found.")
    row = IsmsCompetence(tenant_id=tenant_id, user_id=user_id, kind=data["kind"], title=title, achieved_on=achieved,
                         expires_on=expires, evidence_id=evidence_id,
                         notes=js_trim(str(data.get("notes") or ""))[:4000], updated_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "isms.competence_added", title, tenant_id, id=row.id, user_id=user_id, kind=row.kind)
    return row


def delete_competence(db: Session, row: IsmsCompetence, actor: str) -> None:
    db.delete(row)
    audit.record(db, actor, "isms.competence_deleted", row.title, row.tenant_id, id=row.id, user_id=row.user_id)


# Acknowledgement campaigns ----------------------------------------------------------------------------------------

def content_sha256(version: IsmsDocumentVersion) -> str:
    return hashlib.sha256(version.html.encode()).hexdigest()


def _targets(db: Session, tenant_id: str, audience: list[str]) -> dict[str, str]:
    """User id to ISMS role for everyone the audience covers (active, unexpired roles only)."""
    from .memberships import active_role
    out = {}
    for m, u in db.execute(select(IsmsMembership, User).join(User, User.id == IsmsMembership.user_id)
                           .where(IsmsMembership.tenant_id == tenant_id)).all():
        role = active_role(db, u, tenant_id)
        if role and (not audience or role in audience):
            out[u.id] = role
    return out


def _acks(db: Session, campaign_ids: list[str]) -> dict[str, list[IsmsAcknowledgement]]:
    out: dict[str, list[IsmsAcknowledgement]] = {}
    if campaign_ids:
        for a in db.execute(select(IsmsAcknowledgement).where(IsmsAcknowledgement.campaign_id.in_(campaign_ids))).scalars():
            out.setdefault(a.campaign_id, []).append(a)
    return out


def _campaign_view(c: IsmsAckCampaign, v: IsmsDocumentVersion, d: IsmsDocument, targets: dict[str, str],
                   acks: list[IsmsAcknowledgement]) -> dict:
    p = ack_progress(list(targets), [a.user_id for a in acks])
    return {"id": c.id, "documentVersionId": v.id, "documentId": d.id, "documentTitle": d.title,
            "documentNumber": d.number, "docType": d.doc_type, "version": v.version,
            "audienceRoles": list(c.audience_roles or []), "dueOn": c.due_on.isoformat(), "status": c.status,
            "overdue": c.status == "open" and c.due_on < utcnow().date() and p.done < p.total,
            "progress": {"total": p.total, "done": p.done, "percent": p.percent}, "superseded": v.state != "published"}


def _campaigns(db: Session, tenant_id: str, campaign_id: str | None = None):
    q = (select(IsmsAckCampaign, IsmsDocumentVersion, IsmsDocument)
         .join(IsmsDocumentVersion, IsmsDocumentVersion.id == IsmsAckCampaign.document_version_id)
         .join(IsmsDocument, IsmsDocument.id == IsmsDocumentVersion.document_id)
         .where(IsmsAckCampaign.tenant_id == tenant_id))
    if campaign_id:
        q = q.where(IsmsAckCampaign.id == campaign_id)
    rows = db.execute(q).all()
    return sorted(rows, key=lambda r: (r[0].status, r[0].due_on, r[2].title))


def campaign_rows(db: Session, tenant_id: str) -> list[dict]:
    rows = _campaigns(db, tenant_id)
    acks = _acks(db, [c.id for c, _, _ in rows])
    return [_campaign_view(c, v, d, _targets(db, tenant_id, c.audience_roles or []), acks.get(c.id, []))
            for c, v, d in rows]


def campaign_candidates(db: Session, tenant_id: str) -> list[dict]:
    open_versions = set(db.execute(select(IsmsAckCampaign.document_version_id).where(
        IsmsAckCampaign.tenant_id == tenant_id, IsmsAckCampaign.status == "open")).scalars())
    rows = db.execute(select(IsmsDocumentVersion, IsmsDocument)
                      .join(IsmsDocument, IsmsDocument.id == IsmsDocumentVersion.document_id)
                      .where(IsmsDocument.tenant_id == tenant_id, IsmsDocumentVersion.state == "published")
                      .order_by(IsmsDocument.title)).all()
    return [{"versionId": v.id, "title": d.title, "number": d.number, "version": v.version}
            for v, d in rows if v.id not in open_versions]


def start_campaign(db: Session, tenant_id: str, actor: str, data: dict) -> IsmsAckCampaign:
    due = _day(data.get("dueOn"), "Choose a due date from today onwards.")
    if due < utcnow().date():
        raise _error("Choose a due date from today onwards.")
    audience = list(dict.fromkeys(str(r) for r in (data.get("audienceRoles") or [])))
    if any(r not in TENANT_ROLES for r in audience):
        raise _error("Unknown role in the audience.")
    v = db.get(IsmsDocumentVersion, str(data.get("documentVersionId") or ""))
    if v is None or v.tenant_id != tenant_id:
        raise _error("Document not found.", 404)
    if v.state != "published":
        raise _error("Only a published document can be sent for acknowledgement.")
    if db.execute(select(IsmsAckCampaign.id).where(IsmsAckCampaign.document_version_id == v.id,
                                                   IsmsAckCampaign.status == "open")).first():
        raise _error("This document already has an open campaign.")
    row = IsmsAckCampaign(tenant_id=tenant_id, document_version_id=v.id, audience_roles=audience, due_on=due,
                          updated_by=actor)
    db.add(row)
    db.flush()
    targets = _targets(db, tenant_id, audience)
    audit.record(db, actor, "isms.acknowledgement_campaign_started", row.id, tenant_id, document_version_id=v.id,
                 audience=audience, people=len(targets))
    _notify(db, row, list(targets), "is asking you to read and acknowledge")
    return row


def close_campaign(db: Session, row: IsmsAckCampaign, actor: str) -> None:
    if row.status != "open":
        return
    row.status, row.closed_at, row.updated_by = "closed", utcnow(), actor
    audit.record(db, actor, "isms.acknowledgement_campaign_closed", row.id, row.tenant_id)


def campaign_detail(db: Session, row: IsmsAckCampaign) -> dict:
    c, v, d = _campaigns(db, row.tenant_id, row.id)[0]
    targets = _targets(db, row.tenant_id, c.audience_roles or [])
    acks = {a.user_id: a for a in _acks(db, [c.id]).get(c.id, [])}
    names = _names(db, targets)
    people = [{"userId": uid, "name": names.get(uid, ""), "role": role,
               "acknowledgedAt": acks[uid].acknowledged_at.isoformat() + "Z" if uid in acks else None,
               "via": acks[uid].via if uid in acks else None} for uid, role in targets.items()]
    people.sort(key=lambda p: (p["acknowledgedAt"] is not None, p["name"]))
    return {**_campaign_view(c, v, d, targets, list(acks.values())), "people": people, "html": v.html}


def pending_for(db: Session, user: User, tenant_ids: list[str]) -> list[dict]:
    """Open campaigns that ask this person and that they have not acknowledged, across their customers."""
    from .memberships import active_role
    out = []
    held = set(db.execute(select(IsmsMembership.tenant_id).where(IsmsMembership.user_id == user.id)).scalars())
    for tid in sorted(held & set(tenant_ids)):
        role = active_role(db, user, tid)
        if not role:
            continue
        rows = [r for r in _campaigns(db, tid) if r[0].status == "open" and
                (not r[0].audience_roles or role in r[0].audience_roles)]
        acks = _acks(db, [c.id for c, _, _ in rows])
        for c, v, d in rows:
            if any(a.user_id == user.id for a in acks.get(c.id, [])):
                continue
            out.append({**_campaign_view(c, v, d, _targets(db, tid, c.audience_roles or []), acks.get(c.id, [])),
                        "tenantId": tid})
    return out


def acknowledgement_view(db: Session, row: IsmsAckCampaign, user: User) -> dict:
    """What a person needs to read and acknowledge a campaign's document."""
    c, v, d = _campaigns(db, row.tenant_id, row.id)[0]
    mine = db.execute(select(IsmsAcknowledgement).where(IsmsAcknowledgement.campaign_id == c.id,
                                                        IsmsAcknowledgement.user_id == user.id)).scalar_one_or_none()
    return {"id": c.id, "documentTitle": d.title, "documentNumber": d.number, "version": v.version,
            "dueOn": c.due_on.isoformat(), "status": c.status, "html": v.html, "sha256": content_sha256(v),
            "blocks": [{"ref": b.get("ref"), "markdown": b.get("markdown", "")} for b in (v.blocks or [])],
            "acknowledgedAt": mine.acknowledged_at.isoformat() + "Z" if mine else None}


def acknowledge(db: Session, row: IsmsAckCampaign, user: User, actor: str, sha256: str, ip: str, user_agent: str,
                via: str) -> IsmsAcknowledgement:
    """Records the person's own acknowledgement, with a hash of the text they were shown."""
    from .memberships import active_role
    if row.status != "open":
        raise _error("This campaign has closed.")
    role = active_role(db, user, row.tenant_id)
    if not role or (row.audience_roles and role not in row.audience_roles):
        raise _error("This document has not been sent to you.", 403)
    v = db.get(IsmsDocumentVersion, row.document_version_id)
    if v.state != "published":
        raise _error("This version is no longer published. Reload to read the current one.", 409)
    if sha256 != content_sha256(v):
        raise _error("The document changed while you were reading it. Reload and read it again.", 409)
    existing = db.execute(select(IsmsAcknowledgement).where(IsmsAcknowledgement.campaign_id == row.id,
                                                            IsmsAcknowledgement.user_id == user.id)).scalar_one_or_none()
    if existing:
        return existing
    a = IsmsAcknowledgement(tenant_id=row.tenant_id, campaign_id=row.id, document_version_id=v.id, user_id=user.id,
                            content_sha256=sha256, ip=ip[:64], user_agent=user_agent[:300], via=via)
    db.add(a)
    db.flush()
    audit.record(db, actor, "isms.document_acknowledged", row.id, row.tenant_id, document_version_id=v.id, via=via,
                 sha256=sha256)
    return a


def by_user(db: Session, tenant_id: str) -> list[dict]:
    """Completion per person across open and closed campaigns."""
    rows = db.execute(select(IsmsAckCampaign).where(IsmsAckCampaign.tenant_id == tenant_id)).scalars().all()
    acks = _acks(db, [c.id for c in rows])
    everyone = _targets(db, tenant_id, [])
    names = _names(db, everyone)
    out = []
    for uid, role in everyone.items():
        asked = [c for c in rows if not c.audience_roles or role in c.audience_roles]
        done = sum(1 for c in asked if any(a.user_id == uid for a in acks.get(c.id, [])))
        out.append({"userId": uid, "name": names.get(uid, ""), "asked": len(asked), "done": done})
    return sorted(out, key=lambda x: x["name"])


def _notify(db: Session, row: IsmsAckCampaign, user_ids: list[str], verb: str) -> None:
    from .. import mailer
    from ..models import Tenant
    v = db.get(IsmsDocumentVersion, row.document_version_id)
    d = db.get(IsmsDocument, v.document_id)
    tenant = db.get(Tenant, row.tenant_id)
    due = row.due_on.strftime("%d/%m/%Y")
    for u in db.execute(select(User).where(User.id.in_(user_ids))).scalars() if user_ids else []:
        where = "the client portal" if u.role == "client" else "Governance, ISMS documents"
        mailer.send(u.email, f"Please read: {d.title}",
                    f"{tenant.name if tenant else 'Your organization'} {verb} {d.number} {d.title} (version "
                    f"{v.version}) by {due}. Open it in {where}.")


def send_reminders(db: Session, today: date | None = None) -> int:
    """Daily reminder for open campaigns due within 3 days or overdue, to the people who have not acknowledged.
    Run by the hourly maintenance job; at most one reminder per campaign per day."""
    today = today or utcnow().date()
    sent = 0
    for c in db.execute(select(IsmsAckCampaign).where(IsmsAckCampaign.status == "open")).scalars().all():
        if c.last_reminded_on == today or (c.due_on - today).days > 3:
            continue
        v = db.get(IsmsDocumentVersion, c.document_version_id)
        if v is None or v.state != "published":
            continue
        done = {a.user_id for a in _acks(db, [c.id]).get(c.id, [])}
        waiting = [u for u in _targets(db, c.tenant_id, c.audience_roles or []) if u not in done]
        if waiting:
            _notify(db, c, waiting, "is still waiting for you to read and acknowledge" if c.due_on >= today
                    else "has an overdue request for you to read and acknowledge")
            sent += len(waiting)
        c.last_reminded_on = today
    return sent
