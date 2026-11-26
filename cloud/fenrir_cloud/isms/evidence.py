"""Evidence for ISMS controls: files, links, notes and Fenrir's automated GRC results.

* A control is "implemented with evidence" while it is implemented and has at least one linked piece of current
  evidence: scanned clean (or not needing a scan), and not past its valid-until date. ``refresh_states`` keeps that in
  step after every change and every hour (so expiry is noticed).
* Files are stored encrypted under the artifact directory, bound to their customer and id, and can be downloaded only
  once scanned clean. An infected file is deleted at once and the attempt kept as a record.
* Fenrir's own automated GRC evidence (``grc_automation.py``) is imported hourly: a passing result is evidence for the
  mapped controls and marks a not started or in progress control implemented; a failing one moves an implemented
  control back to in progress (as the standalone app's Fenrir connector did).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import date, timedelta

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import audit, crypto
from ..config import get_settings
from ..models import GrcEvidence, Tenant, utcnow
from . import scanning
from .domain._js import js_trim
from .fenrir_map import FENRIR_CONTROL_MAP
from .models import IsmsEvidence, IsmsEvidenceLink, IsmsTenantControl, IsmsTenantFramework

MAX_EVIDENCE_BYTES = 25 * 1024 * 1024
CURRENT_SCANS = ("clean", "not_required")


def _error(message: str, status: int = 400) -> HTTPException:
    return HTTPException(status, message)


def _dir():
    path = get_settings().artifact_dir / "isms-evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _aad(row: IsmsEvidence) -> str:
    return f"isms-evidence:{row.tenant_id}:{row.id}"


def _today() -> date:
    return utcnow().date()


def is_current(e: IsmsEvidence, today: date | None = None) -> bool:
    if e.kind == "connector_result" and not e.passing:
        return False
    return e.scan_status in CURRENT_SCANS and (e.valid_until is None or e.valid_until >= (today or _today()))


def refresh_states(db: Session, tenant_id: str) -> int:
    """implemented <-> implemented_evidenced, from the current evidence linked to each control."""
    today = _today()
    evidenced = {cid for cid, e in db.execute(select(IsmsEvidenceLink.tenant_control_id, IsmsEvidence).join(
        IsmsEvidence, IsmsEvidence.id == IsmsEvidenceLink.evidence_id).where(
        IsmsEvidenceLink.tenant_id == tenant_id)).all() if is_current(e, today)}
    changed = 0
    for c in db.execute(select(IsmsTenantControl).where(IsmsTenantControl.tenant_id == tenant_id,
                                                        IsmsTenantControl.state.in_(("implemented",
                                                                                     "implemented_evidenced")))).scalars():
        state = "implemented_evidenced" if c.id in evidenced else "implemented"
        if c.state != state:
            c.state, c.updated_at = state, utcnow()
            changed += 1
    return changed


def _controls(db: Session, tenant_id: str, ids: list[str]) -> list[IsmsTenantControl]:
    if not ids:
        raise _error("Link the evidence to at least one control.")
    rows = list(db.execute(select(IsmsTenantControl).where(IsmsTenantControl.tenant_id == tenant_id,
                                                           IsmsTenantControl.id.in_(ids))).scalars())
    if len(rows) != len(set(ids)):
        raise _error("One of the chosen controls does not exist.")
    return rows


def _valid(value) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        raise _error("Valid until must be a date.") from None


def add_link_or_note(db: Session, tenant_id: str, actor: str, user_id: str, title: str, kind: str, url: str | None,
                     note: str | None, valid_until, control_ids: list[str]) -> IsmsEvidence:
    title = js_trim(title or "")
    if not title:
        raise _error("Give the evidence a title.")
    controls = _controls(db, tenant_id, control_ids)
    row = IsmsEvidence(tenant_id=tenant_id, title=title[:300], kind=kind, valid_until=_valid(valid_until),
                       uploaded_by_user_id=user_id, updated_by=actor)
    if kind == "link":
        url = js_trim(url or "")
        if not (url.lower().startswith("https://") or url.lower().startswith("http://")) or any(c.isspace() for c in url):
            raise _error("Enter a web address starting with https:// or http://.")
        row.url = url[:2000]
    elif kind == "note":
        note = js_trim(note or "")
        if not note:
            raise _error("Write the note.")
        row.note = note[:10_000]
    else:
        raise _error("Evidence is a file, a link or a note.")
    db.add(row)
    db.flush()
    _link(db, row, controls, actor)
    audit.record(db, actor, "isms.evidence_added", row.title, tenant_id, id=row.id, kind=kind)
    refresh_states(db, tenant_id)
    return row


def add_file(db: Session, tenant_id: str, actor: str, user_id: str, title: str, filename: str, content_type: str,
             data: bytes, valid_until, control_ids: list[str]) -> IsmsEvidence:
    """Stores, hashes and scans a file. An infected file is deleted and the attempt kept (status infected)."""
    if not data:
        raise _error("Choose a file.")
    if len(data) > MAX_EVIDENCE_BYTES:
        raise _error("Files can be up to 25 MB.", 413)
    clean_name = os.path.basename(filename or "").replace("\\", "_")[:200] or "evidence"
    if scanning.BLOCKED_EXTENSIONS.search(clean_name):
        raise _error("Program and script files cannot be uploaded as evidence.")
    controls = _controls(db, tenant_id, control_ids)
    row = IsmsEvidence(tenant_id=tenant_id, title=(js_trim(title or "") or clean_name)[:300], kind="file",
                       filename=clean_name, content_type=(content_type or "application/octet-stream")[:120],
                       size=len(data), sha256=hashlib.sha256(data).hexdigest(), storage_name=secrets.token_hex(16),
                       valid_until=_valid(valid_until), uploaded_by_user_id=user_id, updated_by=actor)
    db.add(row)
    db.flush()
    _write(row, data)
    _apply_scan(db, row, data, actor)
    _link(db, row, controls, actor)
    audit.record(db, actor, "isms.evidence_uploaded", row.filename, tenant_id, id=row.id, size=row.size,
                 sha256=row.sha256, scan=row.scan_status)
    refresh_states(db, tenant_id)
    return row


def _write(row: IsmsEvidence, data: bytes) -> None:
    path = _dir() / row.storage_name
    with open(path, "w", encoding="utf-8") as out:
        os.chmod(path, 0o600)
        json.dump(crypto.encrypt(data, _aad(row)), out)


def _read(row: IsmsEvidence) -> bytes:
    with open(_dir() / row.storage_name, encoding="utf-8") as f:
        return crypto.decrypt_bytes(json.load(f), _aad(row))


def _remove_file(row: IsmsEvidence) -> None:
    if row.storage_name:
        try:
            (_dir() / row.storage_name).unlink()
        except FileNotFoundError:
            pass


def _apply_scan(db: Session, row: IsmsEvidence, data: bytes, actor: str) -> None:
    if scanning.configured():
        status, detail = scanning.scan(data)
        if status == "infected":
            _remove_file(row)
            row.storage_name = None
            row.scan_status, row.scan_detail = "infected", detail
            audit.record(db, actor, "isms.evidence_infected", row.filename or row.title, row.tenant_id, id=row.id,
                         signature=detail)
        elif status == "clean":
            row.scan_status, row.scan_detail = "clean", None
        else:
            row.scan_status, row.scan_detail = "pending", detail
    elif get_settings().environment == "production":
        row.scan_status, row.scan_detail = "pending", "Waiting for the virus scanner."
    else:
        row.scan_status, row.scan_detail = "clean", "Not scanned: no virus scanner is configured in this environment."
    if row.scan_status != "pending":
        row.scanned_at = utcnow()


def _link(db: Session, row: IsmsEvidence, controls: list[IsmsTenantControl], actor: str) -> None:
    for c in controls:
        db.add(IsmsEvidenceLink(tenant_id=row.tenant_id, evidence_id=row.id, tenant_control_id=c.id, updated_by=actor))
    db.flush()


def set_links(db: Session, row: IsmsEvidence, actor: str, control_ids: list[str]) -> None:
    if not control_ids:
        raise _error("Evidence must stay linked to at least one control.")
    wanted = {c.id for c in _controls(db, row.tenant_id, control_ids)}
    current = set(db.execute(select(IsmsEvidenceLink.tenant_control_id)
                             .where(IsmsEvidenceLink.evidence_id == row.id)).scalars())
    db.execute(delete(IsmsEvidenceLink).where(IsmsEvidenceLink.evidence_id == row.id,
                                              IsmsEvidenceLink.tenant_control_id.notin_(wanted)))
    for cid in wanted - current:
        db.add(IsmsEvidenceLink(tenant_id=row.tenant_id, evidence_id=row.id, tenant_control_id=cid, updated_by=actor))
    db.flush()
    audit.record(db, actor, "isms.evidence_relinked", row.title, row.tenant_id, id=row.id, controls=sorted(wanted))
    refresh_states(db, row.tenant_id)


def set_valid_until(db: Session, row: IsmsEvidence, actor: str, value) -> None:
    row.valid_until, row.expiry_notified_at = _valid(value), None
    row.updated_at, row.updated_by = utcnow(), actor
    audit.record(db, actor, "isms.evidence_validity_set", row.title, row.tenant_id, id=row.id,
                 validUntil=row.valid_until.isoformat() if row.valid_until else None)
    refresh_states(db, row.tenant_id)


def delete_evidence(db: Session, row: IsmsEvidence, actor: str) -> None:
    audit.record(db, actor, "isms.evidence_deleted", row.title, row.tenant_id, id=row.id, sha256=row.sha256)
    db.execute(delete(IsmsEvidenceLink).where(IsmsEvidenceLink.evidence_id == row.id))
    _remove_file(row)
    tenant_id = row.tenant_id
    db.delete(row)
    db.flush()
    refresh_states(db, tenant_id)


def file_for_download(row: IsmsEvidence) -> bytes:
    """The file, only once it has been scanned clean (or did not need a scan)."""
    if row.kind != "file" or not row.storage_name:
        raise _error("There is no file for this evidence." if row.scan_status != "infected"
                     else "This file was rejected by the virus scanner.")
    if row.scan_status not in CURRENT_SCANS:
        raise _error("This file was rejected by the virus scanner." if row.scan_status == "infected"
                     else "This file has not been virus scanned yet.", 409)
    return _read(row)


# Fenrir's automated GRC evidence ----------------------------------------------------------------------------

def import_fenrir(db: Session, tenant_id: str, actor: str = "system:isms") -> dict:
    """Imports Fenrir automated evidence newer than what was imported last, per Fenrir control."""
    controls = {c.ref: c for c in db.execute(select(IsmsTenantControl).where(
        IsmsTenantControl.tenant_id == tenant_id, IsmsTenantControl.state != "not_applicable")).scalars()}
    imported = set(db.execute(select(IsmsEvidence.source_ref).where(IsmsEvidence.tenant_id == tenant_id,
                                                                    IsmsEvidence.kind == "connector_result")).scalars())
    latest: dict[str, GrcEvidence] = {}
    for e in db.execute(select(GrcEvidence).where(GrcEvidence.tenant_id == tenant_id, GrcEvidence.kind == "automated",
                                                  GrcEvidence.control_id.in_(list(FENRIR_CONTROL_MAP)))
                        .order_by(GrcEvidence.created_at)).scalars():
        latest[e.control_id] = e
    out = {"imported": 0, "passing": 0, "failing": 0, "controlsChanged": 0}
    for fc, e in sorted(latest.items()):
        if e.id in imported:
            continue
        targets = [controls[ref] for ref in FENRIR_CONTROL_MAP[fc] if ref in controls]
        if not targets:
            continue
        passing = (e.data or {}).get("status") == "passing"
        row = IsmsEvidence(tenant_id=tenant_id, title=f"Fenrir: {e.title}"[:300], kind="connector_result",
                           note=(e.description or "")[:10_000], source=f"fenrir:{fc}", source_ref=e.id, passing=passing,
                           sha256=e.sha256, content_type="application/json", collected_at=e.created_at,
                           valid_until=e.valid_until.date() if passing and e.valid_until else None,
                           scan_status="not_required", updated_by=actor)
        db.add(row)
        db.flush()
        out["imported"] += 1
        out["passing" if passing else "failing"] += 1
        for c in targets:
            if passing:
                db.add(IsmsEvidenceLink(tenant_id=tenant_id, evidence_id=row.id, tenant_control_id=c.id,
                                        updated_by=actor))
            nxt = (("implemented" if c.state in ("not_started", "in_progress") else None) if passing
                   else ("in_progress" if c.state in ("implemented", "implemented_evidenced") else None))
            if nxt:
                c.state, c.updated_at, c.updated_by = nxt, utcnow(), actor
                c.implementation = c.implementation or f"Checked by Fenrir ({fc})."
                out["controlsChanged"] += 1
        db.flush()
    if out["imported"]:
        audit.record(db, actor, "isms.fenrir_evidence_imported", f"{out['imported']} result(s)", tenant_id, **out)
    refresh_states(db, tenant_id)
    return out


def rescan_pending(db: Session, tenant_id: str, actor: str = "system:isms") -> int:
    if not scanning.configured():
        return 0
    done = 0
    for row in db.execute(select(IsmsEvidence).where(IsmsEvidence.tenant_id == tenant_id, IsmsEvidence.kind == "file",
                                                     IsmsEvidence.scan_status == "pending")).scalars():
        _apply_scan(db, row, _read(row), actor)
        done += row.scan_status != "pending"
    return done


def expiring(db: Session, tenant_id: str, within_days: int = 30) -> list[IsmsEvidence]:
    """Linked evidence that expires within the window and has not been flagged yet."""
    horizon = _today() + timedelta(days=within_days)
    return list(db.execute(select(IsmsEvidence).where(IsmsEvidence.tenant_id == tenant_id,
                                                      IsmsEvidence.valid_until.is_not(None),
                                                      IsmsEvidence.valid_until <= horizon,
                                                      IsmsEvidence.expiry_notified_at.is_(None))).scalars())


def tick(db: Session) -> None:
    """Hourly, for every customer with an ISMS programme: import Fenrir results, rescan pending files, refresh
    evidenced states (expiry) and flag evidence that is about to expire."""
    tenants = set(db.execute(select(IsmsTenantFramework.tenant_id)).scalars())
    for tenant_id in sorted(tenants):
        if db.get(Tenant, tenant_id) is None:
            continue
        import_fenrir(db, tenant_id)
        rescan_pending(db, tenant_id)
        refresh_states(db, tenant_id)
        for e in expiring(db, tenant_id):
            e.expiry_notified_at = utcnow()
            audit.record(db, "system:isms", "isms.evidence_expiring", e.title, tenant_id, id=e.id,
                         validUntil=e.valid_until.isoformat())
        db.commit()
