"""eDiscovery cases over backups (backup/docs/design/ediscovery.md).

A case names custodians (machines, SaaS tenants, optionally only some of a tenant's accounts). While it is open, their
backups are on legal hold (and, with `hold_new`, every later backup too), searches run on the machines that keep the
backups and their matches are kept with the case, and exports are made on those machines with a manifest of each item's
SHA-256, encrypted for the requesting browser. The case's manifest (custodians, holds, searches, exports with the
agent's manifest hash and the server's hash of the encrypted stream, the audit trail) is the chain-of-custody record.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import backup as bk
from .models import AuditLog, BackupCase, BackupImage, BackupJob, utcnow

MAX_HITS = 5000
PREFIX = "case:"


def device_key(i: BackupImage) -> str:
    """Same key as the console's machine list (routers/backup.py _device_key)."""
    if (i.machine_id or "").startswith(("saas:", "k8s:", "cdp:")):
        return f"app:{i.machine_id}|"
    return f"{i.agent_id or 'host:' + (i.hostname or '')}|{i.vm_name or ''}"


def custodian_images(db: Session, case: BackupCase) -> list[BackupImage]:
    keys = {c.get("device") for c in case.custodians or []}
    if not keys:
        return []
    rows = db.execute(select(BackupImage).where(BackupImage.tenant_id == case.tenant_id)
                      .order_by(BackupImage.created_unix.desc())).scalars().all()
    return [i for i in rows if device_key(i) in keys]


def _hold(im: BackupImage, case: BackupCase, actor: str) -> bool:
    h = dict(im.legal_hold or {})
    cases = list(h.get("cases") or [])
    if case.id in cases:
        return False
    if not h:
        h = {"reason": f"eDiscovery case {case.name}" + (f" ({case.matter})" if case.matter else ""), "by": actor,
             "at": utcnow().isoformat(), "caseOnly": True}
    h["cases"] = cases + [case.id]
    im.legal_hold = h
    return True


def _release(im: BackupImage, case: BackupCase) -> bool:
    h = dict(im.legal_hold or {})
    cases = [c for c in h.get("cases") or [] if c != case.id]
    if len(cases) == len(h.get("cases") or []):
        return False
    if not cases and h.get("caseOnly"):
        im.legal_hold = None
    else:
        h["cases"] = cases
        im.legal_hold = h
    return True


def apply_holds(db: Session, case: BackupCase, actor: str) -> tuple[int, int]:
    """Hold the custodians' backups while the case is open; release those of removed custodians (or all, closed)."""
    keys = {c.get("device") for c in case.custodians or []} if case.status == "open" else set()
    held = released = 0
    for im in db.execute(select(BackupImage).where(BackupImage.tenant_id == case.tenant_id)).scalars():
        if device_key(im) in keys:
            held += _hold(im, case, actor)
        elif case.id in ((im.legal_hold or {}).get("cases") or []):
            released += _release(im, case)
    return held, released


def hold_new_image(db: Session, im: BackupImage) -> None:
    """A new backup of a custodian of an open case that holds later backups too."""
    key = device_key(im)
    for case in db.execute(select(BackupCase).where(BackupCase.tenant_id == im.tenant_id, BackupCase.status == "open",
                                                    BackupCase.hold_new.is_(True))).scalars():
        if any(c.get("device") == key for c in case.custodians or []):
            _hold(im, case, f"case:{case.id}")


def _accounts(case: BackupCase, image_id: str, db: Session) -> list[str] | None:
    im = db.get(BackupImage, image_id)
    if im is None:
        return None
    c = next((c for c in case.custodians or [] if c.get("device") == device_key(im)), None)
    return [a.lower() for a in (c or {}).get("accounts") or []] or None


def record_job(db: Session, job: BackupJob, state: str) -> None:
    """A case's search or export job finished: keep its matches, or the export's hashes, with the case."""
    parts = (job.requested_by or "").split(":")
    if len(parts) < 4 or parts[0] != "case":
        return
    case = db.get(BackupCase, parts[1])
    if case is None or case.tenant_id != job.tenant_id:
        return
    what, entry_id = parts[2], parts[3]
    result = job.result if isinstance(job.result, dict) else {}
    if what == "search":
        searches = [dict(s) for s in case.searches or []]
        for s in searches:
            if s.get("id") != entry_id:
                continue
            hits = list(s.get("hits") or [])
            for h in result.get("hits") or []:
                if len(hits) >= MAX_HITS:
                    s["truncated"] = True
                    break
                if h.get("account"):
                    allowed = _accounts(case, str(h.get("image_id")), db)
                    if allowed is not None and str(h["account"]).lower() not in allowed:
                        continue
                hits.append({k: h.get(k) for k in ("image_id", "volume", "path", "size", "modified", "folder",
                                                   "account", "kind")})
            s["hits"] = hits
            s["truncated"] = bool(s.get("truncated") or result.get("truncated"))
            s["notIndexed"] = int(s.get("notIndexed") or 0) + int(result.get("not_indexed") or 0)
            done = set(s.get("done") or []) | {job.id}
            s["done"] = sorted(done)
            if job.error:
                s.setdefault("errors", []).append(job.error[:500])
            if done >= set(s.get("jobs") or []):
                s["state"] = "done"
        case.searches = searches
    elif what == "export":
        exports = [dict(e) for e in case.exports or []]
        for e in exports:
            if e.get("id") != entry_id:
                continue
            e["state"] = state
            e["finishedAt"] = utcnow().isoformat()
            e["manifestSha256"] = result.get("manifest_sha256")
            e["manifestEntries"] = result.get("manifest_files")
            e["error"] = job.error
            path = bk.download_path(job.id)
            if path.exists():
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for block in iter(lambda: f.read(1 << 20), b""):
                        h.update(block)
                e["ciphertextSha256"], e["ciphertextBytes"] = h.hexdigest(), path.stat().st_size
        case.exports = exports
    bk.record(db, f"backup-agent:{job.agent_id}", f"backup.case.{what}_finished", case.name, case.tenant_id,
              case=case.id, job=job.id, state=state)


def manifest(db: Session, case: BackupCase) -> dict:
    """The case's chain-of-custody record, with the SHA-256 of its own canonical JSON."""
    held = [{"imageId": i.image_id, "machine": i.vm_name or i.hostname, "createdUnix": i.created_unix,
             "repositoryId": i.repository_id}
            for i in db.execute(select(BackupImage).where(BackupImage.tenant_id == case.tenant_id)).scalars()
            if case.id in ((i.legal_hold or {}).get("cases") or [])]
    trail = [{"at": a.at.isoformat(), "actor": a.actor, "action": a.action, "details": a.details, "hash": a.hash}
             for a in db.execute(select(AuditLog).where(AuditLog.tenant_id == case.tenant_id,
                                                        AuditLog.action.like("backup.case.%"))
                                 .order_by(AuditLog.id)).scalars()
             if (a.details or {}).get("case") == case.id]
    doc = {
        "format": "fenrir-ediscovery-case", "version": 1, "generatedAt": utcnow().isoformat(),
        "case": {"id": case.id, "name": case.name, "matter": case.matter, "description": case.description,
                 "status": case.status, "createdBy": case.created_by, "createdAt": case.created_at.isoformat(),
                 "closedBy": case.closed_by, "closedAt": case.closed_at.isoformat() if case.closed_at else None,
                 "holdNewBackups": case.hold_new},
        "custodians": case.custodians,
        "holds": sorted(held, key=lambda h: (h["machine"] or "", h["createdUnix"])),
        "searches": [{k: s.get(k) for k in ("id", "query", "by", "at", "state", "truncated", "notIndexed")}
                     | {"hits": len(s.get("hits") or [])} for s in case.searches or []],
        "exports": case.exports,
        "auditTrail": trail,
    }
    doc["sha256"] = hashlib.sha256(json.dumps(doc, sort_keys=True, default=str).encode()).hexdigest()
    return doc
