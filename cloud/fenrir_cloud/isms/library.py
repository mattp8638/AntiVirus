"""The content library: immutable snapshots of every shipped content pack version.

At startup ``publish_shipped`` validates the packs in ``isms/packs`` as one set and stores any pack version the
database does not have yet. A stored version is never changed: editing a pack's content means raising its
``pack_version``. Customers stay on the framework versions they chose until an upgrade is reviewed, so older versions
stay readable here after newer ones ship.

Library rows are platform content, not tenant data: they have no ``tenant_id`` and every customer reads them.
"""

from __future__ import annotations

import hashlib
import json
import logging
from functools import lru_cache
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import utcnow
from .content import PACKS_ROOT, find_pack_dirs, load_pack, validate_packs
from .models import IsmsContentPack

log = logging.getLogger(__name__)


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


@lru_cache(maxsize=1)
def shipped() -> tuple[dict, ...]:
    """The shipped packs, validated together and serialized, once per process."""
    result = validate_packs([load_pack(d) for d in find_pack_dirs(PACKS_ROOT, ("questionnaires",))])
    if not result.ok:
        problems = "; ".join(f"{i.pack} {i.where}: {i.message}" for i in result.errors()[:10])
        raise RuntimeError(f"Shipped ISMS content packs are invalid: {problems}")
    out = []
    for p in result.packs:
        data = {
            "meta": p.meta.model_dump(mode="json", exclude_none=True),
            "groups": [g.model_dump(mode="json", exclude_none=True) for g in p.groups],
            "requirements": [r.model_dump(mode="json", exclude_none=True) for r in p.requirements],
            "controls": [c.model_dump(mode="json", exclude_none=True) for c in p.controls],
            "mappings": [m.model_dump(mode="json", exclude_none=True) for m in p.mappings],
            "questions": [q.model_dump(mode="json", exclude_none=True) for q in p.questions],
            "rules": [r.model_dump(mode="json") for r in p.rules],
            "templates": [{"file": t.path.name, "meta": t.meta.model_dump(mode="json", exclude_none=True), "body": t.body}
                          for t in p.templates],
        }
        text = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        out.append({"data": data, "sha256": hashlib.sha256(text.encode()).hexdigest()})
    return tuple(out)


def publish_shipped(db: Session) -> list[str]:
    """Stores shipped pack versions the database does not have. Returns the ``pack@version`` strings added."""
    existing = {(r.pack_id, r.pack_version): r.sha256 for r in db.execute(select(IsmsContentPack)).scalars()}
    added = []
    for item in shipped():
        meta = item["data"]["meta"]
        key = (meta["id"], meta["pack_version"])
        if key in existing:
            if existing[key] != item["sha256"]:
                log.error("ISMS content pack %s@%s changed without a new pack_version; the stored version is kept",
                          *key)
            continue
        db.add(IsmsContentPack(pack_id=meta["id"], pack_version=meta["pack_version"], kind=meta["kind"],
                               framework=meta.get("framework"), licence=meta["licence"], data=item["data"],
                               sha256=item["sha256"], published_at=utcnow()))
        added.append(f"{key[0]}@{key[1]}")
    return added


def versions(db: Session, pack_id: str) -> list[IsmsContentPack]:
    rows = db.execute(select(IsmsContentPack).where(IsmsContentPack.pack_id == pack_id)).scalars().all()
    return sorted(rows, key=lambda r: _version_key(r.pack_version))


def latest(db: Session, pack_id: str) -> IsmsContentPack | None:
    rows = versions(db, pack_id)
    return rows[-1] if rows else None


def get(db: Session, pack_id: str, pack_version: str) -> IsmsContentPack | None:
    return db.execute(select(IsmsContentPack).where(IsmsContentPack.pack_id == pack_id,
                                                    IsmsContentPack.pack_version == pack_version)).scalar_one_or_none()


def latest_frameworks(db: Session) -> list[IsmsContentPack]:
    """The newest version of each framework pack."""
    best: dict[str, IsmsContentPack] = {}
    for r in db.execute(select(IsmsContentPack).where(IsmsContentPack.kind == "framework")).scalars():
        cur = best.get(r.pack_id)
        if cur is None or _version_key(r.pack_version) > _version_key(cur.pack_version):
            best[r.pack_id] = r
    return list(best.values())


def common_controls(db: Session) -> dict[str, dict[str, Any]]:
    """The newest common control library, by control ref."""
    pack = latest(db, "common-controls")
    return {c["ref"]: c for c in (pack.data["controls"] if pack else [])}


def template_sections(db: Session) -> list[str]:
    pack = latest(db, "templates")
    if pack is None:
        return []
    return sorted({s for t in pack.data["templates"] for s in t["meta"].get("sections", [])})
