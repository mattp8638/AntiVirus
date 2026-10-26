"""Forensic and support bundles uploaded by agents, and their audited download from the console."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, current_device, current_principal
from ..models import Command, Device, DeviceArtifact, utcnow
from ..serialize import to_dict

agent = APIRouter(prefix="/api/v1", tags=["Agent artifacts"])
console = APIRouter(prefix="/api/console", tags=["Device artifacts"])

BUNDLE_COMMANDS = {"forensics.collect", "support.bundle", "support.bundle.sanitized"}
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def artifact_dir() -> Path:
    path = get_settings().artifact_dir
    path.mkdir(parents=True, exist_ok=True)
    return path


def _view(row: DeviceArtifact) -> dict:
    return to_dict(row, exclude={"storage_name"})


@agent.post("/devices/{device_id}/commands/{command_id}/artifact")
async def upload_artifact(command_id: str, request: Request, filename: str = Query("bundle.tar.gz", max_length=200),
                          sha256: str = Query("", max_length=64), device: Device = Depends(current_device),
                          db: Session = Depends(get_db)):
    """The agent streams the bundle body; sent before it completes the command. One artifact per command."""
    command = db.get(Command, command_id)
    if command is None or command.device_id != device.id or command.tenant_id != device.tenant_id:
        raise HTTPException(404, "Unknown command")
    if command.type not in BUNDLE_COMMANDS:
        raise HTTPException(400, "This command does not produce an uploadable bundle")
    if command.status not in {"pending", "dispatched"}:
        raise HTTPException(409, "The command is already finished")
    if db.scalar(select(DeviceArtifact.id).where(DeviceArtifact.command_id == command.id)):
        raise HTTPException(409, "A bundle was already uploaded for this command")
    limit = get_settings().artifact_max_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"Bundles are limited to {limit // (1024 * 1024)} MB")
    storage_name = secrets.token_hex(16)
    target = artifact_dir() / storage_name
    digest, size = hashlib.sha256(), 0
    try:
        with open(target, "wb") as out:
            os.chmod(target, 0o600)
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, f"Bundles are limited to {limit // (1024 * 1024)} MB")
                digest.update(chunk)
                out.write(chunk)
        if size == 0:
            raise HTTPException(400, "Empty bundle")
        if sha256 and sha256.lower() != digest.hexdigest():
            raise HTTPException(400, "Bundle SHA-256 does not match; upload again")
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    clean = SAFE_NAME.sub("_", filename).strip("._") or "bundle.bin"
    row = DeviceArtifact(tenant_id=device.tenant_id, device_id=device.id, command_id=command.id, kind=command.type,
                         filename=f"{device.hostname}-{clean}"[:200], size=size, sha256=digest.hexdigest(), storage_name=storage_name)
    db.add(row)
    audit.record(db, f"device:{device.hostname}", "artifact.uploaded", row.filename, device.tenant_id, size=size, command=command.id)
    db.commit()
    return {"artifactId": row.id, "size": size, "sha256": row.sha256}


@console.get("/devices/{device_id}/artifacts")
def list_artifacts(device_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    device = db.get(Device, device_id)
    if device is None or device.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    rows = db.scalars(select(DeviceArtifact).where(DeviceArtifact.device_id == device.id).order_by(DeviceArtifact.created_at.desc()))
    return [_view(r) for r in rows]


@console.get("/artifacts/{artifact_id}/download")
def download_artifact(artifact_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Bundles hold process lists, logs and file copies: incident responders only, and every download is audited."""
    principal.require("respond")
    row = db.get(DeviceArtifact, artifact_id)
    if row is None or row.tenant_id not in principal.tenant_ids:
        raise HTTPException(404, "Not found")
    path = artifact_dir() / row.storage_name
    if not path.is_file():
        raise HTTPException(410, "The bundle file is no longer stored")
    audit.record(db, principal.actor, "artifact.downloaded", row.filename, row.tenant_id, artifact=row.id)
    db.commit()
    return FileResponse(path, filename=row.filename, media_type="application/octet-stream",
                        headers={"Cache-Control": "private, no-store", "X-Content-SHA256": row.sha256})


def purge_expired(db: Session) -> int:
    """Delete bundles past the retention period (scheduler pass)."""
    cutoff = utcnow() - timedelta(days=get_settings().artifact_retention_days)
    expired = list(db.scalars(select(DeviceArtifact).where(DeviceArtifact.created_at < cutoff).limit(500)))
    for row in expired:
        (get_settings().artifact_dir / row.storage_name).unlink(missing_ok=True)
        db.delete(row)
    return len(expired)
