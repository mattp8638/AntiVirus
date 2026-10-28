"""Cancellation is a request until the endpoint has stopped its owned work and acknowledged it."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .models import Command, Device, utcnow

ACTIVE = ("pending", "dispatched", "cancelling")


def request_cancel(db: Session, command: Command, actor: str, *, retire_key: str | None = None) -> bool:
    """Callers hold the command row lock. Never overwrite a completed outcome."""
    if command.status not in ACTIVE:
        return False
    first = command.cancel_requested_at is None
    now = utcnow()
    if first:
        command.cancel_requested_at, command.cancel_requested_by = now, actor
    if retire_key and command.status in ("dispatched", "cancelling"):
        if not command.cancel_api_key_hash:
            command.cancel_requested_at, command.cancel_requested_by = now, actor
        command.cancel_api_key_hash = retire_key
    if command.status == "pending":
        command.status, command.completed_at = "cancelled", now
        command.result = {"cancelledBeforeExecution": True, "stopConfirmed": True}
    else:
        command.status = "cancelling"
    command.updated_at = now
    if first:
        audit.record(db, actor, "command.cancel.requested", command.id, command.tenant_id,
                     type=command.type, status=command.status)
    return True


def cancel_commands(db: Session, actor: str, *, device: Device | None = None, ids: list[str] | None = None,
                    retiring: bool = False) -> dict:
    query = select(Command).where(Command.status.in_(ACTIVE)).order_by(Command.id).with_for_update()
    if device is not None:
        query = query.where(Command.device_id == device.id)
    if ids is not None:
        query = query.where(Command.id.in_(ids))
    pending = stopping = 0
    jobs = set()
    for command in db.execute(query.execution_options(populate_existing=True)).scalars():
        was_pending = command.status == "pending"
        request_cancel(db, command, actor, retire_key=device.api_key_hash if retiring and device else None)
        pending += was_pending
        stopping += not was_pending
        payload = command.payload if isinstance(command.payload, dict) else {}
        if payload.get("jobId"):
            jobs.add((payload["jobId"], command.tenant_id))
    db.flush()
    from . import rmm
    for job_id, tenant_id in jobs:
        job = db.get(rmm.Job, job_id)
        if job is None or job.tenant_id != tenant_id:
            continue
        if job is not None and job.status == "running" and stopping:
            job.status = "cancelling"
        rmm.refresh_job(db, job_id)
    return {"cancelledPending": pending, "stopRequested": stopping, "cancellationComplete": stopping == 0}
