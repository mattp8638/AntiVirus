"""Cross-module business logic shared by routers and the detection pipeline."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from datetime import timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit, policy_schema
from .commands import BY_TYPE
from .models import Command, Contract, Device, DeviceGroup, Policy, Tenant, Ticket, Webhook, utcnow

log = logging.getLogger("fenrir.services")

GLOBAL_POLICY_ID = "pol_global"
SEVERITY_ORDER = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_at_least(severity: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(floor, 99)


# ---------------------------------------------------------------------------
# Policy resolution
# ---------------------------------------------------------------------------


def _policy_chain(db: Session, policy_id: str | None, seen: set[str]) -> list[Policy]:
    """A policy and its parent policies, most general first."""
    chain: list[Policy] = []
    while policy_id and policy_id not in seen:
        seen.add(policy_id)
        policy = db.get(Policy, policy_id)
        if policy is None:
            break
        chain.append(policy)
        policy_id = policy.parent_id
    return list(reversed(chain))


def _group_chain(db: Session, group_id: str | None) -> list[DeviceGroup]:
    chain: list[DeviceGroup] = []
    seen: set[str] = set()
    while group_id and group_id not in seen:
        seen.add(group_id)
        group = db.get(DeviceGroup, group_id)
        if group is None:
            break
        chain.append(group)
        group_id = group.parent_id
    return list(reversed(chain))


def policy_layers(db: Session, tenant: Tenant | None, group_id: str | None = None, device: Device | None = None) -> list[policy_schema.Layer]:
    seen: set[str] = set()
    ordered: list[tuple[str, Policy]] = []
    for policy in _policy_chain(db, GLOBAL_POLICY_ID, seen):
        ordered.append(("global", policy))
    if tenant is not None:
        for policy in _policy_chain(db, tenant.default_policy_id, seen):
            ordered.append((f"tenant:{tenant.name}", policy))
    for group in _group_chain(db, group_id if device is None else device.group_id):
        for policy in _policy_chain(db, group.policy_id, seen):
            ordered.append((f"group:{group.name}", policy))
    if device is not None:
        for policy in _policy_chain(db, device.policy_id, seen):
            ordered.append((f"device:{device.hostname}", policy))
    return [policy_schema.Layer(name=f"{scope} / {policy.name}", settings=policy.settings or {}, locks=policy.locks or [])
            for scope, policy in ordered]


def effective_policy(db: Session, device: Device) -> tuple[dict, dict]:
    """Returns (resolution, agent_document) for a device."""
    tenant = db.get(Tenant, device.tenant_id)
    layers = policy_layers(db, tenant, device=device)
    resolution = policy_schema.resolve(layers)
    name = layers[-1].name if layers else "Fenrir baseline"
    doc = policy_schema.to_agent_policy(policy_id=device.policy_id or (tenant.default_policy_id if tenant else None) or GLOBAL_POLICY_ID,
                                        name=name, settings=resolution["settings"])
    return resolution, doc


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


class CommandError(ValueError):
    pass


def enqueue_command(
    db: Session,
    device: Device,
    command_type: str,
    issued_by: str,
    target_path: str = "",
    record_id: str = "",
    payload: dict | None = None,
    reason: str = "",
    incident_id: str | None = None,
) -> Command:
    spec = BY_TYPE.get(command_type)
    if spec is None:
        raise CommandError(f"unknown command type '{command_type}'")
    if "targetPath" in spec.needs and not target_path:
        raise CommandError(f"{command_type} needs targetPath")
    if "recordId" in spec.needs and not record_id:
        raise CommandError(f"{command_type} needs recordId")
    if device.platform not in spec.platforms:
        raise CommandError(f"{command_type} is not supported on {device.platform}")
    # Don't stack identical pending actions (e.g. two auto-isolations). Different payloads (another remote
    # session, a script with other parameters) are different actions.
    for existing in db.execute(
        select(Command).where(Command.device_id == device.id, Command.type == command_type, Command.status == "pending",
                              Command.target_path == target_path, Command.record_id == record_id)
    ).scalars():
        if (existing.payload or {}) == (payload or {}):
            return existing
    command = Command(
        tenant_id=device.tenant_id, device_id=device.id, type=command_type, issued_by=issued_by,
        target_path=target_path, record_id=record_id, payload=payload or {}, reason=reason, incident_id=incident_id,
    )
    db.add(command)
    # Agents holding a realtime channel are told to poll as soon as this commits.
    db.info.setdefault("wake_devices", set()).add(device.id)
    audit.record(db, issued_by, "command.queued", f"{device.hostname}:{command_type}", device.tenant_id,
                 targetPath=target_path, recordId=record_id, reason=reason)
    return command


# ---------------------------------------------------------------------------
# PSA tickets
# ---------------------------------------------------------------------------

DEFAULT_SLA_HOURS = {"P1": 1, "P2": 4, "P3": 24, "P4": 72}
PRIORITY_BY_SEVERITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}


def msp_tenant_id(db: Session, tenant_id: str) -> str:
    """Tickets and invoices belong to the MSP that manages the customer."""
    tenant = db.get(Tenant, tenant_id)
    while tenant is not None and tenant.kind != "msp" and tenant.parent_id:
        tenant = db.get(Tenant, tenant.parent_id)
    return tenant.id if tenant else tenant_id


def sla_hours(db: Session, account_tenant_id: str | None, priority: str) -> int:
    if account_tenant_id:
        contract = db.execute(
            select(Contract).where(Contract.account_tenant_id == account_tenant_id, Contract.active.is_(True))
        ).scalars().first()
        if contract and contract.sla.get(priority):
            return int(contract.sla[priority])
    return DEFAULT_SLA_HOURS.get(priority, 24)


def open_ticket(
    db: Session,
    account_tenant_id: str,
    subject: str,
    description: str = "",
    priority: str = "P3",
    source: str = "manual",
    requester: str = "",
    incident_id: str | None = None,
    device_id: str | None = None,
    queue: str = "Service Desk",
    board_id: str | None = None,
    **fields,
) -> Ticket:
    """Open a ticket on a service board, apply its SLA, auto-assign, and run "ticket created" workflow rules."""
    from . import psa

    owner = msp_tenant_id(db, account_tenant_id)
    board = None
    if board_id:
        from .models import Board

        board = db.get(Board, board_id)
        if board is not None and board.tenant_id != owner:
            board = None
    if board is None:
        board = psa.board_by_name(db, owner, queue)
    number = (db.execute(select(func.max(Ticket.number)).where(Ticket.tenant_id == owner)).scalar() or 1000) + 1
    now = utcnow()
    ticket = Ticket(
        number=number, tenant_id=owner, account_tenant_id=account_tenant_id, subject=subject[:300], description=description,
        priority=priority, source=source, requester=requester, incident_id=incident_id, device_id=device_id,
        queue=board.name if board else queue, board_id=board.id if board else None, status=psa.default_status(board),
        created_at=now, updated_at=now, status_changed_at=now, comments=[], tasks=[], resources=[], configuration_ids=[],
        workflow_fired=[],
    )
    for key, value in fields.items():
        if hasattr(ticket, key) and value is not None:
            setattr(ticket, key, value)
    if ticket.agreement_id is None:
        agreement = psa.active_agreement(db, account_tenant_id)
        ticket.agreement_id = agreement.id if agreement else None
    psa.apply_sla(db, ticket)
    if board is not None and not ticket.assignee and board.auto_assign == "round_robin":
        ticket.assignee = psa.next_round_robin(db, board)
    db.add(ticket)
    db.flush()
    psa.run_workflows(db, ticket, "ticket.created")
    return ticket


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------


def _format_webhook(kind: str, event: str, body: dict) -> dict:
    title = body.get("title") or event
    text = f"*{title}*\nSeverity: {body.get('severity', 'n/a')}  Tenant: {body.get('tenant', '')}\n{body.get('url', '')}"
    if kind == "slack":
        return {"text": text}
    if kind == "teams":
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": title, "text": text}
    return {"event": event, "data": body}


def _post(url: str, payload: dict, secret: str) -> None:
    data = json.dumps(payload, default=str).encode()
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Fenrir-Signature"] = "sha256=" + hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()
    try:
        httpx.post(url, content=data, headers=headers, timeout=5.0)
    except httpx.HTTPError as exc:  # pragma: no cover - network dependent
        log.warning("webhook delivery to %s failed: %s", url, exc)


def fire_webhooks(db: Session, tenant_id: str, event: str, body: dict) -> int:
    hooks = db.execute(select(Webhook).where(Webhook.tenant_id.in_({tenant_id, msp_tenant_id(db, tenant_id)}),
                                             Webhook.enabled.is_(True))).scalars().all()
    sent = 0
    for hook in hooks:
        if event in (hook.events or []) or "*" in (hook.events or []):
            threading.Thread(target=_post, args=(hook.url, _format_webhook(hook.kind, event, body), hook.secret), daemon=True).start()
            sent += 1
    return sent
