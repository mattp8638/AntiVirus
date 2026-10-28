"""Staged agent rollouts (AGT-04).

Each new agent build for a platform starts at the canary stage. A device is offered the build once the rollout has
reached the device's ring, taken from its updates.channel policy (canary -> beta -> stable -> lts). A stage moves on
after its soak time when nothing in it failed; a stage with no devices moves on at once, so fleets that use no rings
update as before. A failure - a device that took the build but still reports the old one an hour later while
online, went silent after taking it, or refused it - pauses the rollout before the next ring is offered anything.
Platform administrators can pause, resume, advance and emergency-stop a rollout; every change is audited.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit
from .models import AgentRollout, AgentRolloutDevice, Device, Event, utcnow

STAGES = ("canary", "beta", "stable", "lts")
SOAK = {"canary": timedelta(hours=2), "beta": timedelta(hours=24), "stable": timedelta(hours=72), "lts": timedelta(0)}
UPDATE_GRACE = timedelta(minutes=60)  # time a device has to come back on the new build after taking it


def ring_of(settings: dict) -> int:
    channel = str((settings.get("updates") or {}).get("channel") or "stable")
    return STAGES.index(channel) if channel in STAGES else STAGES.index("stable")


def _note(rollout: AgentRollout, actor: str, action: str, detail: str = "") -> None:
    rollout.history = [*(rollout.history or []), {"at": utcnow().isoformat() + "Z", "by": actor, "action": action,
                                                  "stage": STAGES[min(rollout.stage, len(STAGES) - 1)], "detail": detail}][-200:]


def current(db: Session, platform: str, build: str, version: str = "") -> AgentRollout:
    """The rollout for this build, starting one (and superseding the platform's older ones) when the build is new."""
    rollout = db.execute(select(AgentRollout).where(AgentRollout.platform == platform, AgentRollout.build == build)).scalar_one_or_none()
    if rollout is not None:
        return rollout
    for older in db.execute(select(AgentRollout).where(AgentRollout.platform == platform,
                                                        AgentRollout.state.in_(("active", "paused")))).scalars():
        older.state = "superseded"
        _note(older, "system", "superseded", f"by build {build}")
    rollout = AgentRollout(platform=platform, build=build, version=version, stage=0, state="active", history=[])
    _note(rollout, "system", "started", f"version {version}".strip())
    db.add(rollout)
    db.flush()
    audit.record(db, "system", "agent.rollout.started", f"{platform}:{build}", None, version=version)
    return rollout


_RING_CACHE: dict[tuple[str, int], tuple[datetime, bool]] = {}
RING_CACHE_TTL = timedelta(minutes=5)


def ring_has_devices(db: Session, platform: str, stage: int, now: datetime | None = None) -> bool:
    """Whether any approved device of this platform is in the ring. Stops at the first match and is cached briefly,
    because update checks from the whole fleet call it."""
    from . import services

    now = now or utcnow()
    cached = _RING_CACHE.get((platform, stage))
    if cached and now - cached[0] < RING_CACHE_TTL:
        return cached[1]
    found = False
    for device in db.execute(select(Device).where(Device.platform == platform, Device.approved.is_(True))).scalars():
        try:
            resolution, _ = services.effective_policy(db, device)
        except Exception:  # noqa: BLE001 - a device without a resolvable policy counts as the default ring
            resolution = {"settings": {}}
        if ring_of(resolution["settings"]) == stage:
            found = True
            break
    _RING_CACHE[(platform, stage)] = (now, found)
    return found


def evaluate(db: Session, rollout: AgentRollout, now: datetime | None = None) -> AgentRollout:
    """Resolve offered devices, pause on failure, and advance through stages whose soak time has passed."""
    now = now or utcnow()
    if rollout.state not in ("active", "paused"):
        return rollout
    offers = db.execute(select(AgentRolloutDevice).where(AgentRolloutDevice.rollout_id == rollout.id,
                                                         AgentRolloutDevice.outcome == "pending")).scalars().all()
    for offer in offers:
        device = db.get(Device, offer.device_id)
        if device is None:
            offer.outcome, offer.detail, offer.resolved_at = "failed", "device removed", now
        elif device.agent_build == rollout.build:
            offer.outcome, offer.resolved_at = "updated", now
        elif _rejected(db, device, offer.offered_at):
            offer.outcome, offer.detail, offer.resolved_at = "failed", "the agent refused the update", now
        elif now - offer.offered_at > UPDATE_GRACE:
            seen = device.last_seen_at
            offer.outcome, offer.resolved_at = "failed", now
            offer.detail = ("still running the previous build an hour after taking the update" if seen and seen > offer.offered_at + UPDATE_GRACE / 2
                            else "stopped checking in after taking the update")
        if offer.outcome == "failed" and rollout.state == "active":
            rollout.state = "paused"
            rollout.reason = f"Paused automatically: {device.hostname if device else offer.device_id} - {offer.detail}"
            _note(rollout, "system", "paused", rollout.reason)
            audit.record(db, "system", "agent.rollout.paused", f"{rollout.platform}:{rollout.build}", offer.tenant_id, reason=rollout.reason)
    while rollout.state == "active" and rollout.stage < len(STAGES) - 1:
        stage = STAGES[rollout.stage]
        pending = any(o.outcome == "pending" and o.stage == rollout.stage for o in offers)
        in_ring = ring_has_devices(db, rollout.platform, rollout.stage, now)
        if in_ring and (pending or now - rollout.stage_started_at < SOAK[stage]):
            break
        rollout.stage += 1
        rollout.stage_started_at = now
        _note(rollout, "system", "advanced", f"{stage} {'had no devices' if not in_ring else 'passed its soak time'}")
    if rollout.state == "active" and rollout.stage == len(STAGES) - 1:
        rollout.state = "complete"
        _note(rollout, "system", "complete")
    return rollout


def _rejected(db: Session, device: Device, since: datetime) -> bool:
    return db.execute(select(Event.id).where(Event.device_id == device.id, Event.event_type == "agent.update.rejected",
                                             Event.received_at >= since).limit(1)).first() is not None


def offer(db: Session, device: Device, platform: str, build: str, version: str = "", record: bool = True) -> tuple[bool, str]:
    """Whether to offer this device the build now. With record (the device updates automatically), the offer is
    tracked so its outcome counts towards the rollout's health; a device that will not act on it is not tracked."""
    from . import services

    rollout = evaluate(db, current(db, platform, build, version))
    resolution, _ = services.effective_policy(db, device)
    ring = ring_of(resolution["settings"])
    if device.agent_build == build:
        return True, "already on this build"
    if rollout.state in ("paused", "stopped"):
        return False, f"rollout {rollout.state}: {rollout.reason}".strip()
    if rollout.state != "complete" and ring > rollout.stage:
        return False, f"waiting for the {STAGES[rollout.stage]} stage to finish (this device is in the {STAGES[ring]} ring)"
    existing = db.execute(select(AgentRolloutDevice).where(AgentRolloutDevice.rollout_id == rollout.id,
                                                           AgentRolloutDevice.device_id == device.id)).scalar_one_or_none()
    if existing is None and record:
        db.add(AgentRolloutDevice(rollout_id=rollout.id, device_id=device.id, tenant_id=device.tenant_id, stage=ring))
    return True, ""


def act(db: Session, rollout: AgentRollout, action: str, actor: str, reason: str = "") -> AgentRollout:
    if action == "pause" and rollout.state == "active":
        rollout.state, rollout.reason = "paused", reason or "Paused by an administrator"
    elif action == "resume" and rollout.state == "paused":
        rollout.state, rollout.reason, rollout.stage_started_at = "active", "", utcnow()
    elif action == "advance" and rollout.state in ("active", "paused") and rollout.stage < len(STAGES) - 1:
        rollout.stage += 1
        rollout.stage_started_at = utcnow()
    elif action == "stop" and rollout.state in ("active", "paused", "complete"):
        rollout.state, rollout.reason = "stopped", reason or "Emergency stop"
    else:
        raise ValueError(f"cannot {action} a {rollout.state} rollout")
    _note(rollout, actor, action, reason)
    audit.record(db, actor, f"agent.rollout.{action}", f"{rollout.platform}:{rollout.build}", None, reason=reason, stage=STAGES[rollout.stage])
    return rollout


def view(db: Session, rollout: AgentRollout) -> dict:
    offers = db.execute(select(AgentRolloutDevice).where(AgentRolloutDevice.rollout_id == rollout.id)).scalars().all()
    counts = {k: sum(1 for o in offers if o.outcome == k) for k in ("pending", "updated", "failed")}
    return {"id": rollout.id, "platform": rollout.platform, "build": rollout.build, "version": rollout.version,
            "stage": STAGES[min(rollout.stage, len(STAGES) - 1)], "state": rollout.state, "reason": rollout.reason,
            "startedAt": rollout.started_at.isoformat() + "Z", "stageStartedAt": rollout.stage_started_at.isoformat() + "Z",
            "devices": counts, "failures": [{"deviceId": o.device_id, "detail": o.detail} for o in offers if o.outcome == "failed"][:50],
            "history": rollout.history or []}
