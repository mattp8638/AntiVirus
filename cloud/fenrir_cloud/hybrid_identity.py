"""Hybrid identity: users that Entra Connect syncs from on-premises Active Directory to Microsoft 365.

For a synced user, Active Directory is the source of truth: Microsoft refuses cloud changes to the account itself
(name, sign-in blocking, password, synced groups). Fenrir makes those changes where they belong, on the customer's
domain controller, through its agent:

- ``ad.directory`` commands run one allowlisted operation of the agent's embedded script (create, disable, a random
  password, group removal, move to an OU, description, address-book hiding) on a domain controller, or an Entra
  Connect delta sync on the server that runs Entra Connect;
- a new starter's temporary password travels encrypted in the command and is released once, only to the domain
  controller the command was sent to, then deleted (the same pattern as switch and Intel AMT credentials);
- cloud-only work (licences, cloud groups, sessions, MFA, out-of-office) still goes through Microsoft Graph.

Which domain belongs to which Microsoft 365 tenant: the domain controllers of the same Fenrir customer.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import activedirectory, audit, crypto, presence, services
from .models import Command, Device, DeviceProfile, Tenant, utcnow

SECRET_WINDOW = timedelta(minutes=30)
SYNC_WORKLOAD = "Entra Connect (Azure AD Connect)"
OPTIONS_TTL = timedelta(hours=12)


class HybridError(Exception):
    pass


def context(db: Session, tenant_id: str) -> dict:
    """The customer's domain controllers and Entra Connect server, best first."""
    controllers = []
    domain = None
    for device, profile, data in activedirectory._dc_profiles(db, [tenant_id]):
        ad = data.get("activeDirectory") if isinstance(data.get("activeDirectory"), dict) else {}
        domain = domain or ((ad.get("domain") or {}).get("dnsName") if isinstance(ad.get("domain"), dict) else None) or \
            (data.get("role") or {}).get("domain")
        controllers.append({"deviceId": device.id, "hostname": device.hostname, "online": presence.is_up(device),
                            "entraConnect": SYNC_WORKLOAD in ((data.get("role") or {}).get("workloads") or [])})
    controllers.sort(key=lambda c: (not c["online"], c["hostname"]))
    sync = next((c for c in controllers if c["entraConnect"]), None)
    if sync is None:
        # Entra Connect is often on a member server rather than a domain controller.
        rows = db.execute(select(Device, DeviceProfile).join(DeviceProfile, DeviceProfile.device_id == Device.id)
                          .where(Device.tenant_id == tenant_id)).all()
        for device, profile in rows:
            if device.api_key_hash == f"retired-{device.id}":
                continue
            if SYNC_WORKLOAD in (((profile.profile or {}).get("role") or {}).get("workloads") or []):
                sync = {"deviceId": device.id, "hostname": device.hostname, "online": presence.is_up(device), "entraConnect": True}
                break
    tenant = db.get(Tenant, tenant_id)
    cached = (tenant.settings or {}).get("adOptions") if tenant else None
    return {"available": bool(controllers), "domain": domain, "controllers": controllers,
            "controller": next((c for c in controllers if c["online"]), controllers[0] if controllers else None),
            "syncServer": sync, "options": (cached or {}).get("data"), "optionsAt": (cached or {}).get("at"),
            "optionsCommandId": (cached or {}).get("commandId")}


def send(db: Session, tenant_id: str, device_id: str, operation: str, params: dict, actor: str, secret: str | None = None,
         reason: str = "") -> Command:
    device = db.get(Device, device_id)
    if device is None or device.tenant_id != tenant_id:
        raise HybridError("That server does not belong to this customer")
    payload = {"operation": operation, "params": params}
    if secret:
        payload["secret"] = True
    try:
        command = services.enqueue_command(db, device, "ad.directory", actor, payload=payload,
                                           reason=reason or f"Active Directory: {operation}")
    except services.CommandError as exc:
        raise HybridError(str(exc)) from None
    db.flush()
    if secret:
        command.payload = {**command.payload, "secretEnvelope": crypto.encrypt(secret, _aad(command))}
    audit.record(db, actor, "ad.directory.sent", operation, tenant_id, device=device.hostname, command=command.id,
                 identity=str(params.get("identity") or params.get("sam") or "")[:200])
    return command


def _aad(command: Command) -> str:
    return f"ad-secret:{command.tenant_id}:{command.id}"


def release_secret(db: Session, device: Device, command: Command) -> str:
    """The one-time secret of an ad.directory command, released once, only to the device it was sent to."""
    payload = command.payload or {}
    if (command.device_id != device.id or command.type != "ad.directory" or not payload.get("secretEnvelope")
            or command.status not in ("pending", "dispatched") or utcnow() - command.created_at > SECRET_WINDOW):
        raise HybridError("No secret is available for this command")
    secret = crypto.decrypt(payload["secretEnvelope"], _aad(command))
    command.payload = {k: v for k, v in payload.items() if k != "secretEnvelope"} | {"secretReleased": utcnow().isoformat() + "Z"}
    audit.record(db, f"device:{device.hostname}", "ad.directory.secret_released", command.id, command.tenant_id)
    return secret


def outcome(command: Command | None) -> tuple[str, dict]:
    """("waiting" | "done" | "failed", details) for an ad.directory command."""
    if command is None:
        return "failed", {"error": "The command is gone"}
    if command.status in ("pending", "dispatched", "cancelling"):
        if utcnow() - command.created_at > timedelta(hours=2):
            return "failed", {"error": "The server did not pick up the command within 2 hours (is its agent online?)"}
        return "waiting", {}
    result = command.result or {}
    if command.status == "completed" and result.get("ok") is True:
        return "done", result
    error = result.get("error") or result.get("message") or f"the command ended {command.status}"
    return "failed", {"error": str(error)[:500]}


def refresh_options(db: Session, tenant_id: str, actor: str) -> Command:
    ctx = context(db, tenant_id)
    if not ctx["controller"]:
        raise HybridError("No domain controller with the Fenrir agent is known for this customer")
    command = send(db, tenant_id, ctx["controller"]["deviceId"], "options", {}, actor, reason="Read OUs and groups for onboarding")
    tenant = db.get(Tenant, tenant_id)
    cached = (tenant.settings or {}).get("adOptions") or {}
    tenant.settings = {**(tenant.settings or {}), "adOptions": {**cached, "commandId": command.id}}
    return command


def collect_options(db: Session, tenant_id: str) -> None:
    """Store the result of the latest options command, once it has finished."""
    tenant = db.get(Tenant, tenant_id)
    cached = (tenant.settings or {}).get("adOptions") or {} if tenant else {}
    if not cached.get("commandId"):
        return
    state, result = outcome(db.get(Command, cached["commandId"]))
    if state == "waiting":
        return
    if state == "done":
        data = {k: result.get(k) for k in ("domain", "netbios", "usersContainer", "upnSuffixes", "ous", "groups", "adsyncHere")}
        tenant.settings = {**(tenant.settings or {}), "adOptions": {"data": data, "at": utcnow().isoformat() + "Z", "commandId": None}}
    else:
        tenant.settings = {**(tenant.settings or {}), "adOptions": {**cached, "commandId": None, "error": result.get("error")}}
