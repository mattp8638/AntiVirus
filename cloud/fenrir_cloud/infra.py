"""Hypervisor and virtual infrastructure monitoring from the providers' own APIs (RMM-14).

Fenrir reads the state the provider itself reports. It does not stop at checking that a TCP port answers.

* **Proxmox VE:** nodes (online or offline, CPU, memory), virtual machines and containers (running or stopped, and
  the node each is on), and storage (active, used and total). Read with an API token
  (``PVEAPIToken=user@realm!id=secret``) through ``/api2/json``.
* **VMware vCenter:** hosts (connection and power state), virtual machines (power state and host), and datastores
  (capacity and free space). Read through the vSphere Automation REST API with a session.

**Relationships.** Each virtual machine and storage item records its parent host.

**Dependency-aware alerts.**

* If the provider cannot be reached, or refuses the credential, that is the one alert. Its assets become ``unknown``
  and raise nothing of their own.
* A host that is offline or not responding raises one alert. The virtual machines on it are ``suppressed`` with that
  reason, not alerted one by one.
* A virtual machine that is not in its expected state raises an alert. The expected state is set from what was seen
  the first time, and can be changed per VM.
* Storage at or above ``STORAGE_FULL`` used, or inactive, raises an alert.

Alerts are deduplicated per asset and resolved when the asset recovers.

**Routes.**

* ``direct``: the Fenrir server calls the API. Public addresses only, checked by the address guard.
* ``agent``: a probe device on the customer's network makes the calls with the ``infra.poll`` command. The agent
  asks the cloud for the credential once for that command, and it is never in the command payload. The agent sends
  only the fixed read requests of the provider. The Linux and macOS agents support this; the Windows agent does not
  yet.
"""
from __future__ import annotations

import base64
import json
import logging
from datetime import timedelta
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, crypto, netguard, services
from .models import Alert, Command, Device, InfraAsset, InfraSource, utcnow

log = logging.getLogger("fenrir.infra")

PROVIDERS = {"proxmox": "Proxmox VE", "vsphere": "VMware vCenter"}
STORAGE_FULL = 0.9
ALERT_RULE = "infra.health"
COMMAND = "infra.poll"
CREDENTIAL_WINDOW = timedelta(minutes=10)
MAX_HOSTS = 50


class InfraError(Exception):
    pass


def validate_url(url: str) -> str:
    p = urlparse(url.strip())
    if p.scheme != "https" or not p.hostname or p.path not in ("", "/") or p.query or p.username:
        raise InfraError("Enter the https:// address of the server only, for example https://pve.example.local:8006")
    return f"https://{p.netloc}"


def store_credentials(source: InfraSource, creds: dict) -> None:
    if source.provider == "proxmox":
        if not creds.get("tokenId") or not creds.get("secret") or "!" not in creds["tokenId"]:
            raise InfraError("Enter the API token ID (user@realm!name) and its secret")
        data = {"tokenId": creds["tokenId"], "secret": creds["secret"]}
    else:
        if not creds.get("username") or not creds.get("password"):
            raise InfraError("Enter the vCenter user name and password (a read-only role is enough)")
        data = {"username": creds["username"], "password": creds["password"]}
    source.credentials_envelope = crypto.encrypt(json.dumps(data), f"infra:{source.id}")


def _creds(source: InfraSource) -> dict:
    return json.loads(crypto.decrypt(source.credentials_envelope, f"infra:{source.id}"))


# ---- fetching (direct route; the agent does the same calls) --------------------------------------------------------

def fetch(source: InfraSource, client: httpx.Client) -> list[dict]:
    """The provider's responses as [{name, status, body}] (the same shape the agent returns)."""
    creds, base = _creds(source), source.base_url
    out = []

    def get(name, path, headers):
        r = client.get(base + path, headers=headers)
        out.append({"name": name, "status": r.status_code, "body": r.text[:2_000_000]})
        return r

    if source.provider == "proxmox":
        h = {"Authorization": f"PVEAPIToken={creds['tokenId']}={creds['secret']}"}
        for name, path in (("nodes", "/api2/json/nodes"), ("vms", "/api2/json/cluster/resources?type=vm"),
                           ("storage", "/api2/json/cluster/resources?type=storage")):
            if get(name, path, h).status_code in (401, 403):
                break
        return out
    basic = base64.b64encode(f"{creds['username']}:{creds['password']}".encode()).decode()
    r = client.post(base + "/api/session", headers={"Authorization": "Basic " + basic})
    out.append({"name": "session", "status": r.status_code, "body": ""})
    if r.status_code >= 400:
        return out
    h = {"vmware-api-session-id": r.json() if r.content else ""}
    hosts = get("hosts", "/api/vcenter/host", h)
    get("vms", "/api/vcenter/vm", h)
    get("datastores", "/api/vcenter/datastore", h)
    if hosts.status_code == 200:
        for host in (hosts.json() or [])[:MAX_HOSTS]:
            get("vms-on:" + host["host"], "/api/vcenter/vm?hosts=" + host["host"], h)
    client.delete(base + "/api/session", headers=h)
    return out


# ---- parsing --------------------------------------------------------------------------------------------------------

def _json(responses: dict, name: str):
    r = responses.get(name)
    if r is None or r.get("status") != 200:
        return None
    try:
        return json.loads(r.get("body") or "null")
    except ValueError:
        return None


def parse(provider: str, raw: list[dict]) -> tuple[str, str, list[dict]]:
    """(status, error, assets) from provider responses."""
    responses = {r.get("name"): r for r in raw if isinstance(r, dict)}
    failures = [r for r in raw if isinstance(r, dict) and r.get("status") in (401, 403)]
    if failures:
        return "auth_failed", f"{PROVIDERS[provider]} refused the credential (HTTP {failures[0]['status']})", []
    errors = [r for r in raw if isinstance(r, dict) and (r.get("status") or 0) == 0]
    if errors or not raw:
        return "unreachable", (errors[0].get("error") if errors else "No answer") or "No answer", []
    assets = []
    if provider == "proxmox":
        nodes = (_json(responses, "nodes") or {}).get("data")
        if nodes is None:
            return "error", "Proxmox did not return its nodes", []
        for n in nodes:
            assets.append({"kind": "host", "id": n["node"], "name": n["node"], "parent": "",
                           "state": "online" if n.get("status") == "online" else n.get("status") or "unknown",
                           "metrics": {"cpu": n.get("cpu"), "memUsed": n.get("mem"), "memTotal": n.get("maxmem"), "uptime": n.get("uptime")}})
        for v in (_json(responses, "vms") or {}).get("data") or []:
            if v.get("template"):
                continue
            assets.append({"kind": "vm", "id": str(v.get("id") or v.get("vmid")), "name": v.get("name") or str(v.get("vmid")),
                           "parent": v.get("node", ""), "state": v.get("status") or "unknown",
                           "metrics": {"type": v.get("type"), "cpu": v.get("cpu"), "memUsed": v.get("mem"), "memTotal": v.get("maxmem")}})
        for s in (_json(responses, "storage") or {}).get("data") or []:
            total, used = s.get("maxdisk") or 0, s.get("disk") or 0
            assets.append({"kind": "storage", "id": s.get("id") or f"{s.get('node')}/{s.get('storage')}", "name": s.get("storage") or s.get("id"),
                           "parent": s.get("node", ""), "state": "available" if s.get("status") == "available" else s.get("status") or "unknown",
                           "metrics": {"used": used, "total": total, "usedFraction": round(used / total, 3) if total else None}})
        return "ok", "", assets
    hosts = _json(responses, "hosts")
    if hosts is None:
        return "error", "vCenter did not return its hosts", []
    for h in hosts:
        state = "connected" if h.get("connection_state") == "CONNECTED" else str(h.get("connection_state") or "unknown").lower()
        assets.append({"kind": "host", "id": h["host"], "name": h.get("name") or h["host"], "parent": "", "state": state,
                       "metrics": {"power": h.get("power_state")}})
    host_of = {}
    for name, r in responses.items():
        if name and name.startswith("vms-on:") and r.get("status") == 200:
            for v in json.loads(r.get("body") or "[]"):
                host_of[v["vm"]] = name.split(":", 1)[1]
    for v in _json(responses, "vms") or []:
        power = str(v.get("power_state") or "").upper()
        assets.append({"kind": "vm", "id": v["vm"], "name": v.get("name") or v["vm"], "parent": host_of.get(v["vm"], ""),
                       "state": {"POWERED_ON": "running", "POWERED_OFF": "stopped", "SUSPENDED": "suspended"}.get(power, power.lower() or "unknown"),
                       "metrics": {"cpus": v.get("cpu_count"), "memoryMiB": v.get("memory_size_MiB")}})
    for d in _json(responses, "datastores") or []:
        total, free = d.get("capacity") or 0, d.get("free_space") or 0
        assets.append({"kind": "storage", "id": d["datastore"], "name": d.get("name") or d["datastore"], "parent": "", "state": "available",
                       "metrics": {"used": total - free, "total": total, "usedFraction": round((total - free) / total, 3) if total else None}})
    return "ok", "", assets


# ---- evaluation and alerts -----------------------------------------------------------------------------------------

HOST_UP = {"online", "connected"}


def _alert(db: Session, source: InfraSource, key: str, title: str, severity: str, description: str) -> None:
    open_ = db.scalars(select(Alert).where(Alert.tenant_id == source.tenant_id, Alert.rule_id == ALERT_RULE,
                                           Alert.status.in_(("new", "triaged")))).all()
    if any((a.details or {}).get("key") == key for a in open_):
        return
    db.add(Alert(tenant_id=source.tenant_id, rule_id=ALERT_RULE, title=title[:300], severity=severity, mitre=[], event_ids=[],
                 details={"category": "infrastructure", "source": PROVIDERS[source.provider], "key": key, "description": description,
                          "link": "/infrastructure", "sourceId": source.id}))


def _resolve(db: Session, source: InfraSource, key: str) -> None:
    for a in db.scalars(select(Alert).where(Alert.tenant_id == source.tenant_id, Alert.rule_id == ALERT_RULE,
                                            Alert.status.in_(("new", "triaged")))).all():
        if (a.details or {}).get("key") == key:
            a.status, a.updated_at = "resolved", utcnow()


def apply(db: Session, source: InfraSource, raw: list[dict]) -> dict:
    status, error, found = parse(source.provider, raw)
    now = utcnow()
    source.status, source.last_error, source.last_polled_at = status, error[:500], now
    existing = {(a.kind, a.external_id): a for a in db.scalars(select(InfraAsset).where(InfraAsset.source_id == source.id))}
    src_key = f"source:{source.id}"
    if status != "ok":
        _alert(db, source, src_key, f"{source.name}: {PROVIDERS[source.provider]} {'refused the credential' if status == 'auth_failed' else 'cannot be read'}",
               "high", error + ". The state of its hosts and virtual machines is unknown until it can be read again.")
        for a in existing.values():
            a.health, a.reason = "unknown", f"{source.name} could not be read"
        return {"status": status, "error": error}
    _resolve(db, source, src_key)
    seen = set()
    for f in found:
        key = (f["kind"], f["id"])
        seen.add(key)
        a = existing.get(key)
        if a is None:
            a = InfraAsset(tenant_id=source.tenant_id, source_id=source.id, kind=f["kind"], external_id=f["id"],
                           expected_state="running" if f["kind"] == "vm" and f["state"] == "running" else "")
            db.add(a)
            existing[key] = a
        a.name, a.parent_external_id, a.state, a.metrics, a.missing, a.last_seen_at = f["name"], f["parent"], f["state"], f["metrics"], False, now
    for key, a in existing.items():
        if key not in seen:
            a.missing = True
    hosts = {a.external_id: a for a in existing.values() if a.kind == "host"}
    counts = {"alert": 0, "suppressed": 0, "ok": 0}
    for a in existing.values():
        akey = f"asset:{source.id}:{a.kind}:{a.external_id}"
        problem, severity = "", "medium"
        parent = hosts.get(a.parent_external_id)
        if a.kind == "host":
            if a.missing:
                problem, severity = "is no longer reported", "medium"
            elif a.state not in HOST_UP:
                problem, severity = f"is {a.state}", "critical"
        elif parent is not None and (parent.state not in HOST_UP or parent.missing):
            a.health, a.reason = "suppressed", f"Its host {parent.name} is {parent.state}"
            _resolve(db, source, akey)
            counts["suppressed"] += 1
            continue
        elif a.kind == "vm":
            if a.missing and a.expected_state:
                problem, severity = "is no longer reported", "medium"
            elif a.expected_state and a.state != a.expected_state:
                problem, severity = f"is {a.state} (expected {a.expected_state})", "high"
        elif a.kind == "storage":
            frac = (a.metrics or {}).get("usedFraction")
            if a.state != "available":
                problem, severity = f"is {a.state}", "high"
            elif frac is not None and frac >= STORAGE_FULL:
                problem, severity = f"is {round(frac * 100)}% full", "medium"
        if problem:
            a.health, a.reason = "alert", f"{a.name} {problem}"
            _alert(db, source, akey, f"{source.name}: {a.kind} {a.name} {problem}", severity,
                   f"Reported by {PROVIDERS[source.provider]} at {now:%Y-%m-%d %H:%M} UTC.")
            counts["alert"] += 1
        else:
            a.health, a.reason = "ok", ""
            _resolve(db, source, akey)
            counts["ok"] += 1
    return {"status": "ok", "assets": len(seen), **counts}


# ---- polling ----------------------------------------------------------------------------------------------------------

def _client(source: InfraSource) -> httpx.Client:
    return httpx.Client(timeout=20, follow_redirects=False, verify=not source.tls_insecure)


def poll(db: Session, source: InfraSource, actor: str = "system:infra") -> dict:
    if source.route == "direct":
        host = urlparse(source.base_url).hostname or ""
        try:
            netguard.resolve_public(host)
        except netguard.Blocked as exc:
            return apply(db, source, [{"name": "connect", "status": 0, "error": f"{exc}; use a probe device on that network"}])
        except OSError:
            pass
        try:
            with _client(source) as client:
                raw = fetch(source, client)
        except httpx.HTTPError as exc:
            raw = [{"name": "connect", "status": 0, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}]
        return apply(db, source, raw)
    probe = db.get(Device, source.probe_device_id) if source.probe_device_id else None
    if probe is None or probe.tenant_id != source.tenant_id:
        return apply(db, source, [{"name": "connect", "status": 0, "error": "No probe device on the customer's network is chosen"}])
    if (probe.platform or "").lower().startswith("win"):
        return apply(db, source, [{"name": "connect", "status": 0, "error": "Windows probe devices cannot poll infrastructure yet; choose a Linux or macOS device"}])
    waiting = db.scalars(select(Command).where(Command.device_id == probe.id, Command.type == COMMAND, Command.status.in_(("pending", "dispatched")))).all()
    if any((c.payload or {}).get("infraSourceId") == source.id for c in waiting):
        return {"status": "waiting"}
    command = services.enqueue_command(db, probe, COMMAND, actor, payload={"infraSourceId": source.id, "provider": source.provider},
                                       reason=f"Poll {PROVIDERS[source.provider]} {source.name}")
    return {"status": "queued", "commandId": command.id}


def credential_for_command(db: Session, device: Device, command: Command) -> dict:
    """Base address and credential for one pending infra.poll command, released once to the device it was sent to."""
    payload = command.payload or {}
    if (command.device_id != device.id or command.type != COMMAND or command.status not in ("pending", "dispatched")
            or payload.get("credentialReleased") or utcnow() - command.created_at > CREDENTIAL_WINDOW):
        raise InfraError("No credential is available for this command")
    source = db.get(InfraSource, payload.get("infraSourceId") or "")
    if source is None or source.tenant_id != device.tenant_id or source.probe_device_id != device.id or source.route != "agent":
        raise InfraError("No credential is available for this command")
    command.payload = {**payload, "credentialReleased": utcnow().isoformat() + "Z"}
    audit.record(db, f"device:{device.hostname}", "infra.credential.released", source.name, source.tenant_id, command=command.id, source=source.id)
    return {"provider": source.provider, "baseUrl": source.base_url, "tlsInsecure": source.tls_insecure, **_creds(source)}


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    source = db.get(InfraSource, (command.payload or {}).get("infraSourceId") or "")
    if source is None or source.tenant_id != device.tenant_id or source.probe_device_id != device.id:
        return
    if command.status != "completed":
        apply(db, source, [{"name": "agent", "status": 0, "error": str((command.result or {}).get("error") or command.status)[:300]}])
        return
    apply(db, source, (command.result or {}).get("responses") or [])


def tick(db: Session) -> int:
    """Poll each source when it is due (every poll_minutes)."""
    now, done = utcnow(), 0
    for source in db.scalars(select(InfraSource)).all():
        if source.last_polled_at and now - source.last_polled_at < timedelta(minutes=source.poll_minutes):
            continue
        try:
            poll(db, source)
            if source.route == "agent":
                source.last_polled_at = now  # the agent's answer updates it again
            db.commit()
            done += 1
        except Exception:  # noqa: BLE001
            db.rollback()
            log.exception("infra poll of %s failed", source.id)
    return done
