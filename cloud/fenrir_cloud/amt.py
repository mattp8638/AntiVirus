"""Intel AMT / vPro out-of-band management over WS-Management.

AMT answers on the machine's own network port even when Windows is crashed, powered off (on standby power) or
mid-reinstall: Fenrir uses it to read the power state and AMT version and to power on, power off, power cycle or
reset the machine. Hardware KVM is reached through a remote tunnel to the AMT address (port 5900 when AMT's
standard VNC port is enabled, or 16994/16995 for a redirection-aware viewer).

Two routes to the management engine:

* ``direct``: the Fenrir server talks to it (the customer network is reachable over a site VPN).
* ``agent``: a Fenrir agent on the same LAN performs the HTTP requests (``amt.wsman``). The AMT password is never in
  the command: the agent fetches the connection details once, for that command only, from
  ``POST /api/v1/devices/<id>/commands/<command>/amt-credential``.

Every request is one WS-Management call authenticated with HTTP Digest (AMT's admin realm).
"""

from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from datetime import timedelta

import httpx
from sqlalchemy.orm import Session

from . import audit, crypto, services
from .models import AmtEndpoint, Command, Device, utcnow

crypto.register_encrypted(AmtEndpoint, "secret_envelope", lambda row: f"amt:{row.tenant_id}:{row.id}")

PORTS = (16992, 16993)  # HTTP, TLS
CREDENTIAL_WINDOW = timedelta(minutes=10)

NS_S = "http://www.w3.org/2003/05/soap-envelope"
NS_WSA = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
NS_WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
NS_WSEN = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"
NS_WSMID = "http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"
CIM = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
AMT = "http://intel.com/wbem/wscim/1/amt-schema/1/"
ANONYMOUS = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

# CIM_PowerManagementService.RequestPowerStateChange values Intel AMT accepts.
POWER_ACTIONS = {"on": 2, "cycle": 5, "off": 8, "reset": 10, "graceful-off": 12, "graceful-reset": 14}
POWER_STATES = {2: "on", 3: "sleep (light)", 4: "sleep (deep)", 5: "power cycle", 6: "off (hard)", 7: "hibernate", 8: "off",
                9: "power cycle (hard)", 10: "reset", 11: "NMI", 12: "off (graceful)", 13: "off (hard, graceful)",
                14: "reset (graceful)", 15: "power cycle (graceful)", 16: "power cycle (hard, graceful)"}
RETURN_VALUES = {0: "completed", 1: "not supported", 2: "unknown or unspecified error", 3: "timed out", 4: "failed",
                 5: "invalid parameter", 6: "in use", 4096: "job started", 4097: "invalid state transition",
                 4098: "use of timeout parameter not supported", 4099: "busy", 2147500034: "not ready"}


class AmtError(Exception):
    pass


# --------------------------------------------------------------------------- WS-Management messages


def _selectors(selectors: dict[str, str] | None) -> str:
    if not selectors:
        return ""
    items = "".join(f'<wsman:Selector Name="{k}">{v}</wsman:Selector>' for k, v in selectors.items())
    return f"<wsman:SelectorSet>{items}</wsman:SelectorSet>"


def envelope(action: str, resource_uri: str, body: str = "", selectors: dict[str, str] | None = None) -> str:
    return (f'<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="{NS_S}" xmlns:wsa="{NS_WSA}" xmlns:wsman="{NS_WSMAN}">'
            f'<s:Header><wsa:Action s:mustUnderstand="true">{action}</wsa:Action><wsa:To s:mustUnderstand="true">/wsman</wsa:To>'
            f'<wsman:ResourceURI s:mustUnderstand="true">{resource_uri}</wsman:ResourceURI>'
            f'<wsa:MessageID s:mustUnderstand="true">uuid:{uuid.uuid4()}</wsa:MessageID>'
            f'<wsa:ReplyTo><wsa:Address>{ANONYMOUS}</wsa:Address></wsa:ReplyTo><wsman:OperationTimeout>PT60S</wsman:OperationTimeout>'
            f'{_selectors(selectors)}</s:Header><s:Body>{body}</s:Body></s:Envelope>')


def identify() -> str:
    return f'<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="{NS_S}" xmlns:wsmid="{NS_WSMID}"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>'


def get(resource_uri: str, selectors: dict[str, str] | None = None) -> str:
    return envelope("http://schemas.xmlsoap.org/ws/2004/09/transfer/Get", resource_uri, selectors=selectors)


def enumerate_items(resource_uri: str) -> str:
    """An optimised enumeration: the items come back in the Enumerate response itself, so one request is enough."""
    body = (f'<wsen:Enumerate xmlns:wsen="{NS_WSEN}"><wsman:OptimizeEnumeration/><wsman:MaxElements>20</wsman:MaxElements>'
            f'</wsen:Enumerate>')
    return envelope(f"{NS_WSEN}/Enumerate", resource_uri, body)


def power_change(action: str) -> str:
    state = POWER_ACTIONS[action]
    service = CIM + "CIM_PowerManagementService"
    body = (f'<p:RequestPowerStateChange_INPUT xmlns:p="{service}"><p:PowerState>{state}</p:PowerState>'
            f'<p:ManagedElement><wsa:Address>{ANONYMOUS}</wsa:Address><wsa:ReferenceParameters>'
            f'<wsman:ResourceURI>{CIM}CIM_ComputerSystem</wsman:ResourceURI>'
            f'{_selectors({"CreationClassName": "CIM_ComputerSystem", "Name": "ManagedSystem"})}'
            f'</wsa:ReferenceParameters></p:ManagedElement></p:RequestPowerStateChange_INPUT>')
    return envelope(f"{service}/RequestPowerStateChange", service, body,
                    {"CreationClassName": "CIM_PowerManagementService", "Name": "Intel(r) AMT Power Management Service",
                     "SystemCreationClassName": "CIM_ComputerSystem", "SystemName": "Intel(r) AMT"})


def check_requests() -> list[dict]:
    """What a status check asks for: version, power state and AMT's own network settings."""
    return [{"name": "identify", "body": identify()},
            {"name": "power", "body": enumerate_items(CIM + "CIM_AssociatedPowerManagementService")},
            {"name": "general", "body": get(AMT + "AMT_GeneralSettings")}]


# --------------------------------------------------------------------------- parsing


def _fields(xml_text: str) -> dict[str, str]:
    """Leaf elements of the SOAP body by local name (first occurrence wins). AMT responses are small and flat."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise AmtError(f"AMT returned something that is not WS-Management XML: {exc}") from exc
    body = next((el for el in root.iter() if el.tag.endswith("}Body")), root)
    out: dict[str, str] = {}
    for el in body.iter():
        name = el.tag.rsplit("}", 1)[-1]
        if len(el) == 0 and name not in out:
            out[name] = (el.text or "").strip()
    return out


def parse_responses(endpoint: AmtEndpoint, responses: list[dict]) -> dict:
    """Fold check or power-action responses into the endpoint. Returns a summary for the caller."""
    summary: dict = {}
    for item in responses:
        status, name = int(item.get("status") or 0), item.get("name")
        if status == 401:
            endpoint.status, endpoint.last_error = "auth_failed", "AMT rejected the user name or password"
            return {"error": endpoint.last_error}
        if status == 0 or item.get("error"):
            endpoint.status, endpoint.last_error = "unreachable", str(item.get("error") or "no response")[:500]
            return {"error": endpoint.last_error}
        if status >= 400:
            fields = _fields(item.get("body") or "<x/>") if (item.get("body") or "").lstrip().startswith("<") else {}
            summary.setdefault("errors", []).append({"request": name, "status": status, "detail": fields.get("Text") or fields.get("Reason") or ""})
            continue
        fields = _fields(item.get("body") or "")
        if name == "identify":
            endpoint.amt_version = (fields.get("ProductVersion") or "")[:60]
            summary["version"] = endpoint.amt_version
        elif name == "power":
            code = int(fields["PowerState"]) if fields.get("PowerState", "").isdigit() else 0
            endpoint.power_state = POWER_STATES.get(code, f"unknown ({code})" if code else "unknown")
            summary["powerState"] = endpoint.power_state
        elif name == "general":
            endpoint.settings = {**(endpoint.settings or {}), "hostName": fields.get("HostName", ""),
                                 "domainName": fields.get("DomainName", ""), "networkEnabled": fields.get("NetworkInterfaceEnabled", "")}
        elif name.startswith("power:"):
            code = int(fields["ReturnValue"]) if fields.get("ReturnValue", "").isdigit() else -1
            summary["action"] = name.split(":", 1)[1]
            summary["result"] = RETURN_VALUES.get(code, f"returned {code}")
            if code not in (0, 4096):
                summary.setdefault("errors", []).append({"request": name, "detail": summary["result"]})
    endpoint.status = "online"
    endpoint.last_error = "; ".join(f"{e['request']}: {e.get('detail') or e.get('status')}" for e in summary.get("errors", []))[:500]
    endpoint.last_checked_at = utcnow()
    return summary


# --------------------------------------------------------------------------- credentials and transport


def set_password(endpoint: AmtEndpoint, password: str) -> None:
    endpoint.secret_envelope = crypto.encrypt(password, f"amt:{endpoint.tenant_id}:{endpoint.id}")


def password(endpoint: AmtEndpoint) -> str:
    if not endpoint.secret_envelope:
        raise AmtError("No AMT password is stored for this endpoint")
    return crypto.decrypt(endpoint.secret_envelope, f"amt:{endpoint.tenant_id}:{endpoint.id}")


def url(endpoint: AmtEndpoint) -> str:
    scheme = "https" if endpoint.port == 16993 else "http"
    host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    return f"{scheme}://{host}:{endpoint.port}/wsman"


def http_client(endpoint: AmtEndpoint) -> httpx.Client:
    return httpx.Client(timeout=20, verify=not endpoint.tls_insecure)


def send_direct(endpoint: AmtEndpoint, requests: list[dict]) -> list[dict]:
    auth = httpx.DigestAuth(endpoint.username, password(endpoint))
    out = []
    with http_client(endpoint) as client:
        for item in requests:
            try:
                response = client.post(url(endpoint), content=item["body"].encode(), auth=auth,
                                       headers={"Content-Type": "application/soap+xml;charset=UTF-8"})
                out.append({"name": item["name"], "status": response.status_code, "body": response.text[:262144]})
            except httpx.HTTPError as exc:
                out.append({"name": item["name"], "status": 0, "error": str(exc)[:300]})
                break
    return out


def run(db: Session, endpoint: AmtEndpoint, requests: list[dict], actor: str) -> dict:
    """Send the requests by the endpoint's route. Direct: the result now. Agent: the queued command."""
    if endpoint.route == "direct":
        summary = parse_responses(endpoint, send_direct(endpoint, requests))
        return {"route": "direct", **summary}
    probe = db.get(Device, endpoint.probe_device_id) if endpoint.probe_device_id else None
    if probe is None or probe.tenant_id != endpoint.tenant_id:
        raise AmtError("Choose a device on the same network to reach this AMT endpoint through")
    command = services.enqueue_command(db, probe, "amt.wsman", actor, payload={"amtEndpointId": endpoint.id, "requests": requests},
                                       reason=f"Intel AMT: {', '.join(r['name'] for r in requests)} on {endpoint.name or endpoint.host}")
    endpoint.status = "pending" if endpoint.status in ("unknown", "pending") else endpoint.status
    return {"route": "agent", "commandId": command.id, "queued": True}


def credential_for_command(db: Session, device: Device, command: Command) -> dict:
    """Connection details for one pending amt.wsman command, released once to the device it was sent to."""
    payload = command.payload or {}
    if (command.device_id != device.id or command.type != "amt.wsman" or command.status not in ("pending", "dispatched")
            or payload.get("credentialReleased") or utcnow() - command.created_at > CREDENTIAL_WINDOW):
        raise AmtError("No AMT credential is available for this command")
    endpoint = db.get(AmtEndpoint, payload.get("amtEndpointId") or "")
    if endpoint is None or endpoint.tenant_id != device.tenant_id or endpoint.probe_device_id != device.id or endpoint.port not in PORTS:
        raise AmtError("No AMT credential is available for this command")
    command.payload = {**payload, "credentialReleased": utcnow().isoformat() + "Z"}
    audit.record(db, f"device:{device.hostname}", "amt.credential.released", endpoint.name or endpoint.host, endpoint.tenant_id,
                 command=command.id, endpoint=endpoint.id)
    return {"host": endpoint.host, "port": endpoint.port, "tls": endpoint.port == 16993, "tlsInsecure": endpoint.tls_insecure,
            "username": endpoint.username, "password": password(endpoint)}


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    endpoint = db.get(AmtEndpoint, (command.payload or {}).get("amtEndpointId") or "")
    if endpoint is None or endpoint.tenant_id != device.tenant_id:
        return
    result = command.result or {}
    if command.status != "completed":
        endpoint.status, endpoint.last_error = "unreachable", str(result.get("error") or command.status)[:500]
        endpoint.last_checked_at = utcnow()
        return
    summary = parse_responses(endpoint, result.get("responses") or [])
    if summary.get("action"):
        audit.record(db, "system:amt", "amt.power.result", endpoint.name or endpoint.host, endpoint.tenant_id,
                     powerAction=summary["action"], result=summary.get("result"))


def view(endpoint: AmtEndpoint, hostnames: dict[str, str] | None = None) -> dict:
    hostnames = hostnames or {}
    return {"id": endpoint.id, "tenantId": endpoint.tenant_id, "deviceId": endpoint.device_id,
            "deviceName": hostnames.get(endpoint.device_id or "", ""), "nodeId": endpoint.node_id, "name": endpoint.name,
            "host": endpoint.host, "port": endpoint.port, "tls": endpoint.port == 16993, "tlsInsecure": endpoint.tls_insecure,
            "username": endpoint.username, "hasPassword": bool(endpoint.secret_envelope), "route": endpoint.route,
            "probeDeviceId": endpoint.probe_device_id, "probeName": hostnames.get(endpoint.probe_device_id or "", ""),
            "status": endpoint.status, "amtVersion": endpoint.amt_version, "powerState": endpoint.power_state,
            "settings": endpoint.settings or {}, "lastError": endpoint.last_error,
            "lastCheckedAt": endpoint.last_checked_at.isoformat() + "Z" if endpoint.last_checked_at else None}
