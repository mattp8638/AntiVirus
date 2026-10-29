"""Network topology discovery: subnets, gateways and every device seen on them, managed or not.

A managed device runs ``network.discover`` (Linux/macOS native, ``fleet/topology.go``; Windows the PowerShell
script below through ``script.run``). It reports its interfaces, default gateway, ARP/neighbour table and,
unless turned off, a short TCP sweep of its own private subnets for common ports.

The cloud merges reports from every device of a customer into subnets and nodes, keyed by MAC address (or IP
when no MAC is visible, e.g. across a router), links nodes to managed devices by MAC/IP, and guesses each
unmanaged node's kind from its ports and vendor. The graph view puts each subnet behind its gateway, with
managed and unmanaged nodes on it; unmanaged workstations and servers are candidates for agent deployment.

Only private IPv4 ranges are swept (the agent enforces this); the cloud never scans customer networks itself.
"""

from __future__ import annotations

import ipaddress
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, services
from .models import Command, Device, NetworkNode, NetworkSubnet, Tenant, utcnow

MARKER = "FENRIR-TOPOLOGY-RESULT:"
MAX_NEIGHBOURS = 4096

# Only prefixes we are certain of: virtualisation platforms and Raspberry Pi.
OUI_VENDORS = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware", "00:1c:14": "VMware",
    "00:15:5d": "Microsoft Hyper-V", "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM", "00:16:3e": "Xen",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
}
VIRTUAL_VENDORS = {"VMware", "Microsoft Hyper-V", "VirtualBox", "QEMU/KVM", "Xen"}

WINDOWS_SCRIPT = r"""$ErrorActionPreference = 'SilentlyContinue'
$ports = @(22,23,53,80,135,139,443,445,515,554,631,3389,5900,8080,8443,9100)
$private = { param($ip) $b = $ip.GetAddressBytes(); ($b[0] -eq 10) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) }
$interfaces = @(); $targets = New-Object System.Collections.ArrayList; $swept = @()
foreach ($cfg in Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' }) {
  $addresses = @()
  foreach ($a in $cfg.IPv4Address) {
    $addresses += "$($a.IPAddress)/$($a.PrefixLength)"
    $ip = [System.Net.IPAddress]::Parse($a.IPAddress)
    if (& $private $ip) {
      $prefix = [Math]::Max([int]$a.PrefixLength, 24); $bytes = $ip.GetAddressBytes(); $n = ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]
      $mask = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $prefix)); $base = $n -band $mask; $size = [Math]::Pow(2, 32 - $prefix)
      $swept += ('{0}.{1}.{2}.{3}/{4}' -f (($base -shr 24) -band 255), (($base -shr 16) -band 255), (($base -shr 8) -band 255), ($base -band 255), $prefix)
      for ($i = 1; $i -lt $size - 1 -and $targets.Count -lt 1024; $i++) { $h = $base + $i
        $t = '{0}.{1}.{2}.{3}' -f (($h -shr 24) -band 255), (($h -shr 16) -band 255), (($h -shr 8) -band 255), ($h -band 255)
        if ($t -ne $a.IPAddress) { [void]$targets.Add($t) } } } }
  $interfaces += [ordered]@{ name = $cfg.InterfaceAlias; mac = ($cfg.NetAdapter.MacAddress -replace '-', ':').ToLower(); addresses = $addresses }
  if ($cfg.IPv4DefaultGateway -and -not $gateway) { $gateway = $cfg.IPv4DefaultGateway.NextHop } }
$open = @{}
for ($start = 0; $start -lt $targets.Count; $start += 32) {
  $batch = @()
  foreach ($t in $targets[$start..([Math]::Min($start + 31, $targets.Count - 1))]) { foreach ($p in $ports) {
    $c = New-Object System.Net.Sockets.TcpClient; $batch += [pscustomobject]@{ ip = $t; port = $p; client = $c; task = $c.ConnectAsync($t, $p) } } }
  Start-Sleep -Milliseconds 400
  foreach ($b in $batch) { if ($b.task.IsCompleted -and -not $b.task.IsFaulted -and $b.client.Connected) { if (-not $open[$b.ip]) { $open[$b.ip] = @() }; $open[$b.ip] += $b.port }; $b.client.Dispose() } }
$neighbors = @{}
foreach ($n in Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -in 'Reachable','Stale','Delay','Probe','Permanent' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' }) {
  $neighbors[$n.IPAddress] = [ordered]@{ ip = $n.IPAddress; mac = ($n.LinkLayerAddress -replace '-', ':').ToLower(); source = 'arp' } }
foreach ($ip in $open.Keys) { if (-not $neighbors[$ip]) { $neighbors[$ip] = [ordered]@{ ip = $ip; source = 'sweep' } }; $neighbors[$ip].openPorts = @($open[$ip] | Sort-Object) }
foreach ($ip in @($neighbors.Keys)) { try { $neighbors[$ip].hostname = [System.Net.Dns]::GetHostEntry($ip).HostName } catch { } }
$result = [ordered]@{ interfaces = $interfaces; gateway = $gateway; neighbors = @($neighbors.Values); swept = $swept; truncated = ($targets.Count -ge 1024) }
'FENRIR-TOPOLOGY-RESULT:' + ($result | ConvertTo-Json -Compress -Depth 6)
"""


def request_discovery(db: Session, device: Device, actor: str, sweep: bool = True) -> Command:
    if device.platform in {"linux", "macos"}:
        return services.enqueue_command(db, device, "network.discover", actor, payload={"sweep": sweep, "topologyScan": True},
                                        reason="Network topology discovery")
    if device.platform == "windows":
        body = WINDOWS_SCRIPT if sweep else WINDOWS_SCRIPT.replace("$targets.Count -lt 1024", "$false")
        return services.enqueue_command(db, device, "script.run", actor,
                                        payload={"language": "powershell", "body": body, "timeoutSeconds": 600,
                                                 "scriptName": "Network discovery", "topologyScan": True},
                                        reason="Network topology discovery")
    raise services.CommandError(f"Network discovery is not available on {device.platform}")


def _parse(command: Command) -> dict | None:
    result = command.result or {}
    if isinstance(result.get("topology"), dict):
        return result["topology"]
    for line in reversed(str(result.get("stdout") or "").splitlines()):
        if line.startswith(MARKER):
            try:
                parsed = json.loads(line[len(MARKER):])
            except json.JSONDecodeError:
                return None
            return parsed if isinstance(parsed, dict) else None
    return None


def _mac(value) -> str:
    mac = str(value or "").strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) != 6 or not all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
        return ""
    return "" if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else mac


def vendor(mac: str) -> str:
    if not mac:
        return ""
    if mac.startswith("02:42:"):
        return "Docker"
    known = OUI_VENDORS.get(mac[:8])
    if known:
        return known
    if int(mac[1], 16) & 0x2:
        return "Randomised (private) address"
    return ""


def classify(ip: str, ports: list[int], vendor_name: str, gateway_ips: set[str], hostname: str = "") -> str:
    ports_set = set(ports)
    name = hostname.lower()
    if ip in gateway_ips:
        return "gateway"
    if ports_set & {9100, 515, 631}:
        return "printer"
    if vendor_name in VIRTUAL_VENDORS:
        return "virtual"
    if 554 in ports_set:
        return "camera"
    if 3389 in ports_set or {135, 445} <= ports_set:
        return "server" if any(tag in name for tag in ("srv", "server", "dc", "sql", "fs", "hv")) else "workstation"
    if 23 in ports_set or (ports_set & {80, 443} and 22 in ports_set and not ports_set & {135, 445}):
        return "network"
    if vendor_name == "Raspberry Pi":
        return "iot"
    return "unknown"


def _private(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.version == 4 and (address.is_private or address in ipaddress.ip_network("100.64.0.0/10"))


def _subnet_for(ip: str, subnets: list[ipaddress.IPv4Network]) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for net in subnets:
        if address in net:
            return str(net)
    return ""


def ingest(db: Session, device: Device, data: dict) -> dict:
    now = utcnow()
    gateway = str(data.get("gateway") or "")
    subnets: list[ipaddress.IPv4Network] = []
    own_macs, own_ips = set(), set()
    for iface in data.get("interfaces") or []:
        if not isinstance(iface, dict):
            continue
        if _mac(iface.get("mac")):
            own_macs.add(_mac(iface.get("mac")))
        for cidr in iface.get("addresses") or []:
            try:
                interface = ipaddress.ip_interface(str(cidr))
            except ValueError:
                continue
            if interface.version != 4 or not _private(str(interface.ip)):
                continue
            own_ips.add(str(interface.ip))
            network = interface.network
            subnets.append(network)
            row = db.execute(select(NetworkSubnet).where(NetworkSubnet.tenant_id == device.tenant_id,
                                                         NetworkSubnet.cidr == str(network))).scalar_one_or_none()
            if row is None:
                row = NetworkSubnet(tenant_id=device.tenant_id, cidr=str(network))
                db.add(row)
            row.last_seen = now
            row.seen_by = sorted(set(row.seen_by or []) | {device.id})
            if gateway and _subnet_for(gateway, [network]):
                row.gateway_ip = gateway
    managed = db.execute(select(Device).where(Device.tenant_id == device.tenant_id)).scalars().all()
    by_mac, by_ip = {}, {}
    for d in managed:
        inventory = d.inventory or {}
        for mac in inventory.get("macAddresses") or []:
            if _mac(mac):
                by_mac[_mac(mac)] = d
        for ip in inventory.get("ipAddresses") or []:
            by_ip[str(ip).split("/")[0]] = d
    for mac in own_macs:
        by_mac[mac] = device
    for ip in own_ips:
        by_ip[ip] = device
    gateways = {gateway} if gateway else set()
    seen = 0
    neighbours = [n for n in (data.get("neighbors") or []) if isinstance(n, dict)][:MAX_NEIGHBOURS]
    # The reporting device is itself on these subnets.
    for ip in own_ips:
        neighbours.append({"ip": ip, "mac": next(iter(own_macs), ""), "hostname": device.hostname, "source": "self"})
    for item in neighbours:
        ip = str(item.get("ip") or "")
        if not _private(ip):
            continue
        mac = _mac(item.get("mac"))
        key = f"mac:{mac}" if mac else f"ip:{ip}"
        node = db.execute(select(NetworkNode).where(NetworkNode.tenant_id == device.tenant_id, NetworkNode.key == key)).scalar_one_or_none()
        if node is None and mac:  # first seen by IP only, now with its MAC
            node = db.execute(select(NetworkNode).where(NetworkNode.tenant_id == device.tenant_id, NetworkNode.key == f"ip:{ip}")).scalar_one_or_none()
            if node is not None:
                node.key = key
        if node is None:
            node = NetworkNode(tenant_id=device.tenant_id, key=key)
            db.add(node)
        ports = sorted({int(p) for p in item.get("openPorts") or [] if isinstance(p, int) and 0 < p < 65536})
        node.ip, node.mac = ip, mac or node.mac
        node.hostname = str(item.get("hostname") or node.hostname or "")[:255]
        node.vendor = vendor(node.mac)
        if ports or item.get("source") == "sweep":
            node.open_ports = ports
        node.subnet = _subnet_for(ip, subnets) or node.subnet
        linked = by_mac.get(node.mac) if node.mac else None
        linked = linked or by_ip.get(ip)
        node.device_id = linked.id if linked else None
        if linked is not None:
            node.kind = "server" if "server" in (linked.os_version or "").lower() else "workstation"
            node.hostname = node.hostname or linked.hostname
        else:
            node.kind = classify(ip, node.open_ports or [], node.vendor, gateways, node.hostname)
        node.last_seen = now
        node.seen_by = sorted(set(node.seen_by or []) | {device.id})
        seen += 1
    db.flush()
    return {"subnets": len(subnets), "nodes": seen}


def on_command_complete(db: Session, device: Device, command: Command) -> None:
    if command.status != "completed":
        return
    data = _parse(command)
    if data is None:
        return
    summary = ingest(db, device, data)
    audit.record(db, "system", "topology.discovered", device.hostname, device.tenant_id, **summary)


def graph(db: Session, tenant_id: str) -> dict:
    """Subnets behind their gateways, with managed and unmanaged nodes, for the console map."""
    subnets = db.execute(select(NetworkSubnet).where(NetworkSubnet.tenant_id == tenant_id).order_by(NetworkSubnet.cidr)).scalars().all()
    nodes = db.execute(select(NetworkNode).where(NetworkNode.tenant_id == tenant_id).order_by(NetworkNode.ip)).scalars().all()
    hostnames = dict(db.execute(select(Device.id, Device.hostname).where(Device.tenant_id == tenant_id)).all())
    out_nodes = [{"id": f"subnet:{s.cidr}", "type": "subnet", "label": s.cidr, "gateway": s.gateway_ip,
                  "lastSeen": s.last_seen.isoformat() + "Z"} for s in subnets]
    edges = []
    for n in nodes:
        out_nodes.append({"id": n.id, "type": "node", "label": n.hostname or hostnames.get(n.device_id or "", "") or n.ip, "ip": n.ip,
                          "mac": n.mac, "vendor": n.vendor, "kind": n.kind, "openPorts": n.open_ports or [], "subnet": n.subnet,
                          "managed": n.device_id is not None, "deviceId": n.device_id, "ignored": n.ignored,
                          "lastSeen": n.last_seen.isoformat() + "Z"})
        if n.subnet:
            edges.append({"from": f"subnet:{n.subnet}", "to": n.id, "kind": "member"})
    # Gateways connect their subnets; a node on several subnets (a router or multi-homed server) links them.
    by_ip = {n.ip: n for n in nodes}
    for s in subnets:
        gw = by_ip.get(s.gateway_ip)
        if gw is not None:
            edges.append({"from": gw.id, "to": f"subnet:{s.cidr}", "kind": "gateway"})
    unmanaged = [n for n in out_nodes if n["type"] == "node" and not n["managed"] and not n["ignored"]]
    return {"nodes": out_nodes, "edges": edges,
            "summary": {"subnets": len(subnets), "nodes": len(nodes), "managed": sum(1 for n in nodes if n.device_id),
                        "unmanaged": len(unmanaged),
                        "deployable": sum(1 for n in unmanaged if n["kind"] in ("workstation", "server"))}}


def tick(db: Session) -> int:
    """Re-run discovery from each customer's chosen probe devices on their schedule (default daily)."""
    from datetime import timedelta

    queued = 0
    for tenant in db.execute(select(Tenant)).scalars():
        config = (tenant.settings or {}).get("topology") or {}
        probes = config.get("probeDeviceIds") or []
        if not probes:
            continue
        every = timedelta(hours=max(1, int(config.get("intervalHours") or 24)))
        for device_id in probes:
            device = db.get(Device, device_id)
            if device is None or device.tenant_id != tenant.id:
                continue
            last = db.execute(select(Command.created_at).where(Command.device_id == device.id, Command.reason == "Network topology discovery")
                              .order_by(Command.created_at.desc()).limit(1)).scalar_one_or_none()
            if last and utcnow() - last < every:
                continue
            try:
                request_discovery(db, device, "system:topology", sweep=bool(config.get("sweep", True)))
                queued += 1
            except services.CommandError:
                continue
    return queued
