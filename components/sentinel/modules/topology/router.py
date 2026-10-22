import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()

TOPOLOGY_DIR = Path("data") / "topology"
TOPOLOGY_DIR.mkdir(parents=True, exist_ok=True)

COMMON_PORTS = [22, 23, 53, 80, 135, 139, 161, 443, 445, 631, 3389, 5900, 8080, 8443]
OUI = {
    "00:00:0c": "Cisco",
    "c4:71:54": "Cisco Meraki",
    "00:24:8c": "Aruba",
    "2c:56:dc": "Ubiquiti",
    "00:0c:42": "MikroTik",
    "00:1a:1e": "Fortinet",
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:15:5d": "Microsoft Hyper-V",
    "52:54:00": "QEMU/KVM",
    "08:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi",
    "00:11:32": "Synology",
    "b0:be:76": "Apple",
}
ROLE_WORDS = {
    "router": ["router", "gateway", "firewall", "fortigate", "pfsense", "opnsense", "sonicwall", "mikrotik", "edge"],
    "switch": ["switch", "catalyst", "nexus", "procurve", "aruba", "unifi switch", "cbs", "poe"],
    "access_point": ["access point", "wireless", "wifi", "unifi ap", "uap", "aironet", "wap"],
    "server": ["server", "ubuntu", "debian", "vmware", "esxi", "synology", "nas", "proxmox", "hyper-v"],
    "printer": ["printer", "jetdirect", "laserjet", "mfp", "ipp"],
    "camera": ["camera", "hikvision", "dahua", "axis", "nvr", "cctv"],
}

class TopologyScanRequest(BaseModel):
    subnets: List[str] = Field(default_factory=list)
    scan_ports: bool = True
    max_workers: int = 96
    default_gateway: Optional[str] = None
    snmp_communities: List[str] = Field(default_factory=list)

@dataclass
class Evidence:
    source: str
    detail: str
    confidence: int

@dataclass
class Device:
    id: str
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = "Unknown"
    role: str = "endpoint"
    confidence: int = 30
    status: str = "online"
    open_ports: List[int] = field(default_factory=list)
    services: Dict[str, str] = field(default_factory=dict)
    subnet: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    last_seen: str = ""

@dataclass
class Link:
    source: str
    target: str
    type: str = "inferred"
    confidence: int = 40
    evidence: List[str] = field(default_factory=list)


def ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sh(command: List[str], timeout: int = 5) -> str:
    try:
        kwargs = {"capture_output": True, "text": True, "timeout": timeout}
        if platform.system().lower().startswith("win"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(command, **kwargs)
        return (result.stdout or "") + (result.stderr or "")
    except Exception:
        return ""


def mac_norm(value: str) -> str:
    value = (value or "").strip().lower().replace("-", ":").replace(".", "")
    if ":" not in value and len(value) == 12:
        value = ":".join(value[index:index + 2] for index in range(0, 12, 2))
    return value if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", value) else ""


def vendor(mac: str) -> str:
    normalised = mac_norm(mac)
    return OUI.get(":".join(normalised.split(":")[:3]), "Unknown") if normalised else "Unknown"


def default_subnet() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except Exception:
        return "192.168.1.0/24"


def gateway() -> str:
    if platform.system().lower().startswith("win"):
        for line in sh(["route", "print", "0.0.0.0"]).splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", sh(["ip", "route", "show", "default"]))
    return match.group(1) if match else ""


def arp_table() -> Dict[str, str]:
    output = {}
    arp_proc = Path("/proc/net/arp")
    if arp_proc.exists():
        for line in arp_proc.read_text(errors="ignore").splitlines()[1:]:
            parts = line.split()
            mac = mac_norm(parts[3]) if len(parts) >= 4 else ""
            if mac and mac != "00:00:00:00:00:00":
                output[parts[0]] = mac
    for line in sh(["arp", "-a"]).splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
        if ip and mac:
            output[ip.group(1)] = mac_norm(mac.group(0))
    return output


def ping(ip: str) -> bool:
    command = ["ping", "-n", "1", "-w", "700", ip] if platform.system().lower().startswith("win") else ["ping", "-c", "1", "-W", "1", ip]
    return "ttl=" in sh(command, 3).lower()


def touch(ip: str):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.05)
        sock.sendto(b"0", (ip, 9))
        sock.close()
    except Exception:
        pass


def port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=0.35):
            return True
    except Exception:
        return False


def rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def banner(ip: str, port: int) -> str:
    try:
        with socket.create_connection((ip, port), timeout=0.8) as sock:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            data = sock.recv(500).decode("latin-1", "ignore")
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def classify(name: str, vend: str, ports: List[int], banners: Dict[str, str], is_gateway: bool = False):
    if is_gateway:
        return "router", 90, [Evidence("gateway", "Default gateway match", 90)]
    text = " ".join([name, vend, " ".join(banners.values())]).lower()
    scores = {key: 0 for key in ["router", "switch", "access_point", "server", "printer", "camera", "endpoint"]}
    evidence = []
    for role, words in ROLE_WORDS.items():
        for word in words:
            if word in text:
                scores[role] += 20
                evidence.append(Evidence("classification", f"Matched {word}", 65))
    if 161 in ports:
        scores["switch"] += 15
        scores["router"] += 10
        evidence.append(Evidence("tcp", "SNMP open", 55))
    if 445 in ports or 3389 in ports:
        scores["server"] += 12
        scores["endpoint"] += 8
    if 631 in ports:
        scores["printer"] += 20
    if vend in ["VMware", "Microsoft Hyper-V", "QEMU/KVM", "VirtualBox"]:
        scores["server"] += 18
    if vend in ["Cisco", "Cisco Meraki", "Aruba", "Ubiquiti", "MikroTik"]:
        scores["switch"] += 10
        scores["router"] += 8
        scores["access_point"] += 6
    role = max(scores, key=scores.get)
    score = scores[role]
    return ("endpoint", 45 if ports else 35, evidence) if score < 12 else (role, min(95, score + 35), evidence)


def scan_topology(request: TopologyScanRequest) -> Dict:
    subnets = [str(ipaddress.ip_network(value, strict=False)) for value in (request.subnets or [default_subnet()])]
    gateway_ip = request.default_gateway or gateway()
    workers = max(1, min(int(request.max_workers), 256))
    ips = []
    for subnet in subnets:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.num_addresses > 4096:
            raise HTTPException(status_code=400, detail=f"{subnet} is too large for active discovery; use /20 or smaller")
        ips.extend([str(ip) for ip in network.hosts()])

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(touch, ips))

    raw = {
        ip: {"ip": ip, "mac": mac, "source": ["arp"], "open_ports": []}
        for ip, mac in arp_table().items()
        if any(ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False) for subnet in subnets)
    }

    def probe(ip: str):
        open_ports = [port for port in COMMON_PORTS if request.scan_ports and port_open(ip, port)]
        return ip, ping(ip), open_ports

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for ip, alive, open_ports in executor.map(probe, ips):
            if alive or open_ports:
                raw.setdefault(ip, {"ip": ip, "mac": "", "source": [], "open_ports": []})
                raw[ip]["source"].append("active_probe")
                raw[ip]["open_ports"] = sorted(set(raw[ip]["open_ports"] + open_ports))

    devices = {}
    for ip, item in sorted(raw.items(), key=lambda row: tuple(map(int, row[0].split(".")))):
        mac = mac_norm(item.get("mac", ""))
        vend = vendor(mac)
        name = rdns(ip)
        open_ports = item.get("open_ports", [])
        banners = {str(port): banner(ip, port) for port in [80, 443, 8080, 8443] if port in open_ports}
        banners = {key: value for key, value in banners.items() if value}
        role, confidence, evidence = classify(name, vend, open_ports, banners, ip == gateway_ip)
        subnet = next((subnet for subnet in subnets if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)), "")
        device = Device(
            id=f"dev-{uuid.uuid5(uuid.NAMESPACE_DNS, ip)}",
            ip=ip,
            hostname=name,
            mac=mac,
            vendor=vend,
            role=role,
            confidence=confidence,
            status="online",
            open_ports=open_ports,
            services=banners,
            subnet=subnet,
            last_seen=ts(),
            evidence=[Evidence("discovery", ",".join(sorted(set(item.get("source", [])))), 60)] + evidence,
        )
        if mac:
            device.evidence.append(Evidence("arp", f"{ip} resolves to {mac}", 75))
        devices[ip] = device

    links = []
    root = devices.get(gateway_ip) or (list(devices.values())[0] if devices else None)
    if root:
        if root.ip == gateway_ip:
            root.role = "router"
        for device in devices.values():
            if device.id != root.id:
                links.append(Link(root.id, device.id, type="gateway_inferred" if root.ip == gateway_ip else "subnet_inferred", confidence=70 if device.role in ["switch", "access_point"] else 45, evidence=["Gateway/subnet relationship"]))

    findings = []
    for device in devices.values():
        if device.role == "endpoint" and 161 in device.open_ports:
            findings.append({"severity": "medium", "title": "Endpoint exposes SNMP", "device": device.hostname, "detail": "SNMP on endpoints can disclose topology data."})
        if device.role in ["router", "switch", "access_point"] and device.confidence < 65:
            findings.append({"severity": "low", "title": "Infrastructure role inferred with limited evidence", "device": device.hostname, "detail": "Enable SNMP/LLDP for stronger confidence."})
        if not device.mac:
            findings.append({"severity": "low", "title": "Online device without MAC evidence", "device": device.hostname, "detail": "L3 response seen, but no local ARP evidence."})

    summary = {
        "devices": len(devices),
        "links": len(links),
        "routers": sum(device.role == "router" for device in devices.values()),
        "switches": sum(device.role == "switch" for device in devices.values()),
        "access_points": sum(device.role == "access_point" for device in devices.values()),
        "endpoints": sum(device.role == "endpoint" for device in devices.values()),
    }
    result = {
        "scan_id": str(uuid.uuid4()),
        "generated_at": ts(),
        "scope": subnets,
        "summary": summary,
        "devices": [asdict(device) for device in devices.values()],
        "links": [asdict(link) for link in links],
        "findings": findings,
    }
    output_path = TOPOLOGY_DIR / f"topology-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}.json"
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["stored_result"] = str(output_path)
    return result


@router.get("/interfaces")
def interfaces():
    return {"default_subnet": default_subnet(), "default_gateway": gateway(), "platform": platform.platform()}


@router.post("/scan")
def scan(request: TopologyScanRequest):
    return scan_topology(request)
