"""Attack-path analysis (VULN-19): how an attacker could get from the internet to what matters most, from the
evidence Fenrir holds.

Nodes: the internet, the customer's exposed services (external scans), their devices, and their Microsoft 365
tenant. Edges, each marked observed (seen in data: an open port found by a scan, a known-exploited vulnerability on a
device, an administrator without MFA) or inferred (a relationship we deduce: an exposed address that is a device's
address, two devices on the same site or subnet):

* internet -> exposed service: the scan found it open (observed);
* exposed service -> device: the service's address or name is the device's (inferred);
* device is a foothold when it has open, known-exploited or critical vulnerabilities (observed);
* device -> device: same site or /24 subnet, towards a server, a domain controller or a critical device (inferred);
* internet -> Microsoft 365 tenant: an administrator without MFA (observed).

Paths lead from the internet to critical targets (devices of high or critical business criticality, domain
controllers and servers, and the Microsoft 365 tenant). This is analysis, not an executed test: every path lists its
edges with their evidence and kind, and running it again after remediation shows which paths are resolved.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Device, ExternalAsset, M365Connection, Vulnerability

CRITICAL_SERVICES = {3389, 445, 22, 23, 1433, 3306, 5432, 27017, 9200, 6379, 5900, 11211}
MAX_DEPTH = 5


def _subnet(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4 or not a.is_private:
        return None
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def _is_critical(d: Device) -> bool:
    tags = {str(t).lower() for t in d.tags or []}
    os = (d.os_version or "").lower()
    return (d.criticality or "") in ("high", "critical") or "domain-controller" in tags or "server" in tags or "server" in os


def analyse(db: Session, tenant_id: str) -> dict:
    devices = db.execute(select(Device).where(Device.tenant_id == tenant_id, Device.approved.is_(True))).scalars().all()
    assets = db.execute(select(ExternalAsset).where(ExternalAsset.tenant_id == tenant_id)).scalars().all()
    vulns = db.execute(select(Vulnerability).where(Vulnerability.tenant_id == tenant_id,
                                                   Vulnerability.status.in_(("open", "patching")))).scalars().all()
    by_dev: dict[str, list[Vulnerability]] = defaultdict(list)
    for v in vulns:
        by_dev[v.device_id].append(v)
    nodes: dict[str, dict] = {"internet": {"label": "Internet", "kind": "internet"}}
    edges: dict[str, list[dict]] = defaultdict(list)

    def edge(a: str, b: str, kind: str, why: str, weight: float) -> None:
        edges[a].append({"to": b, "kind": kind, "evidence": why, "weight": weight})

    for d in devices:
        kev = [v for v in by_dev[d.id] if v.known_exploited]
        crit = [v for v in by_dev[d.id] if v.severity == "critical"]
        nodes[f"device:{d.id}"] = {"label": d.hostname, "kind": "device", "critical": _is_critical(d),
                                   "foothold": bool(kev or crit),
                                   "weakness": [f"{v.vuln_id} in {v.package}{' (known exploited)' if v.known_exploited else ''}"
                                                for v in (kev + [c for c in crit if c not in kev])][:5]}
    # Internet -> exposed services -> devices.
    for a in assets:
        open_ports = [p.get("port") for p in (a.last_result or {}).get("openPorts") or []]
        if not open_ports:
            continue
        risky = [p for p in open_ports if p in CRITICAL_SERVICES]
        nid = f"asset:{a.id}"
        nodes[nid] = {"label": f"{a.target} ({', '.join(str(p) for p in open_ports[:6])})", "kind": "exposure"}
        edge("internet", nid, "observed", f"scan {str(a.last_scan_at)[:16]} found port(s) {', '.join(map(str, open_ports[:8]))} open",
             0.9 if risky else 0.5)
        address = (a.last_result or {}).get("address") or ""
        for d in devices:
            public = str((d.metrics or {}).get("publicIp") or "") if hasattr(d, "metrics") else ""
            if a.target in (d.hostname.lower(), (d.ip_address or "").lower()) or (address and address in (d.ip_address, public)):
                edge(nid, f"device:{d.id}", "inferred", f"{a.target} is {d.hostname}'s address or name", 0.8)
    # Lateral movement inside a site or subnet, towards critical devices.
    for src in devices:
        for dst in devices:
            if src.id == dst.id or not _is_critical(dst):
                continue
            same_site = src.site_id and src.site_id == dst.site_id
            same_net = _subnet(src.ip_address or "") and _subnet(src.ip_address or "") == _subnet(dst.ip_address or "")
            if same_site or same_net:
                edge(f"device:{src.id}", f"device:{dst.id}", "inferred",
                     f"{src.hostname} and {dst.hostname} share {'a site' if same_site else 'subnet ' + str(_subnet(src.ip_address))}", 0.6)
    # Identities: Microsoft 365 administrators without MFA.
    for c in db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant_id)).scalars():
        weak = (((c.snapshot or {}).get("insights") or {}).get("mfa") or {}).get("adminsWithoutMfa") or []
        if weak:
            nid = f"m365:{c.id}"
            nodes[nid] = {"label": f"Microsoft 365 {c.tenant_name or c.name}", "kind": "cloud", "critical": True}
            edge("internet", nid, "observed", f"administrator(s) without MFA: {', '.join(weak[:5])}", 0.8)

    # Paths from the internet to critical targets, through a foothold when they pass through devices.
    paths = []

    def walk(node: str, trail: list[str], steps: list[dict], score: float) -> None:
        if len(trail) > MAX_DEPTH:
            return
        n = nodes.get(node, {})
        if node != "internet" and n.get("critical") and len(trail) > 1:
            devices_on = [t for t in trail if t.startswith("device:")]
            if not devices_on or nodes[devices_on[0]].get("foothold"):
                paths.append({"nodes": trail, "steps": steps, "score": round(score, 3)})
        for e in edges.get(node, []):
            if e["to"] in trail:
                continue
            walk(e["to"], trail + [e["to"]], steps + [{"from": node, **e}], score * e["weight"])

    walk("internet", ["internet"], [], 1.0)
    out = []
    for p in sorted(paths, key=lambda p: -p["score"])[:200]:
        fp = hashlib.sha256("|".join(p["nodes"]).encode()).hexdigest()[:16]
        target = nodes[p["nodes"][-1]]
        foothold = next((nodes[t] for t in p["nodes"] if t.startswith("device:") and nodes[t].get("foothold")), None)
        out.append({"id": fp, "target": target["label"], "score": p["score"],
                    "observed": sum(1 for s in p["steps"] if s["kind"] == "observed"),
                    "inferred": sum(1 for s in p["steps"] if s["kind"] == "inferred"),
                    "foothold": foothold["weakness"] if foothold else [],
                    "hops": [nodes[n]["label"] for n in p["nodes"]],
                    "steps": [{"from": nodes[s["from"]]["label"], "to": nodes[s["to"]]["label"], "kind": s["kind"],
                               "evidence": s["evidence"]} for s in p["steps"]]})
    return {"paths": out, "inputs": {"devices": len(devices), "exposures": sum(1 for n in nodes.values() if n["kind"] == "exposure"),
                                     "openVulnerabilities": len(vulns), "footholds": sum(1 for n in nodes.values() if n.get("foothold")),
                                     "criticalTargets": sum(1 for n in nodes.values() if n.get("critical"))},
            "method": "Analysis of Fenrir's records; no exploitation was attempted. Inferred edges are relationships deduced from addresses, names and sites."}
