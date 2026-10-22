"""Exposure management: software inventory, vulnerabilities, external attack surface.

Vulnerability data comes from public, free sources:

* OSV.dev (https://osv.dev) for distro and language packages
* CISA Known Exploited Vulnerabilities catalogue for "actively exploited" flags
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import Device, ExternalAsset, SoftwareItem, Vulnerability, utcnow

log = logging.getLogger("fenrir.exposure")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def ecosystem_for(device: Device) -> str:
    text = f"{device.os_version}".lower()
    for name, eco in (("ubuntu", "Ubuntu"), ("debian", "Debian"), ("alpine", "Alpine"), ("rocky", "Rocky Linux"),
                      ("almalinux", "AlmaLinux"), ("red hat", "Red Hat"), ("suse", "SUSE")):
        if name in text:
            match = re.search(r"(\d+(?:\.\d+)?)", text)
            return f"{eco}:{match.group(1)}" if match else eco
    return device.platform


def record_inventory(db: Session, device: Device, fields: dict) -> int:
    software = fields.get("software") or fields.get("packages") or fields.get("installedSoftware") or []
    summary = {key: fields[key] for key in ("osName", "osVersion", "cpu", "memoryMb", "diskFreeGb", "ipAddresses", "macAddresses",
                                            "domain", "lastBoot", "manufacturer", "model", "bitlocker", "firewall", "secureBoot",
                                            "tpm", "localAdmins") if key in fields}
    if summary:
        device.inventory = {**(device.inventory or {}), **summary, "updatedAt": utcnow().isoformat()}
    if not isinstance(software, list):
        return 0
    db.execute(delete(SoftwareItem).where(SoftwareItem.device_id == device.id))
    ecosystem = ecosystem_for(device)
    count = 0
    for item in software[:5000]:
        if isinstance(item, str):
            name, version, vendor = item, "", ""
        elif isinstance(item, dict):
            name = str(item.get("name") or item.get("displayName") or "")
            version = str(item.get("version") or item.get("displayVersion") or "")
            vendor = str(item.get("vendor") or item.get("publisher") or "")
        else:
            continue
        if not name:
            continue
        db.add(SoftwareItem(tenant_id=device.tenant_id, device_id=device.id, name=name[:300], version=version[:100],
                            vendor=vendor[:200], ecosystem=ecosystem))
        count += 1
    return count


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


_KEV_CACHE: tuple[float, set[str]] = (0.0, set())


def known_exploited(client: httpx.Client) -> set[str]:
    global _KEV_CACHE
    fetched_at, cves = _KEV_CACHE
    if cves and time.time() - fetched_at < 6 * 3600:
        return cves
    try:
        data = client.get(KEV_URL, timeout=20).json()
        cves = {item["cveID"] for item in data.get("vulnerabilities", []) if item.get("cveID")}
        _KEV_CACHE = (time.time(), cves)
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        log.warning("KEV catalogue unavailable: %s", exc)
    return cves


def _severity_from_osv(vuln: dict) -> tuple[str, float | None]:
    label = str((vuln.get("database_specific") or {}).get("severity") or "").lower()
    score: float | None = None
    for entry in vuln.get("severity") or []:
        raw = str(entry.get("score", ""))
        # CVSS vector strings don't carry the number; numeric scores sometimes appear directly.
        try:
            score = float(raw)
        except ValueError:
            continue
    if score is not None:
        label = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    if label in {"moderate"}:
        label = "medium"
    if label not in {"low", "medium", "high", "critical"}:
        label = "medium"
    return label, score


def _fixed_version(vuln: dict, package: str) -> str:
    for affected in vuln.get("affected") or []:
        if (affected.get("package") or {}).get("name") != package:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def scan_device(db: Session, device: Device, client: httpx.Client | None = None, max_details: int = 200) -> dict:
    """Match a device's packages against OSV. Returns counts."""
    items = db.execute(select(SoftwareItem).where(SoftwareItem.device_id == device.id)).scalars().all()
    queryable = [item for item in items
                 if item.version and (":" in item.ecosystem or item.ecosystem in {"PyPI", "npm", "Go", "Maven", "NuGet"})]
    if not queryable:
        return {"device": device.id, "queried": 0, "found": 0, "note": "No packages in an OSV-supported ecosystem."}
    own_client = client is None
    client = client or httpx.Client(timeout=30)
    try:
        found = 0
        details_fetched = 0
        kev = known_exploited(client)
        for start in range(0, len(queryable), 500):
            chunk = queryable[start:start + 500]
            body = {"queries": [{"package": {"name": i.name, "ecosystem": i.ecosystem}, "version": i.version} for i in chunk]}
            results = client.post(OSV_BATCH_URL, json=body).json().get("results", [])
            for item, result in zip(chunk, results):
                for hit in result.get("vulns") or []:
                    vuln_id = hit.get("id")
                    if not vuln_id:
                        continue
                    detail: dict = {}
                    if details_fetched < max_details:
                        try:
                            detail = client.get(OSV_VULN_URL.format(id=vuln_id)).json()
                            details_fetched += 1
                        except (httpx.HTTPError, ValueError):
                            detail = {}
                    aliases = set(detail.get("aliases") or []) | {vuln_id}
                    cve = next((a for a in sorted(aliases) if a.startswith("CVE-")), vuln_id)
                    severity, score = _severity_from_osv(detail)
                    exploited = bool(aliases & kev)
                    if exploited:
                        severity = "critical"
                    row = db.execute(select(Vulnerability).where(Vulnerability.device_id == device.id,
                                                                 Vulnerability.vuln_id == cve,
                                                                 Vulnerability.package == item.name)).scalar_one_or_none()
                    if row is None:
                        row = Vulnerability(tenant_id=device.tenant_id, device_id=device.id, vuln_id=cve, package=item.name)
                        db.add(row)
                        found += 1
                    row.installed_version = item.version
                    row.fixed_version = _fixed_version(detail, item.name)
                    row.severity, row.cvss, row.known_exploited = severity, score, exploited
                    row.summary = str(detail.get("summary") or detail.get("details") or "")[:2000]
                    row.last_seen = utcnow()
                    if row.status == "fixed":
                        row.status = "open"
        return {"device": device.id, "queried": len(queryable), "found": found}
    finally:
        if own_client:
            client.close()


# ---------------------------------------------------------------------------
# External attack surface
# ---------------------------------------------------------------------------

RISKY_PORTS = {
    21: ("FTP", "high", "Cleartext file transfer exposed to the internet."),
    22: ("SSH", "medium", "Restrict to VPN or allow-listed IPs; enforce key auth."),
    23: ("Telnet", "critical", "Cleartext remote shell. Disable immediately."),
    25: ("SMTP", "low", "Expected only on mail servers."),
    53: ("DNS", "medium", "Open resolvers are abused for amplification."),
    80: ("HTTP", "low", "Redirect to HTTPS."),
    110: ("POP3", "medium", "Cleartext mail retrieval."),
    135: ("MS-RPC", "high", "Windows RPC should never face the internet."),
    139: ("NetBIOS", "high", "Windows file sharing exposed."),
    143: ("IMAP", "medium", "Cleartext mail retrieval."),
    389: ("LDAP", "high", "Directory service exposed."),
    443: ("HTTPS", "info", "Check certificate and server patch level."),
    445: ("SMB", "critical", "SMB exposed to the internet: ransomware and worm entry point."),
    1433: ("MSSQL", "high", "Database exposed."),
    1521: ("Oracle", "high", "Database exposed."),
    2049: ("NFS", "high", "File shares exposed."),
    3306: ("MySQL", "high", "Database exposed."),
    3389: ("RDP", "critical", "RDP exposed: the most common ransomware initial access route. Put behind VPN/ZTNA."),
    5432: ("PostgreSQL", "high", "Database exposed."),
    5900: ("VNC", "critical", "Remote desktop often without strong auth."),
    5985: ("WinRM", "high", "Remote management exposed."),
    5986: ("WinRM-TLS", "high", "Remote management exposed."),
    6379: ("Redis", "critical", "Redis is frequently unauthenticated."),
    8080: ("HTTP-alt", "low", "Often admin panels or dev servers."),
    8443: ("HTTPS-alt", "low", "Often admin panels."),
    9200: ("Elasticsearch", "critical", "Frequently unauthenticated data store."),
    11211: ("Memcached", "high", "Amplification and data exposure."),
    27017: ("MongoDB", "critical", "Frequently unauthenticated data store."),
}


def _probe(host: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = b""
            try:
                banner = sock.recv(256)
            except OSError:
                pass
            return {"port": port, "banner": banner.decode("latin-1", "replace").strip()[:200]}
    except OSError:
        return None


def _tls_info(host: str, port: int, timeout: float) -> dict:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (expires - datetime.now(timezone.utc)).days
                return {"valid": True, "expiresInDays": days, "protocol": tls.version(),
                        "issuer": dict(x[0] for x in cert.get("issuer", ()))}
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": exc.verify_message}
    except (OSError, ValueError, KeyError) as exc:
        return {"valid": False, "error": str(exc)}


def scan_external(asset: ExternalAsset, ports: list[int] | None = None, timeout: float = 1.5) -> dict:
    """TCP connect scan of an asset the tenant has attested it owns."""
    ports = ports or sorted(RISKY_PORTS)
    try:
        address = socket.gethostbyname(asset.target)
    except OSError as exc:
        return {"target": asset.target, "error": f"DNS resolution failed: {exc}", "findings": [], "openPorts": []}
    with ThreadPoolExecutor(max_workers=32) as pool:
        open_ports = [r for r in pool.map(lambda p: _probe(address, p, timeout), ports) if r]
    findings = []
    for entry in open_ports:
        service, risk, advice = RISKY_PORTS.get(entry["port"], ("unknown", "medium", "Unexpected open port."))
        entry["service"] = service
        findings.append({"port": entry["port"], "service": service, "risk": risk, "advice": advice, "banner": entry["banner"]})
    for tls_port in (443, 8443):
        if any(e["port"] == tls_port for e in open_ports):
            tls = _tls_info(asset.target, tls_port, timeout * 2)
            if not tls.get("valid"):
                findings.append({"port": tls_port, "service": "TLS", "risk": "high", "advice": f"Certificate problem: {tls.get('error')}"})
            elif tls.get("expiresInDays", 999) < 21:
                findings.append({"port": tls_port, "service": "TLS", "risk": "medium",
                                 "advice": f"Certificate expires in {tls['expiresInDays']} days."})
            if tls.get("protocol") in {"TLSv1", "TLSv1.1"}:
                findings.append({"port": tls_port, "service": "TLS", "risk": "high", "advice": f"Legacy protocol {tls['protocol']}."})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f["risk"], 5))
    return {"target": asset.target, "address": address, "scannedPorts": len(ports), "openPorts": open_ports,
            "findings": findings, "scannedAt": utcnow().isoformat()}
