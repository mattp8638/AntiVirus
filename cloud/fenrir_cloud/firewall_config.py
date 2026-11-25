"""Firewall and router configuration assessment (VULN-13).

Fenrir never asks for firewall credentials. A technician exports the configuration from the firewall's own backup page
and uploads it. Fenrir parses it in memory and keeps only:

* the findings;
* the file's SHA-256, so the evidence can be matched to the exact file;
* the firmware version, when the file records one or the technician gives it.

The file itself is discarded, because it holds password hashes, keys and certificates.

``CAPABILITIES`` is the support matrix. What is assessed for each vendor is listed there, and the findings say which
check produced them. A vendor not in the matrix is refused, rather than given an empty "nothing found" result.

A configuration check is not a port scan. Each finding comes from a setting in the file, and its evidence names that
setting.
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET

from sqlalchemy.orm import Session

from . import audit
from .models import FirewallAssessment

MAX_SIZE = 10 * 1024 * 1024
CHECKS = {
    "wan-any-any": "Rules that pass any traffic from the internet",
    "wan-management": "Management (web GUI, SSH) reachable from the internet",
    "gui-http": "Web GUI over plain HTTP, referer check and anti-lockout",
    "ssh-passwords": "SSH with password sign-in",
    "snmp-community": "SNMP with a default community",
    "remote-logging": "Logs sent to a remote syslog server",
    "upnp": "UPnP / NAT-PMP",
    "ipsec-crypto": "IPsec phase 1 and 2 algorithms",
    "openvpn-crypto": "OpenVPN cipher and TLS authentication",
    "disabled-rules": "Disabled rules left in the rule set",
    "firmware": "Firmware version against the oldest version still supported (given by the technician)",
}
CAPABILITIES = {
    "pfsense": {"name": "pfSense (CE and Plus)", "format": "config.xml from Diagnostics > Backup & Restore", "checks": list(CHECKS)},
    "opnsense": {"name": "OPNsense", "format": "config.xml from System > Configuration > Backups", "checks": list(CHECKS)},
}
UNSUPPORTED_NOTE = ("Other vendors (FortiGate, SonicWall, Sophos, WatchGuard, Cisco, MikroTik, UniFi) are not assessed yet: their "
                    "exports are proprietary or need vendor APIs. Fenrir refuses them rather than report a clean result.")
MGMT_PORTS = {"22", "80", "443", "8080", "8443", "10443"}
WEAK_ENCRYPTION = {"des", "3des", "blowfish", "cast128"}
WEAK_HASH = {"md5", "sha1"}
WEAK_DH = {"1", "2", "5", "22", "23", "24"}


class ConfigFormatError(ValueError):
    pass


def _text(node, path: str, default: str = "") -> str:
    found = node.find(path) if node is not None else None
    return (found.text or "").strip() if found is not None and found.text else default


def _has(node, path: str) -> bool:
    return node is not None and node.find(path) is not None


def parse(data: bytes) -> tuple[str, ET.Element]:
    if len(data) > MAX_SIZE:
        raise ConfigFormatError("The file is larger than 10 MB")
    head = data[:4096].decode("utf-8", "replace")
    if "<!DOCTYPE" in head.upper() or "<!ENTITY" in data.decode("utf-8", "replace").upper():
        raise ConfigFormatError("The file declares a DOCTYPE or entities; firewall exports do not, so it is refused")
    if "<?xml" not in head and "<pfsense" not in head and "<opnsense" not in head:
        raise ConfigFormatError("Not a pfSense or OPNsense configuration (XML). " + UNSUPPORTED_NOTE)
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ConfigFormatError(f"The XML could not be read: {exc}") from None
    vendor = root.tag.lower()
    if vendor not in CAPABILITIES:
        raise ConfigFormatError(f"Unsupported configuration ({root.tag}). " + UNSUPPORTED_NOTE)
    return vendor, root


def _finding(out, check, title, severity, evidence, advice):
    out.append({"check": check, "title": title, "severity": severity, "evidence": evidence[:300], "advice": advice})


def _version_tuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def assess(vendor: str, root: ET.Element, firmware: str = "", minimum: str = "") -> tuple[list[dict], list[dict], dict]:
    f: list[dict] = []
    system = root.find("system")
    # Firewall rules
    rules = (root.find("filter").findall("rule") if root.find("filter") is not None else [])
    disabled = 0
    for i, rule in enumerate(rules):
        if _has(rule, "disabled"):
            disabled += 1
            continue
        if _text(rule, "type", "pass") != "pass":
            continue
        iface = _text(rule, "interface").lower()
        if "wan" not in iface.split(","):
            continue
        src_any, dst_any = _has(rule, "source/any"), _has(rule, "destination/any")
        port = _text(rule, "destination/port")
        descr = _text(rule, "descr") or f"rule {i + 1}"
        dst_self = _text(rule, "destination/network") in ("(self)", "wanip") or _text(rule, "destination/address") == "(self)"
        if src_any and dst_any and not port:
            _finding(f, "wan-any-any", f"WAN rule passes all traffic from anywhere: '{descr}'", "critical",
                     f"<filter><rule> interface={iface} type=pass source=any destination=any (no port)",
                     "Remove the rule, or limit it to the source, destination and port that need it.")
        elif src_any and (dst_self or dst_any) and (port in MGMT_PORTS or not port):
            if dst_self or port in MGMT_PORTS:
                _finding(f, "wan-management", f"Management reachable from the internet: '{descr}'", "high",
                         f"<filter><rule> interface={iface} source=any destination={'(self)' if dst_self else 'any'} port={port or 'any'}",
                         "Reach management over a VPN, or restrict the source to known addresses.")
    if disabled:
        _finding(f, "disabled-rules", f"{disabled} disabled rule(s) in the rule set", "info", f"{disabled} <rule> elements with <disabled/>",
                 "Remove rules that are no longer needed so reviews stay clear.")
    # Web GUI
    gui = system.find("webgui") if system is not None else None
    if _text(gui, "protocol", "https") == "http":
        _finding(f, "gui-http", "Web GUI served over plain HTTP", "high", "<system><webgui><protocol>http</protocol>",
                 "Use HTTPS for the web GUI.")
    if _has(gui, "nohttpreferercheck"):
        _finding(f, "gui-http", "Web GUI HTTP referer check turned off", "medium", "<system><webgui><nohttpreferercheck/>",
                 "Turn the referer check back on; it protects against cross-site request forgery.")
    # SSH
    ssh = system.find("ssh") if system is not None else None
    ssh_on = _text(ssh, "enable") in ("enabled", "1") or (_has(ssh, "enable") and not _text(ssh, "enable"))
    if vendor == "pfsense":
        passwords = _text(ssh, "sshdkeyonly") in ("", "disabled")  # enabled = key only; both = key and password together
    else:
        passwords = _text(ssh, "passwordauth") == "1"
    if ssh_on and passwords:
        _finding(f, "ssh-passwords", "SSH accepts passwords", "medium",
                 "<system><ssh> " + ("without key-only sign-in" if vendor == "pfsense" else "<passwordauth>1"),
                 "Allow public-key sign-in only, or turn SSH off when not needed.")
    if ssh_on and _text(ssh, "permitrootlogin") == "1":
        _finding(f, "ssh-passwords", "SSH allows root sign-in", "medium", "<system><ssh><permitrootlogin>1", "Sign in as a named user instead.")
    # SNMP
    snmp = root.find("snmpd")
    community = _text(snmp, "rocommunity")
    if snmp is not None and (_has(snmp, "enable") or _text(snmp, "enable") == "1") and community.lower() in ("public", "private", ""):
        _finding(f, "snmp-community", f"SNMP enabled with the community '{community or '(empty)'}'", "high",
                 "<snmpd><rocommunity>", "Use a long, unique community (or SNMPv3) and limit who can query it.")
    # Remote logging
    syslog = root.find("syslog")
    remote = _text(syslog, "remoteserver") or (syslog is not None and syslog.find(".//destination") is not None)
    if not remote:
        _finding(f, "remote-logging", "No remote syslog server: logs stay on the firewall only", "medium", "<syslog> has no remote server",
                 "Send logs to a remote syslog or SIEM so they survive a compromise or failure.")
    # UPnP
    upnp = root.find("installedpackages/miniupnpd/config")
    if upnp is not None and (_text(upnp, "enable") in ("on", "1", "yes")):
        _finding(f, "upnp", "UPnP / NAT-PMP is on: devices can open inbound ports by themselves", "medium",
                 "<installedpackages><miniupnpd><config><enable>on", "Turn UPnP off unless a specific need is documented.")
    # IPsec
    for ph1 in root.findall("ipsec/phase1"):
        name = _text(ph1, "descr") or _text(ph1, "remote-gateway") or "tunnel"
        algs = {(_text(e, "encryption-algorithm/name") or "").lower() for e in ph1.findall("encryption/item")} | {
            _text(ph1, "encryption-algorithm/name").lower()}
        hashes = {(_text(e, "hash-algorithm") or "").lower() for e in ph1.findall("encryption/item")} | {
            x.lower() for x in _text(ph1, "hash-algorithm").split(",")}
        groups = {_text(e, "dhgroup") for e in ph1.findall("encryption/item")} | {_text(ph1, "dhgroup")}
        weak = sorted((algs & WEAK_ENCRYPTION) | (hashes & WEAK_HASH) | {f"DH group {g}" for g in groups & WEAK_DH})
        if weak:
            _finding(f, "ipsec-crypto", f"IPsec tunnel '{name}' uses weak algorithms: {', '.join(weak)}", "high",
                     "<ipsec><phase1> encryption/hash/dhgroup", "Use AES-GCM or AES-CBC with SHA-256 or better and DH group 14 or higher.")
        if _text(ph1, "authentication_method") == "pre_shared_key" and len(_text(ph1, "pre-shared-key")) < 20:
            _finding(f, "ipsec-crypto", f"IPsec tunnel '{name}' uses a short pre-shared key", "medium",
                     "<ipsec><phase1><pre-shared-key> shorter than 20 characters", "Use a long random key or certificates.")
    # OpenVPN
    for server in root.findall("openvpn/openvpn-server"):
        name = _text(server, "description") or "server"
        cipher = (_text(server, "crypto") or _text(server, "data_ciphers_fallback")).upper()
        if cipher in ("BF-CBC", "NONE", "DES-CBC", "DES-EDE3-CBC"):
            _finding(f, "openvpn-crypto", f"OpenVPN '{name}' uses the weak cipher {cipher}", "high", "<openvpn-server><crypto>",
                     "Use AES-256-GCM.")
        if not _text(server, "tls"):
            _finding(f, "openvpn-crypto", f"OpenVPN '{name}' has no TLS authentication key", "low", "<openvpn-server> without <tls>",
                     "Add a TLS auth or TLS crypt key to drop unauthenticated packets early.")
    # Firmware
    found_version = firmware or _text(root, "version_firmware")
    untested = []
    fw = {"version": found_version, "minimum": minimum}
    if found_version and minimum:
        if _version_tuple(found_version) < _version_tuple(minimum):
            _finding(f, "firmware", f"Firmware {found_version} is older than {minimum}", "high", f"version {found_version}",
                     "Upgrade to a supported release.")
        fw["status"] = "checked"
    else:
        untested.append({"check": "firmware", "reason": "The configuration file does not record the firmware release; enter the version "
                                                        "shown on the firewall's dashboard and the oldest supported release to check it"})
        fw["status"] = "not checked"
    untested.append({"check": "passwords", "reason": "Password strength is not checked: only hashes are in the file, and Fenrir does not crack them"})
    untested.append({"check": "live state", "reason": "Only the saved configuration is assessed, not what is running or installed packages' versions"})
    order = ["critical", "high", "medium", "low", "info"]
    f.sort(key=lambda x: order.index(x["severity"]))
    summary = {s: sum(1 for x in f if x["severity"] == s) for s in order}
    summary["rules"] = len(rules)
    return f, untested, {"firmware": fw, **summary}


def run(db: Session, tenant_id: str, label: str, data: bytes, firmware: str, minimum: str, actor: str) -> FirewallAssessment:
    vendor, root = parse(data)
    findings, untested, summary = assess(vendor, root, firmware, minimum)
    row = FirewallAssessment(tenant_id=tenant_id, label=label[:200], vendor=vendor, file_sha256=hashlib.sha256(data).hexdigest(),
                             firmware=summary.pop("firmware"), findings=findings, untested=untested, summary=summary, created_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "firewall.assessed", row.id, tenant_id, vendor=vendor, sha256=row.file_sha256, summary=summary)
    return row
