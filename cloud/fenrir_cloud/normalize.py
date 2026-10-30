"""Normalise telemetry from every agent generation into one field vocabulary.

Inputs we see in the wild:

* Windows Fenrir service: ``{eventId, eventType, source, summary, occurredAt, payloadJson}``
  where ``payloadJson`` is a JSON string and eventType is dotted (``process.terminated``).
* Linux/macOS Fenrir agents and the original unified schema:
  ``{eventId, deviceId, timestamp, eventType: ProcessStart, payload: {processName, pid, commandLine}}``
* The SIEM (tamsil) agent and third-party shippers with Sysmon/ECS-style names.

Output fields use Sigma/Sysmon names (Image, CommandLine, TargetFilename,
DestinationIp, QueryName ...) because that is what public Sigma rules expect.
"""

from __future__ import annotations

import json
import re
import ntpath
import posixpath
from datetime import datetime, timezone
from typing import Any

# canonical name -> accepted aliases (compared case-insensitively)
ALIASES: dict[str, tuple[str, ...]] = {
    "Image": ("image", "processImagePath", "processPath", "process_path", "imagePath", "exe", "executable", "processImage"),
    "ProcessName": ("processName", "process_name", "comm"),
    "CommandLine": ("commandLine", "command_line", "cmdline", "cmd", "args"),
    "ProcessId": ("pid", "processId", "process_id"),
    "ParentImage": ("parentImage", "parentImagePath", "parentProcessImagePath", "parentProcessPath", "parent_path", "parentExe"),
    "ParentProcessName": ("parentProcessName", "parent_name", "parentName"),
    "ParentCommandLine": ("parentCommandLine", "parent_command_line", "parentCmdline"),
    "ParentSha256": ("parentSha256", "parentProcessSha256"),
    "ParentProcessId": ("ppid", "parentPid", "parentProcessId", "parent_pid"),
    "User": ("user", "userName", "username", "account", "uid", "userSid"),
    "IntegrityLevel": ("integrityLevel", "integrity"),
    "Hashes": ("hashes",),
    "sha256": ("sha256", "SHA256", "fileSha256", "hash"),
    "Signed": ("signed", "isSigned"),
    "Signature": ("signer", "signature", "signerName", "publisher"),
    "TargetFilename": ("filePath", "file_path", "targetFilename", "target_path", "targetPath", "fileName"),
    "SourceFilename": ("sourceFilename", "oldPath", "old_path", "sourcePath"),
    "DestinationIp": ("destinationIp", "destIp", "dest_ip", "remoteAddress", "remote_ip", "daddr", "dst_ip"),
    "DestinationPort": ("destinationPort", "destPort", "dest_port", "remotePort", "dport", "dst_port"),
    "DestinationHostname": ("destinationHostname", "remoteHost", "host", "domain", "hostname_dest"),
    "Application": ("appId", "applicationId"),
    "SourceIp": ("sourceIp", "localAddress", "src_ip", "saddr"),
    "SourcePort": ("sourcePort", "localPort", "src_port", "sport"),
    "Protocol": ("protocol", "proto"),
    "Initiated": ("initiated", "outbound"),
    "QueryName": ("queryName", "query", "qname", "dnsQuery"),
    "QueryResults": ("queryResults", "answers"),
    "TargetObject": ("targetObject", "registryKey", "registry_path", "key"),
    "Details": ("details", "registryValue", "value"),
    "ScriptBlockText": ("scriptBlockText", "scriptContent", "content", "script"),
    "Url": ("url", "uri"),
    "ThreatName": ("threatName", "detection", "malwareName", "signatureName"),
    "Score": ("score", "riskScore"),
    "Verdict": ("verdict", "action"),
    "Entropy": ("entropy",),
    "FileCount": ("fileCount", "files", "count"),
    "TargetUserName": ("targetUserName", "target_user"),
    "LogonType": ("logonType", "logon_type"),
    "Status": ("status", "result"),
}

_LOOKUP = {}
for canonical, aliases in ALIASES.items():
    _LOOKUP[canonical.lower()] = canonical
    for alias in aliases:
        _LOOKUP.setdefault(alias.lower(), canonical)

# eventType -> (category, sigma-ish action)
_TYPE_RULES: list[tuple[tuple[str, ...], str]] = [
    (("processstart", "process.start", "process.created", "process_creation", "process.exec", "exec"), "process"),
    (("process.terminated", "process.tree.terminated", "processstop", "process.exit"), "process"),
    (("imageload", "image.load", "module.load", "driver.load"), "image_load"),
    (("networkconnect", "network.connect", "network.connection", "network_connection", "network.destination"), "network"),
    (("dns", "dnsquery", "dns.query"), "dns"),
    (("filewrite", "file.write", "file.create", "file.rename", "file.delete", "file.modified", "file_event", "file."), "file"),
    (("registry",), "registry"),
    (("amsi", "script", "powershell"), "script"),
    (("ransomware",), "ransomware"),
    (("asr.", "appcontrol.", "devicecontrol."), "protection"),
    (("scan.", "threat.", "malware", "quarantine", "detection", "signatures."), "malware"),
    (("logon", "auth", "login", "pam."), "auth"),
    (("process.access", "remote.thread", "processaccess"), "process_access"),
    (("ml.model.",), "agent"),
    (("device.", "service.", "policy.", "update.", "agent.", "tamper.", "storage.", "support.", "breakglass."), "agent"),
    (("patch.", "software."), "inventory"),
    (("web.", "http", "proxy"), "web"),
]


def categorize(event_type: str) -> str:
    lowered = event_type.lower()
    if lowered.startswith("ad."):  # Active Directory events from domain controllers (prefix only: "thread." contains "ad.")
        return "identity"
    for needles, category in _TYPE_RULES:
        if any(lowered == needle or lowered.startswith(needle) or needle in lowered for needle in needles):
            return category
    return "other"


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10**11 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)
    if isinstance(value, str) and value:
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed
        except ValueError:
            pass
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _flatten(prefix: str, value: Any, out: dict) -> None:
    if isinstance(value, dict):
        for key, inner in value.items():
            _flatten(f"{prefix}.{key}" if prefix else str(key), inner, out)
    else:
        out[prefix] = value


def _basename(path: str) -> str:
    return ntpath.basename(path) if "\\" in path else posixpath.basename(path)


SEVERITY_BY_SCORE = ((90, "critical"), (70, "high"), (45, "medium"), (20, "low"))


# Windows agents before this fix wrote `"confidence":87","tacticId"` (a stray quote after a number) in real-time
# protection events. Without the repair the whole payload, including the agent's allow/block verdict, is lost.
_STRAY_QUOTE = re.compile(r'(":\s*-?\d+(?:\.\d+)?)"(?=\s*,\s*")')


def _repair(text: str) -> dict:
    try:
        repaired = json.loads(_STRAY_QUOTE.sub(r"\1", text), strict=False)
        return repaired if isinstance(repaired, dict) else {"raw": text}
    except json.JSONDecodeError:
        return {"raw": text}


def _scrub(value: Any) -> Any:
    """Drop NUL characters: PostgreSQL text cannot store them, and one would fail the agent's whole batch."""
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {_scrub(key): _scrub(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_scrub(inner) for inner in value]
    return value


def normalize(raw: dict, platform: str = "") -> dict:
    """Return ``{event_id, event_type, category, source, summary, occurred_at, severity, fields}``."""
    raw = _scrub(raw)
    payload: Any = raw.get("payload")
    if payload is None and isinstance(raw.get("payloadJson"), str) and raw["payloadJson"].strip():
        try:
            payload = _scrub(json.loads(raw["payloadJson"], strict=False))
        except json.JSONDecodeError:
            payload = _scrub(_repair(raw["payloadJson"]))
    if not isinstance(payload, dict):
        payload = {} if payload is None else {"value": payload}

    event_type = str(raw.get("eventType") or payload.get("eventType") or "unknown")
    flat: dict[str, Any] = {}
    _flatten("", payload, flat)

    fields: dict[str, Any] = {}
    for key, value in flat.items():
        leaf = key.rsplit(".", 1)[-1]
        canonical = _LOOKUP.get(key.lower()) or _LOOKUP.get(leaf.lower())
        if canonical and canonical not in fields:
            fields[canonical] = value
        fields.setdefault(key, value)

    # Derive Image from ProcessName when the agent only knows the short name, and vice versa.
    if "Image" not in fields and "ProcessName" in fields:
        fields["Image"] = fields["ProcessName"]
    if "Image" in fields and "ProcessName" not in fields and isinstance(fields["Image"], str):
        fields["ProcessName"] = _basename(fields["Image"])
    if isinstance(fields.get("ParentImage"), str) and "ParentProcessName" not in fields:
        fields["ParentProcessName"] = _basename(fields["ParentImage"])
    if isinstance(fields.get("Hashes"), str) and "sha256" not in fields:
        for part in fields["Hashes"].split(","):
            if part.upper().startswith("SHA256="):
                fields["sha256"] = part.split("=", 1)[1].lower()

    category = categorize(event_type)
    # The Windows service reports the file a file/malware event concerns as plain "path".
    if category in {"file", "malware", "ransomware"} and "TargetFilename" not in fields and isinstance(fields.get("path"), str):
        fields["TargetFilename"] = fields["path"]
    if category == "network" and "DestinationHostname" in fields and "QueryName" not in fields and event_type.lower().startswith("dns"):
        fields["QueryName"] = fields["DestinationHostname"]

    fields["EventType"] = event_type
    fields["Category"] = category
    if platform:
        fields["Platform"] = platform

    severity = str(raw.get("severity") or payload.get("severity") or "").lower()
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "info"
        score = fields.get("Score")
        if isinstance(score, (int, float)):
            for floor, label in SEVERITY_BY_SCORE:
                if score >= floor:
                    severity = label
                    break

    summary = str(raw.get("summary") or "")
    if not summary:
        summary = " ".join(
            str(part) for part in (event_type, fields.get("ProcessName"), fields.get("CommandLine") or fields.get("TargetFilename")
                                   or fields.get("DestinationIp") or fields.get("QueryName")) if part
        )[:500]

    return {
        "event_id": str(raw.get("eventId") or raw.get("id") or ""),
        "event_type": event_type,
        "category": category,
        "source": str(raw.get("source") or "agent"),
        "summary": summary,
        "occurred_at": _parse_time(raw.get("occurredAt") or raw.get("timestamp") or raw.get("time")),
        "severity": severity,
        "fields": fields,
    }
