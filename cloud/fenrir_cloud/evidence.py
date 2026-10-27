"""What an alert is about, pulled out of the raw event: the file, the threat, the process, where it came from, and
any service, registry key, network destination or script involved.

Agents name things differently (the Windows scanner says ``path``, ETW says ``TargetFilename``, real-time says
``processImage``), so each piece is looked up under every name it is known by. The result is stored on the alert
(``details.evidence``: one entry per occurrence, newest last) and shown on the alert and incident pages.
"""

from __future__ import annotations

import copy
from typing import Any

# section -> label -> candidate field names (full flattened key or leaf, any case), first non-empty wins.
SECTIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "file": {
        "path": ("path", "TargetFilename", "filePath", "targetPath", "file", "fileName", "ImageLoaded"),
        "sha256": ("sha256", "fileSha256", "Hashes.SHA256", "hash"),
        "sizeBytes": ("sizeBytes", "fileSizeBytes", "size"),
        "signer": ("signer", "Signature", "signerName", "publisher"),
        "signed": ("Signed", "signed", "isSigned"),
        "reputation": ("reputation",),
        "contentType": ("contentType",),
        "entropy": ("Entropy", "entropy"),
        "quarantinedPath": ("quarantinedPath",),
        "quarantineRecordId": ("quarantineRecordId",),
        "evidenceRecordId": ("evidenceRecordId",),
    },
    "threat": {
        "name": ("ThreatName", "threatName", "alertTitle", "detection", "malwareName", "signatureName", "ruleName"),
        "summary": ("alertSummary",),
        "verdict": ("Verdict", "verdict"),
        "disposition": ("disposition",),
        "remediation": ("remediationStatus",),
        "remediationError": ("remediationError",),
        "engine": ("engine", "scanner"),
        "score": ("heuristicScore", "Score", "score", "mlScore", "probability"),
        "reasons": ("reasonCodes", "reasons"),
        "technique": ("techniqueId",),
        "tactic": ("tacticId",),
    },
    "process": {
        "image": ("Image", "processImage", "processImagePath", "processPath", "exe"),
        "pid": ("ProcessId", "processId", "pid"),
        "commandLine": ("CommandLine", "commandLine", "cmdline"),
        "user": ("User", "user", "userName", "userSid", "account"),
        "integrity": ("IntegrityLevel", "integrityLevel"),
        "parentImage": ("ParentImage", "parentImage", "parentProcessImagePath"),
        "parentPid": ("ParentProcessId", "parentProcessId", "ppid"),
        "parentCommandLine": ("ParentCommandLine", "parentCommandLine"),
    },
    "origin": {
        "label": ("originLabel",),
        "channel": ("originContext.channel", "contextType"),
        "url": ("originContext.sourceUrl", "sourceUrl", "Url", "url"),
        "domain": ("originContext.sourceDomain", "sourceDomain", "originReference"),
        "application": ("originContext.sourceApplication", "sourceApplication", "originContext.parentApplication"),
        "browser": ("originContext.browserFamily", "browserFamily"),
        "downloaded": ("originContext.downloadOriginated", "downloadOriginated"),
        "emailAttachment": ("originContext.attachmentOriginated", "originContext.emailOriginated", "emailOriginated"),
        "macroDocument": ("originContext.macroDocument", "macroDocument"),
        "lure": ("originContext.suspiciousLureName", "suspiciousLureName"),
        "fakeUpdate": ("originContext.fakeUpdatePattern",),
    },
    "service": {
        "name": ("serviceName", "ServiceName"),
        "imagePath": ("serviceImagePath", "ImagePath"),
        "startType": ("startType", "StartType"),
        "account": ("serviceAccount", "ServiceAccount"),
    },
    "registry": {
        "key": ("TargetObject", "targetObject", "registryKey"),
        "value": ("Details", "registryValue"),
        "action": ("EventType", "changeType"),
    },
    "network": {
        "destination": ("DestinationIp", "destinationIp", "remoteAddress"),
        "port": ("DestinationPort", "destinationPort", "remotePort"),
        "hostname": ("DestinationHostname", "destinationHostname", "remoteHost"),
        "protocol": ("Protocol", "protocol"),
        "query": ("QueryName", "queryName", "dnsQuery"),
        "source": ("SourceIp", "sourceIp", "localAddress"),
    },
    "script": {
        "application": ("appName", "Application"),
        "excerpt": ("ScriptBlockText", "scriptBlockText", "scriptContent", "content"),
    },
    "logon": {
        "user": ("TargetUserName", "targetUserName"),
        "type": ("LogonType", "logonType"),
        "sourceIp": ("IpAddress", "ipAddress", "sourceIpAddress"),
        "status": ("Status", "status", "result"),
    },
}

MAX_TEXT = 2000
EMPTY = (None, "", [], {}, "unknown", "none")


def _index(fields: dict) -> dict[str, Any]:
    """Lower-cased full keys and leaf names -> value (full keys win over leaves)."""
    index: dict[str, Any] = {}
    for key, value in fields.items():
        if value in EMPTY:
            continue
        index.setdefault(str(key).lower(), value)
    for key, value in fields.items():
        if value in EMPTY:
            continue
        index.setdefault(str(key).rsplit(".", 1)[-1].lower(), value)
    return index


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return value[:MAX_TEXT]
    if isinstance(value, list):
        return [_clean(v) for v in value[:20] if v not in EMPTY]
    if isinstance(value, dict):
        return {str(k)[:80]: _clean(v) for k, v in list(value.items())[:20]}
    return value


def extract(fields: dict, event_type: str = "", summary: str = "", occurred_at: str | None = None,
            source: str = "", event_id: Any = None) -> dict:
    """Evidence for one event: {"event": {...}, "file": {...}, "process": {...}, ...} with only what is present."""
    index = _index(fields or {})
    out: dict[str, Any] = {}
    for section, labels in SECTIONS.items():
        found: dict[str, Any] = {}
        for label, names in labels.items():
            for name in names:
                value = index.get(name.lower())
                if value not in EMPTY and value is not False:
                    found[label] = _clean(value)
                    break
        # A registry "action" or a lone network "protocol" says nothing on its own.
        if section == "registry" and "key" not in found:
            found = {}
        if section == "network" and not ({"destination", "hostname", "query"} & found.keys()):
            found = {}
        if section == "logon" and "user" not in found:
            found = {}
        if section == "origin" and not ({"label", "url", "domain", "application"} & found.keys()):
            found = {}
        if section == "threat" and set(found) <= {"engine", "tactic", "technique"}:
            found = {}
        if found:
            out[section] = found
    # The process that the file belongs to is the same thing twice; keep the file only once.
    if out.get("file", {}).get("path") and out.get("process", {}).get("image") == out["file"]["path"]:
        out["process"].pop("image")
        if not out["process"]:
            out.pop("process")
    out["event"] = {k: v for k, v in {"type": event_type, "summary": summary[:500] if summary else "", "at": occurred_at,
                                      "source": source, "id": event_id}.items() if v not in EMPTY}
    return out


def headline(evidence: dict) -> dict:
    """The few fields alert lists show: what file and which process."""
    file = (evidence.get("file") or {}).get("path")
    process = (evidence.get("process") or {}).get("image") or (evidence.get("process") or {}).get("parentImage")
    return {k: v for k, v in {"file": file, "process": process or file,
                              "sha256": (evidence.get("file") or {}).get("sha256"),
                              "threat": (evidence.get("threat") or {}).get("name"),
                              "user": (evidence.get("process") or {}).get("user")}.items() if v}


def same_occurrence(a: dict, b: dict) -> bool:
    """Two events about the same file/process/key: folded into one occurrence instead of repeating it."""
    def key(e: dict) -> tuple:
        return ((e.get("file") or {}).get("sha256") or (e.get("file") or {}).get("path"),
                (e.get("process") or {}).get("image"), (e.get("registry") or {}).get("key"),
                (e.get("service") or {}).get("name"), (e.get("network") or {}).get("destination") or (e.get("network") or {}).get("query"))
    return key(a) == key(b)


MAX_OCCURRENCES = 25


def add_occurrence(details: dict, evidence: dict) -> dict:
    """Append evidence to an alert's details (deduplicated, newest kept, capped); returns new details."""
    # Deep copy: the stored JSON must be a new object, or the database never sees the change.
    occurrences = copy.deepcopy(list(details.get("evidence") or []))
    for existing in occurrences:
        if same_occurrence(existing, evidence):
            existing["count"] = int(existing.get("count") or 1) + 1
            existing["lastAt"] = (evidence.get("event") or {}).get("at")
            break
    else:
        occurrences.append(evidence)
    details = dict(details)
    details["evidence"] = occurrences[-MAX_OCCURRENCES:]
    return details


def indicators(alert_details: list[dict]) -> dict[str, list]:
    """Indicators of compromise across an incident's alerts: hashes, files, processes, users, domains, IPs..."""
    out: dict[str, dict[str, int]] = {k: {} for k in ("sha256", "files", "processes", "commandLines", "users", "domains",
                                                         "urls", "ips", "services", "registry")}

    def add(kind: str, value: Any) -> None:
        if isinstance(value, str) and value.strip() and value not in EMPTY:
            out[kind][value] = out[kind].get(value, 0) + 1

    for details in alert_details:
        for ev in details.get("evidence") or []:
            file, proc, origin = ev.get("file") or {}, ev.get("process") or {}, ev.get("origin") or {}
            net, svc, reg = ev.get("network") or {}, ev.get("service") or {}, ev.get("registry") or {}
            add("sha256", file.get("sha256"))
            add("files", file.get("path"))
            add("processes", proc.get("image"))
            add("processes", proc.get("parentImage"))
            add("commandLines", proc.get("commandLine"))
            add("users", proc.get("user"))
            add("domains", origin.get("domain"))
            add("domains", net.get("hostname"))
            add("domains", net.get("query"))
            add("urls", origin.get("url"))
            add("ips", net.get("destination"))
            add("services", svc.get("name"))
            add("registry", reg.get("key"))
    return {kind: [{"value": v, "count": n} for v, n in sorted(values.items(), key=lambda x: -x[1])[:50]]
            for kind, values in out.items() if values}
