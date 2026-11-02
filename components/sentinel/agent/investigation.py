from __future__ import annotations

import hashlib
import getpass
import json
import platform
import re
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from collectors.files import collect_recent_files
from collectors.logs import collect_defender_events, collect_powershell_events, collect_security_events, collect_system_events
from collectors.network import collect_connections
from collectors.persistence import collect_scheduled_tasks, collect_services
from collectors.processes import collect_processes
from collectors.software import collect_installed_software
from collectors.startup import collect_startup_items
from collectors.users import collect_local_users

try:
    import psutil
except Exception:
    psutil = None

DEFAULT_SCOPES = ["processes", "network", "services", "startup", "scheduled_tasks", "eventlogs", "software", "users", "files"]
RELEASE1_ARTIFACT_FILES = [
    "endpoint_snapshot.json",
    "processes.json",
    "network_connections.json",
    "persistence.json",
    "event_logs.json",
    "powershell_activity.json",
]

SCOPE_ALIASES = {
    "process_tree": "processes",
    "command_lines": "processes",
    "network_connections": "network",
    "startup_folders": "startup",
    "registry_autoruns": "startup",
    "persistence": "startup",
    "windows_event_logs": "eventlogs",
    "powershell_artifacts": "eventlogs",
    "defender_events": "eventlogs",
    "security_events": "eventlogs",
    "system_events": "eventlogs",
    "system_event_logs": "eventlogs",
    "installed_software": "software",
    "local_users": "users",
    "admins": "users",
    "suspicious_files": "files",
}

SUSPICIOUS_PATTERNS = [
    ("Encoded PowerShell command", re.compile(r"(?i)(powershell|pwsh).*(-enc|-encodedcommand)\b"), "critical", "Encoded PowerShell commands conceal the payload."),
    ("PowerShell execution policy bypass", re.compile(r"(?i)(powershell|pwsh).*executionpolicy\s+bypass"), "high", "Execution policy bypass weakens script execution controls."),
    ("PowerShell hidden window", re.compile(r"(?i)(powershell|pwsh).*(windowstyle\s+hidden|-w\s+hidden)"), "high", "Hidden PowerShell windows often indicate stealthy execution."),
    ("PowerShell download cradle", re.compile(r"(?i)(downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\b|wget\b)"), "high", "Download cradle behaviour is frequently used to stage payloads."),
    ("Certutil download behaviour", re.compile(r"(?i)certutil.*(-urlcache|-split|-f).*https?://"), "high", "Certutil can be abused to retrieve payloads from remote URLs."),
    ("Regsvr32 remote execution", re.compile(r"(?i)regsvr32.*(scrobj\.dll|/i:https?://)"), "critical", "Regsvr32 remote script execution is high risk."),
    ("MSHTA remote execution", re.compile(r"(?i)mshta\s+https?://"), "critical", "MSHTA invoking remote content is high risk."),
    ("Shadow copy deletion", re.compile(r"(?i)(vssadmin|wmic).*shadow.*delete"), "critical", "Shadow copy deletion is consistent with destructive tampering."),
    ("Recovery tampering", re.compile(r"(?i)bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"), "critical", "Recovery tampering can prevent remediation."),
    ("Execution from AppData or Temp", re.compile(r"(?i)(\\appdata\\|\\temp\\|/appdata/|/tmp/).*(\.exe|\.dll|\.ps1|\.vbs|\.js)"), "medium", "Execution from user-writable paths is suspicious."),
]

PARENT_CHILD_RULES = [
    ("Office spawning shell or script interpreter", {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}, {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}, "critical", "Office spawning scripting or shell interpreters is a common macro abuse pattern."),
    ("Browser spawning shell or script interpreter", {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"}, {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}, "high", "Browsers should not normally launch script interpreters."),
    ("Script interpreter spawning system tool", {"wscript.exe", "cscript.exe", "mshta.exe"}, {"powershell.exe", "cmd.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"}, "high", "Script interpreters launching system tools is often suspicious."),
]


def _normalize_scope(scope: Dict[str, Any] | None) -> Dict[str, Any]:
    scope = scope or {}
    if scope.get("all"):
        return {"collectors": list(DEFAULT_SCOPES)}

    selected = scope.get("collectors") or scope.get("scopes") or scope.get("include")
    if selected:
        return {"collectors": sorted({SCOPE_ALIASES.get(str(item).lower(), str(item).lower()) for item in selected if item})}

    collectors = []
    for name in DEFAULT_SCOPES:
        include_flag = scope.get(name)
        if include_flag is None:
            include_flag = scope.get(f"include_{name}")
        if include_flag is None:
            include_flag = True
        if include_flag:
            collectors.append(name)
    return {"collectors": collectors}


def _stable_finding_id(title: str, evidence: Dict[str, Any]) -> str:
    digest = hashlib.sha1(json.dumps({"title": title, "evidence": evidence}, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return f"F-{digest[:12].upper()}"


def _parse_cmdline(cmdline: Any) -> str:
    if isinstance(cmdline, list):
        return " ".join(str(part) for part in cmdline if part)
    return str(cmdline or "")


def _utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _boot_time() -> str | None:
    if psutil is None:
        return None
    try:
        return datetime.utcfromtimestamp(psutil.boot_time()).isoformat() + "Z"
    except Exception:
        return None


def _logged_in_user() -> str | None:
    try:
        return getpass.getuser()
    except Exception:
        return None


def _local_users(data: Dict[str, Any]) -> Dict[str, Any]:
    users = data.get("local_users") or {}
    if isinstance(users, dict):
        return {
            "users": users.get("users", []),
            "administrators": users.get("administrators", []),
        }
    return {"users": users if isinstance(users, list) else [], "administrators": []}


def collect_endpoint_snapshot(data: Dict[str, Any] | None = None) -> Dict[str, Any]:
    data = data or {}
    local_accounts = _local_users(data)
    return {
        "collected_at": data.get("timestamp") or _utc_now(),
        "hostname": platform.node(),
        "fqdn": socket.getfqdn(),
        "os_version": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "boot_time_utc": _boot_time(),
        "logged_in_user": _logged_in_user(),
        "local_users": local_accounts["users"],
        "local_administrators": local_accounts["administrators"],
        "recent_files": data.get("recent_files", []),
    }


def _finding(title: str, severity: str, module: str, evidence: Dict[str, Any], recommendation: str) -> Dict[str, Any]:
    return {
        "finding_id": _stable_finding_id(title, evidence),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "module": module,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "recommended_action": recommendation,
    }


def _severity_rank(severity: str) -> int:
    return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)


def _analyze_processes(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    by_pid = {process.get("pid"): process for process in processes if process.get("pid") is not None}

    for process in processes:
        name = str(process.get("name") or "").lower()
        cmdline = _parse_cmdline(process.get("cmdline"))
        parent = by_pid.get(process.get("ppid"), {})
        parent_name = str(parent.get("name") or "").lower()

        for title, pattern, severity, reason in SUSPICIOUS_PATTERNS:
            if pattern.search(cmdline) or pattern.search(name):
                findings.append(_finding(title, severity, "processes", {
                    "pid": process.get("pid"),
                    "ppid": process.get("ppid"),
                    "name": process.get("name"),
                    "parent_name": parent.get("name"),
                    "cmdline": cmdline,
                    "username": process.get("username"),
                }, reason))

        for title, parents, children, severity, reason in PARENT_CHILD_RULES:
            if parent_name in parents and name in children:
                findings.append(_finding(title, severity, "process_tree", {
                    "pid": process.get("pid"),
                    "ppid": process.get("ppid"),
                    "name": process.get("name"),
                    "parent_name": parent.get("name"),
                    "cmdline": cmdline,
                }, reason))

    return findings


def _analyze_network(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    suspicious_processes = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}

    for connection in connections:
        remote = str(connection.get("remote_address") or connection.get("raddr") or "")
        process_name = str(connection.get("process_name") or "").lower()
        if remote and remote not in {"None", "", "()"}:
            findings.append(_finding("Outbound network connection observed", "low", "network", {
                "pid": connection.get("pid"),
                "process_name": connection.get("process_name"),
                "process_path": connection.get("process_path"),
                "remote": remote,
                "local": connection.get("laddr"),
                "status": connection.get("status"),
            }, "Review the destination and confirm it is expected for this endpoint."))
        if process_name in suspicious_processes and remote and remote not in {"None", "", "()"}:
            findings.append(_finding("Suspicious process with network connection", "high", "network", {
                "pid": connection.get("pid"),
                "process_name": connection.get("process_name"),
                "process_path": connection.get("process_path"),
                "remote": remote,
                "local": connection.get("laddr"),
                "status": connection.get("status"),
            }, "Inspect the process command line, parent process and destination for malicious staging or exfiltration."))
    return findings


def _analyze_startup(startup: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for folder in startup.get("folders", []):
        for entry in folder.get("entries", []):
            path = str(entry.get("path") or "")
            if any(token in path.lower() for token in ("appdata", "temp", "startup")):
                findings.append(_finding("Startup folder item observed", "medium", "startup", {
                    "folder": folder.get("path"),
                    "name": entry.get("name"),
                    "path": path,
                }, "Review startup items in user-writable locations and remove anything not required."))
    for autorun in startup.get("registry_autoruns", []):
        findings.append(_finding("Registry autorun entry observed", "medium", "registry_autoruns", autorun, "Validate whether the autorun is expected and digitally signed."))
    return findings


def _analyze_files(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item in files:
        path = str(item.get("path") or "")
        if any(token in path.lower() for token in ("appdata", "temp", "downloads", "desktop")):
            findings.append(_finding("Recently modified file in user-writable location", "low", "files", item, "Review recently modified files in user-writable locations for suspicious execution or staging."))
    return findings


def _analyze_event_logs(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    messages = []
    for section in ("security_events", "system_events", "powershell_events", "defender_events"):
        for event in data.get(section, []) or []:
            if isinstance(event, dict):
                messages.append((section, str(event.get("Message") or event.get("message") or "")))

    for source, message in messages:
        for title, pattern, severity, reason in SUSPICIOUS_PATTERNS:
            if pattern.search(message):
                findings.append(_finding(title, severity, source, {"message": message[:2000]}, reason))
    return findings


def _event_counts(data: Dict[str, Any]) -> Dict[str, int]:
    return {
        "defender_events": len(data.get("defender_events", []) or []),
        "powershell_events": len(data.get("powershell_events", []) or []),
        "security_events": len(data.get("security_events", []) or []),
        "system_events": len(data.get("system_events", []) or []),
    }


def _powershell_processes(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for process in processes:
        name = str(process.get("name") or "").lower()
        command = _parse_cmdline(process.get("cmdline") or process.get("cmdline_text")).lower()
        if "powershell" in name or name == "pwsh.exe" or "powershell" in command or "pwsh" in command:
            matches.append(process)
    return matches


def build_release1_artifacts(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    processes = data.get("processes", []) or []
    network = data.get("network", []) or []
    services = data.get("services", []) or []
    startup = data.get("startup", {}) or {}
    local_accounts = _local_users(data)
    powershell_processes = _powershell_processes(processes)
    timestamp = data.get("timestamp") or _utc_now()
    hostname = data.get("hostname") or platform.node()

    endpoint_snapshot = data.get("endpoint_snapshot") or collect_endpoint_snapshot(data)
    endpoint_snapshot = {
        **endpoint_snapshot,
        "local_users": local_accounts["users"],
        "local_administrators": local_accounts["administrators"],
        "recent_files": data.get("recent_files", []),
    }

    return {
        "endpoint_snapshot.json": {
            **endpoint_snapshot,
            "artifact": "endpoint_snapshot",
            "requested_scope": data.get("requested_scope", {}),
        },
        "processes.json": {
            "artifact": "processes",
            "collected_at": timestamp,
            "hostname": hostname,
            "process_count": len(processes),
            "processes": processes,
        },
        "network_connections.json": {
            "artifact": "network_connections",
            "collected_at": timestamp,
            "hostname": hostname,
            "connection_count": len(network),
            "connections": network,
        },
        "persistence.json": {
            "artifact": "persistence",
            "collected_at": timestamp,
            "hostname": hostname,
            "services": services,
            "scheduled_tasks": data.get("scheduled_tasks", []) or [],
            "startup_items": startup.get("folders", []) if isinstance(startup, dict) else [],
            "registry_autoruns": startup.get("registry_autoruns", []) if isinstance(startup, dict) else [],
        },
        "event_logs.json": {
            "artifact": "event_logs",
            "collected_at": timestamp,
            "hostname": hostname,
            "event_counts": _event_counts(data),
            "defender_events": data.get("defender_events", []) or [],
            "security_events": data.get("security_events", []) or [],
            "system_events": data.get("system_events", []) or [],
        },
        "powershell_activity.json": {
            "artifact": "powershell_activity",
            "collected_at": timestamp,
            "hostname": hostname,
            "event_count": len(data.get("powershell_events", []) or []),
            "process_count": len(powershell_processes),
            "powershell_events": data.get("powershell_events", []) or [],
            "powershell_processes": powershell_processes,
        },
    }


def write_release1_artifacts(data: Dict[str, Any], output_dir: str | Path) -> List[str]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    written: List[str] = []
    artifacts = build_release1_artifacts(data)
    for filename in RELEASE1_ARTIFACT_FILES:
        payload = artifacts[filename]
        path = output_path / filename
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        written.append(str(path))
    return written


def _build_timeline(findings: List[Dict[str, Any]], data: Dict[str, Any]) -> List[Dict[str, Any]]:
    timeline: List[Dict[str, Any]] = []
    for finding in findings:
        timeline.append({
            "time": finding.get("created_at"),
            "source": finding.get("module"),
            "event": finding.get("title"),
            "severity": finding.get("severity"),
            "host": data.get("hostname") or platform.node(),
            "evidence_ref": finding.get("finding_id"),
        })
    return sorted(timeline, key=lambda item: item.get("time") or "")


def collect_scoped_data(scope: Dict[str, Any] | None = None) -> Dict[str, Any]:
    normalized_scope = _normalize_scope(scope)
    requested = set(normalized_scope.get("collectors") or [])
    data: Dict[str, Any] = {
        "timestamp": _utc_now(),
        "hostname": platform.node(),
        "requested_scope": normalized_scope,
    }

    if "processes" in requested:
        data["processes"] = collect_processes()
    if "network" in requested:
        data["network"] = collect_connections()
    if "services" in requested:
        data["services"] = collect_services()
    if "startup" in requested:
        data["startup"] = collect_startup_items()
    if "scheduled_tasks" in requested:
        data["scheduled_tasks"] = collect_scheduled_tasks()
    if "eventlogs" in requested:
        data["security_events"] = collect_security_events()
        data["system_events"] = collect_system_events()
        data["powershell_events"] = collect_powershell_events()
        data["defender_events"] = collect_defender_events()
    if "software" in requested:
        data["software_inventory"] = collect_installed_software()
    if "users" in requested:
        data["local_users"] = collect_local_users()
    if "files" in requested:
        data["recent_files"] = collect_recent_files()

    data["endpoint_snapshot"] = collect_endpoint_snapshot(data)

    data["collected_sections"] = sorted(
        key for key in data.keys() if key not in {"timestamp", "hostname", "requested_scope", "collected_sections"}
    )
    return data


def analyze_collection(data: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    findings: List[Dict[str, Any]] = []
    findings.extend(_analyze_processes(data.get("processes", [])))
    findings.extend(_analyze_network(data.get("network", [])))
    findings.extend(_analyze_startup(data.get("startup", {})))
    findings.extend(_analyze_files(data.get("recent_files", [])))
    findings.extend(_analyze_event_logs(data))
    findings.sort(key=lambda finding: (_severity_rank(finding.get("severity", "informational")), finding.get("created_at") or ""), reverse=True)
    timeline = _build_timeline(findings, data)
    return findings, timeline


def run_full_collection():
    return collect_scoped_data({"all": True})
