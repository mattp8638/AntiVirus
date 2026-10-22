import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from modules.investigator.collectors.services import collect_services
from modules.investigator.collectors.startup import collect_startup_items
from modules.storage import save_audit_event

router = APIRouter()

RISKY_PATH_MARKERS = ["\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "/tmp/", "/var/tmp/", "/.config/"]
SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".scr", ".lnk"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".com", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd"}


class PersistenceScanRequest(BaseModel):
    include_services: bool = True
    include_startup: bool = True
    include_scheduled_tasks: bool = True
    include_powershell_profiles: bool = True
    include_browser_extensions: bool = True


def utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def sha256_file(path: str) -> Optional[str]:
    try:
        candidate = Path(path)
        if not candidate.exists() or not candidate.is_file():
            return None
        digest = hashlib.sha256()
        with open(candidate, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


def file_times(path: str) -> Dict[str, Optional[str]]:
    try:
        candidate = Path(path)
        stat = candidate.stat()
        return {
            "created_at": datetime.utcfromtimestamp(getattr(stat, "st_ctime", 0)).isoformat() + "Z",
            "modified_at": datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z",
        }
    except Exception:
        return {"created_at": None, "modified_at": None}


def risk_for_path(path: str, command: str = "") -> Dict[str, str]:
    raw = f"{path} {command}".lower()
    reasons = []
    severity = "low"
    if any(marker in raw for marker in RISKY_PATH_MARKERS):
        severity = "high" if "temp" in raw else "medium"
        reasons.append("references a user-writable or commonly abused path")
    if any(raw.endswith(ext) or f"{ext} " in raw for ext in SCRIPT_EXTENSIONS):
        severity = "high" if severity in {"medium", "high"} else "medium"
        reasons.append("uses a script or executable file type often abused for persistence")
    if any(token in raw for token in ["powershell", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil"]):
        severity = "high"
        reasons.append("launches a living-off-the-land binary or script interpreter")
    if not reasons:
        reasons.append("persistence item observed; validate that it is expected")
    return {"severity": severity, "reason": "; ".join(reasons)}


def normalise_item(*, name: str, item_type: str, location: str, path: str = "", command: str = "", publisher: str = "unknown", source: str = "local") -> Dict[str, Any]:
    risk = risk_for_path(path, command)
    times = file_times(path) if path else {"created_at": None, "modified_at": None}
    return {
        "name": name or "Unnamed persistence item",
        "type": item_type,
        "location": location,
        "path": path or "not available",
        "command": command or path or "not available",
        "publisher": publisher or "unknown",
        "signature": "not checked",
        "sha256": sha256_file(path) if path else None,
        "created_at": times.get("created_at"),
        "modified_at": times.get("modified_at"),
        "risk_rating": risk["severity"],
        "reason_flagged": risk["reason"],
        "recommended_action": "Validate ownership, signature and business need. Preserve evidence before disabling or removing suspicious persistence.",
        "source": source,
    }


def run_command(command: List[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return (result.stdout or result.stderr or "").strip()
    except Exception as exc:
        return f"collector_error: {exc}"


def collect_scheduled_tasks() -> List[Dict[str, Any]]:
    if platform.system().lower() != "windows":
        return []
    output = run_command(["schtasks", "/query", "/fo", "LIST", "/v"])
    tasks: List[Dict[str, Any]] = []
    current: Dict[str, str] = {}
    for line in output.splitlines():
        if not line.strip():
            if current:
                tasks.append(current)
                current = {}
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()
    if current:
        tasks.append(current)
    normalised = []
    for task in tasks[:300]:
        name = task.get("TaskName") or task.get("Task To Run") or "Scheduled task"
        command = task.get("Task To Run") or ""
        normalised.append(normalise_item(name=name, item_type="scheduled_task", location=name, command=command, path=command.split(" ")[0].strip('"') if command else "", source="schtasks"))
    return normalised


def collect_powershell_profiles() -> List[Dict[str, Any]]:
    paths = []
    home = Path.home()
    if platform.system().lower() == "windows":
        documents = Path(os.environ.get("USERPROFILE", str(home))) / "Documents"
        paths.extend([
            documents / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1",
            documents / "PowerShell" / "Microsoft.PowerShell_profile.ps1",
            Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "PowerShell" / "7" / "profile.ps1",
        ])
    else:
        paths.extend([home / ".config" / "powershell" / "Microsoft.PowerShell_profile.ps1"])
    items = []
    for path in paths:
        if path.exists():
            items.append(normalise_item(name=path.name, item_type="powershell_profile", location=str(path.parent), path=str(path), command=str(path), source="filesystem"))
    return items


def collect_browser_extensions() -> List[Dict[str, Any]]:
    candidates: List[Path] = []
    home = Path.home()
    if platform.system().lower() == "windows":
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        roaming = Path(os.environ.get("APPDATA", ""))
        candidates.extend([
            local / "Google" / "Chrome" / "User Data" / "Default" / "Extensions",
            local / "Microsoft" / "Edge" / "User Data" / "Default" / "Extensions",
            roaming / "Mozilla" / "Firefox" / "Profiles",
        ])
    else:
        candidates.extend([home / ".config" / "google-chrome" / "Default" / "Extensions", home / ".mozilla" / "firefox"])
    items = []
    for root in candidates:
        if not root.exists():
            continue
        try:
            for child in list(root.iterdir())[:100]:
                if child.is_dir():
                    items.append(normalise_item(name=child.name, item_type="browser_extension", location=str(root), path=str(child), command=str(child), source="browser_profile"))
        except Exception:
            continue
    return items


def collect_service_items() -> List[Dict[str, Any]]:
    items = []
    for service in collect_services():
        command = service.get("binpath") or ""
        items.append(normalise_item(
            name=service.get("display_name") or service.get("name") or "Windows service",
            item_type="service",
            location=service.get("start_type") or "service_control_manager",
            path=command.split(" ")[0].strip('"') if command else "",
            command=command,
            publisher="unknown",
            source="service_control_manager",
        ))
    return items


def collect_startup_items_normalised() -> List[Dict[str, Any]]:
    startup = collect_startup_items()
    items = []
    for folder in startup.get("startup_folders", []):
        for entry in folder.get("items", []):
            path = entry.get("path", "")
            items.append(normalise_item(name=entry.get("name"), item_type="startup_folder", location=folder.get("folder", "startup folder"), path=path, command=path, source="startup_folder"))
    for index, output in enumerate(startup.get("registry_run_keys", [])):
        location = f"registry_run_key_{index + 1}"
        for line in str(output).splitlines():
            if "REG_" in line:
                parts = line.split()
                name = parts[0] if parts else "Registry autorun"
                command = " ".join(parts[2:]) if len(parts) > 2 else line
                items.append(normalise_item(name=name, item_type="registry_autorun", location=location, path=command.split(" ")[0].strip('"'), command=command, source="registry"))
    return items


def summarise(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    high = len([item for item in items if item.get("risk_rating") == "high"])
    medium = len([item for item in items if item.get("risk_rating") == "medium"])
    low = len([item for item in items if item.get("risk_rating") == "low"])
    verdict = "No persistence items collected"
    severity = "low"
    if high:
        verdict = "High-risk persistence requires review"
        severity = "high"
    elif medium:
        verdict = "Persistence items require validation"
        severity = "medium"
    elif items:
        verdict = "Persistence items observed"
    return {"verdict": verdict, "severity": severity, "total": len(items), "high": high, "medium": medium, "low": low}


@router.post("/scan")
def scan_persistence(request: PersistenceScanRequest = PersistenceScanRequest()):
    items: List[Dict[str, Any]] = []
    if request.include_startup:
        items.extend(collect_startup_items_normalised())
    if request.include_services:
        items.extend(collect_service_items())
    if request.include_scheduled_tasks:
        items.extend(collect_scheduled_tasks())
    if request.include_powershell_profiles:
        items.extend(collect_powershell_profiles())
    if request.include_browser_extensions:
        items.extend(collect_browser_extensions())
    summary = summarise(items)
    payload = {
        "status": "complete",
        "summary": summary,
        "risk_score": max(0, 100 - (summary["high"] * 20) - (summary["medium"] * 8) - (summary["low"] * 2)),
        "severity": summary["severity"],
        "findings": items,
        "evidence": items,
        "timeline": [{"timestamp": item.get("modified_at") or item.get("created_at"), "source": item.get("type"), "event": item.get("name"), "severity": item.get("risk_rating"), "evidence_ref": item.get("sha256") or item.get("path")} for item in items if item.get("modified_at") or item.get("created_at")],
        "recommended_actions": [
            "Review all high and medium persistence items before removal.",
            "Preserve suspicious files and command lines as evidence.",
            "Validate publisher/signature with trusted tooling where available.",
            "Disable unauthorised persistence only after evidence is captured.",
        ],
        "metadata": {"generated_at": utc_now(), "host": platform.node(), "platform": platform.platform()},
    }
    save_audit_event(action="persistence_scan_run", entity_type="host", entity_id=platform.node(), details={"finding_count": len(items), "severity": summary["severity"]})
    return payload


@router.get("/sample")
def sample_persistence_result():
    sample_items = [
        normalise_item(name="Example startup item", item_type="startup_folder", location="Startup", path=r"C:\Users\Public\example.ps1", command=r"powershell.exe -ExecutionPolicy Bypass C:\Users\Public\example.ps1", source="sample"),
        normalise_item(name="Example service", item_type="service", location="auto", path=r"C:\ProgramData\svc.exe", command=r"C:\ProgramData\svc.exe", source="sample"),
    ]
    summary = summarise(sample_items)
    return {"status": "sample", "summary": summary, "findings": sample_items, "recommended_actions": ["Use /scan for live local collection."]}
