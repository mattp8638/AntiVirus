from pathlib import Path
import os
from typing import Dict, Any
from modules.investigator.common import safe_run
from pathlib import Path


def collect_startup_items() -> Dict[str, Any]:
    startup: Dict[str, Any] = {"registry_run_keys": [], "startup_folders": []}
    system = os.sys.platform
    # Use platform.system like original, but keep simple cross-platform handling
    try:
        import platform
        system_name = platform.system().lower()
    except Exception:
        system_name = system
    if system_name == "windows":
        registry_commands = [
            ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
            ["reg", "query", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"],
            ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"],
            ["reg", "query", r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"],
        ]
        startup["registry_run_keys"] = [safe_run(command) for command in registry_commands]
        folders = [
            Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
            Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        ]
    else:
        folders = [Path.home() / ".config" / "autostart", Path("/etc/xdg/autostart")]
    for folder in folders:
        if folder and folder.exists():
            startup["startup_folders"].append({
                "folder": str(folder),
                "items": [{"name": item.name, "path": str(item), "is_file": item.is_file()} for item in folder.iterdir()],
            })
    return startup


def analyse_persistence(startup: Dict[str, Any], services: list) -> list:
    findings = []
    risky_paths = ["\\appdata\\", "\\temp\\", "/tmp/", "/appdata/"]
    for folder in startup.get("startup_folders", []):
        for item in folder.get("items", []):
            path = item.get("path", "")
            if any(fragment in path.lower() for fragment in risky_paths):
                findings.append({
                    "finding_id": f"FND-UNKNOWN",
                    "module": "Persistence Scanner",
                    "title": "Startup item in user-writable location",
                    "severity": "medium",
                    "confidence": "medium",
                    "asset": None,
                    "description": "A startup item exists in a user-writable or temporary path.",
                    "evidence": item,
                    "recommended_action": "Confirm whether the startup item is expected. Disable and preserve it if unauthorised.",
                    "created_at": None,
                })
    for service in services:
        binpath = (service.get("binpath") or "").lower()
        if any(fragment in binpath for fragment in risky_paths):
            findings.append({
                "finding_id": f"FND-UNKNOWN",
                "module": "Persistence Scanner",
                "title": "Service binary path in user-writable location",
                "severity": "high",
                "confidence": "medium",
                "asset": None,
                "description": f"Service {service.get('name')} points to a binary in a user-writable or temporary location.",
                "evidence": service,
                "recommended_action": "Review service ownership, signature and creation history. Disable only after evidence is preserved.",
                "created_at": None,
            })
    return findings
