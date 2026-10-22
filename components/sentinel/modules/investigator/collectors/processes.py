from datetime import datetime, timezone
from typing import List, Dict, Optional
from uuid import uuid4
import socket
try:
    import psutil
except Exception:
    psutil = None


def collect_processes() -> List[Dict[str, Optional[str]]]:
    if psutil is None:
        return []
    processes: List[Dict[str, Optional[str]]] = []
    attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "status"]
    for proc in psutil.process_iter(attrs=attrs):
        try:
            info = proc.info
            cmdline = info.get("cmdline") or []
            processes.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "exe": info.get("exe"),
                "cmdline": cmdline,
                "cmdline_text": " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline),
                "username": info.get("username"),
                "create_time": datetime.fromtimestamp(info.get("create_time"), timezone.utc).isoformat() if info.get("create_time") else None,
                "status": info.get("status"),
            })
        except (Exception):
            continue
    return processes


def analyse_process_tree(processes: List[Dict]) -> List[Dict]:
    findings = []
    # Lightweight local logic kept here to avoid external dependencies
    by_pid = {proc.get("pid"): proc for proc in processes}
    for proc in processes:
        parent = by_pid.get(proc.get("ppid"))
        if not parent:
            continue
        child_name = (proc.get("name") or "").lower()
        parent_name = (parent.get("name") or "").lower()
        # Simple heuristics kept for now; can rely on shared patterns later
        risky_parent_child = [
            ("Office spawning shell or script interpreter", {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}, {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}, "critical"),
            ("Browser spawning shell or script interpreter", {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"}, {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}, "high"),
        ]
        for title, parent_set, child_set, severity in risky_parent_child:
            if parent_name in parent_set and child_name in child_set:
                findings.append({
                    "finding_id": f"FND-{uuid4().hex[:10].upper()}",
                    "module": "Process Tree Viewer",
                    "title": title,
                    "severity": severity,
                    "confidence": "medium",
                    "asset": socket.gethostname(),
                    "description": f"Suspicious parent/child relationship observed: {parent_name} -> {child_name}.",
                    "evidence": {
                        "parent_pid": parent.get("pid"),
                        "parent_name": parent.get("name"),
                        "parent_command": parent.get("cmdline_text"),
                        "child_pid": proc.get("pid"),
                        "child_name": proc.get("name"),
                        "child_command": proc.get("cmdline_text"),
                    },
                    "recommended_action": "Confirm whether this process chain is expected. If unauthorised, collect evidence and contain the endpoint.",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })
    return findings
