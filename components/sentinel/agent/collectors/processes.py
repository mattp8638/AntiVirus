from datetime import datetime, timezone
from typing import Any, Dict, List

import psutil


def _cmdline_text(cmdline: Any) -> str:
    if isinstance(cmdline, list):
        return " ".join(str(part) for part in cmdline if part)
    return str(cmdline or "")


def _created_at(value: Any) -> str | None:
    try:
        if value:
            return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    except Exception:
        pass
    return None


def collect_processes() -> List[Dict[str, Any]]:
    procs: List[Dict[str, Any]] = []
    attrs = ["pid", "ppid", "name", "cmdline", "username", "create_time", "exe", "status", "cwd"]
    for proc in psutil.process_iter(attrs):
        try:
            info = dict(proc.info)
            cmdline = info.get("cmdline") or []
            info["cmdline"] = cmdline
            info["cmdline_text"] = _cmdline_text(cmdline)
            info["parent_pid"] = info.get("ppid")
            info["create_time_utc"] = _created_at(info.get("create_time"))
            procs.append(info)
        except Exception:
            continue
    return procs
