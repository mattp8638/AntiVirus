import json
import platform
import subprocess
import csv
import io
from typing import Any, Dict, List

try:
    import psutil
except Exception:
    psutil = None


def run_ps(cmd: str, timeout: int = 30) -> str:
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return (completed.stdout or completed.stderr or "").strip()
    except Exception:
        return ""


def _as_list(output: str) -> List[Dict[str, Any]]:
    if not output.strip():
        return []
    try:
        parsed = json.loads(output)
        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return parsed
    except Exception:
        pass
    return [{"raw": output}]


def collect_scheduled_tasks() -> List[Dict[str, Any]]:
    if platform.system().lower() != "windows":
        return []
    try:
        completed = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=25,
            shell=False,
        )
        if completed.stdout.strip():
            return list(csv.DictReader(io.StringIO(completed.stdout)))
    except Exception:
        pass
    fallback = run_ps("schtasks /query /fo LIST /v", timeout=20)
    return [{"raw": fallback}] if fallback else []


def collect_services() -> List[Dict[str, Any]]:
    if platform.system().lower() != "windows":
        return []
    if psutil is not None:
        services: List[Dict[str, Any]] = []
        try:
            for service in psutil.win_service_iter():
                try:
                    data = service.as_dict()
                    services.append({
                        "name": data.get("name"),
                        "display_name": data.get("display_name"),
                        "status": data.get("status"),
                        "start_type": data.get("start_type"),
                        "username": data.get("username"),
                        "binpath": data.get("binpath"),
                        "pid": data.get("pid"),
                    })
                except Exception:
                    continue
            return services
        except Exception:
            pass
    command = (
        "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,Status,StartMode,"
        "StartName,PathName,ProcessId | ConvertTo-Json -Depth 4"
    )
    output = run_ps(command, timeout=20)
    if output.strip():
        return _as_list(output)
    fallback = run_ps("Get-Service | Select-Object Name,Status,StartType | ConvertTo-Json -Depth 4", timeout=20)
    return _as_list(fallback)
