import subprocess
import json
import platform
import re
from typing import Any, Dict, List


def _as_list(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return value
    return []


def run_ps_json(cmd: str, timeout: int = 20) -> List[Dict[str, Any]]:
    if platform.system().lower() != "windows":
        return []
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        if not result.stdout.strip():
            return []
        return _as_list(json.loads(result.stdout))
    except Exception:
        return []


def _eventlog_query(log_name: str, limit: int) -> str:
    return (
        f"Get-WinEvent -LogName '{log_name}' -MaxEvents {limit} -ErrorAction SilentlyContinue "
        "| Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message "
        "| ConvertTo-Json -Depth 4"
    )


def _parse_wevtutil_text(log_name: str, output: str) -> List[Dict[str, Any]]:
    blocks: List[str] = []
    current: List[str] = []
    for line in output.splitlines():
        if line.startswith("Event[") and current:
            blocks.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current).strip())

    events: List[Dict[str, Any]] = []
    for block in blocks:
        if not block:
            continue
        event_id = re.search(r"Event ID:\s+(.+)", block)
        provider = re.search(r"Provider Name:\s+(.+)", block)
        level = re.search(r"Level:\s+(.+)", block)
        date = re.search(r"Date:\s+(.+)", block)
        events.append({
            "LogName": log_name,
            "Id": event_id.group(1).strip() if event_id else None,
            "ProviderName": provider.group(1).strip() if provider else None,
            "LevelDisplayName": level.group(1).strip() if level else None,
            "TimeCreated": date.group(1).strip() if date else None,
            "Message": block,
        })
    return events


def run_wevtutil(log_name: str, limit: int = 200, timeout: int = 10) -> List[Dict[str, Any]]:
    if platform.system().lower() != "windows" or limit <= 0:
        return []
    try:
        completed = subprocess.run(
            ["wevtutil", "qe", log_name, f"/c:{limit}", "/rd:true", "/f:text"],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return []
        return _parse_wevtutil_text(log_name, completed.stdout)
    except Exception:
        return []


def collect_security_events(limit=200):
    events = run_wevtutil("Security", limit)
    if events:
        return events
    cmd = _eventlog_query("Security", limit)
    return run_ps_json(cmd)


def collect_powershell_events(limit=200):
    operational = run_wevtutil("Microsoft-Windows-PowerShell/Operational", limit)
    if not operational:
        operational = run_ps_json(_eventlog_query("Microsoft-Windows-PowerShell/Operational", limit))
    classic = run_wevtutil("Windows PowerShell", limit)
    if not classic:
        classic = run_ps_json(_eventlog_query("Windows PowerShell", limit))
    return operational + classic


def collect_defender_events(limit=100):
    events = run_wevtutil("Microsoft-Windows-Windows Defender/Operational", limit)
    if not events:
        events = run_ps_json(_eventlog_query("Microsoft-Windows-Windows Defender/Operational", limit))
    if events:
        return events
    cmd = (
        "Get-MpThreatDetection -ErrorAction SilentlyContinue "
        "| Select-Object InitialDetectionTime,ThreatName,ActionSuccess,Resources "
        "| ConvertTo-Json -Depth 4"
    )
    return run_ps_json(cmd)


def collect_system_events(limit=200):
    events = run_wevtutil("System", limit)
    if events:
        return events
    cmd = _eventlog_query("System", limit)
    return run_ps_json(cmd)
