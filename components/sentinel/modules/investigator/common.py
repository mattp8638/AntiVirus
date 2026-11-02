import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
from typing import Any, Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_run(command: List[str], timeout: int = 10) -> Dict[str, Any]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, shell=False)
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-20000:],
            "stderr": completed.stderr[-10000:],
        }
    except FileNotFoundError:
        return {"command": command, "error": "command_not_found"}
    except subprocess.TimeoutExpired:
        return {"command": command, "error": "timeout"}
    except Exception as exc:
        return {"command": command, "error": type(exc).__name__, "detail": str(exc)}


# Analysis patterns and helpers
import re
from uuid import uuid4
import socket

SUSPICIOUS_COMMAND_PATTERNS = [
    ("Encoded PowerShell command", re.compile(r"(?i)(powershell|pwsh).*\s-(enc|encodedcommand)\b"), "critical"),
    ("PowerShell execution policy bypass", re.compile(r"(?i)(powershell|pwsh).*executionpolicy\s+bypass"), "high"),
    ("PowerShell hidden window", re.compile(r"(?i)(powershell|pwsh).*(windowstyle\s+hidden|-w\s+hidden)"), "high"),
    ("PowerShell web download cradle", re.compile(r"(?i)(downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\b|wget\b)"), "high"),
    ("Invoke-Expression usage", re.compile(r"(?i)(invoke-expression|\biex\b)"), "high"),
    ("Certificate utility download behaviour", re.compile(r"(?i)certutil.*(-urlcache|-split|-f).*https?://"), "high"),
    ("Regsvr32 remote script execution pattern", re.compile(r"(?i)regsvr32.*(scrobj\.dll|/i:https?://)"), "critical"),
    ("MSHTA remote execution pattern", re.compile(r"(?i)mshta\s+https?://"), "critical"),
    ("Rundll32 suspicious JavaScript execution", re.compile(r"(?i)rundll32.*javascript:"), "critical"),
    ("Shadow copy deletion", re.compile(r"(?i)(vssadmin|wmic).*shadow.*delete"), "critical"),
    ("Recovery options tampering", re.compile(r"(?i)bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"), "critical"),
    ("Execution from user temp or appdata", re.compile(r"(?i)(\\appdata\\|\\temp\\|/appdata/|/tmp/).*\.(exe|dll|ps1|vbs|js)"), "medium"),
]

SUSPICIOUS_PARENT_CHILD = [
    ("Office spawning shell or script interpreter", {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}, {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}, "critical"),
    ("Browser spawning shell or script interpreter", {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"}, {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}, "high"),
    ("Script interpreter spawning system tool", {"wscript.exe", "cscript.exe", "mshta.exe"}, {"powershell.exe", "cmd.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe"}, "high"),
]

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
