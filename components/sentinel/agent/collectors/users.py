from __future__ import annotations

import subprocess
from typing import Dict, List


def _run(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, shell=False)
        return completed.stdout.strip()
    except Exception:
        return ""


def _parse_lines(output: str) -> List[str]:
    entries: List[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("---")
            or stripped.startswith("The command")
            or stripped.startswith("Alias name")
            or stripped.startswith("Comment")
            or stripped.startswith("Members")
            or stripped.startswith("User accounts")
        ):
            continue
        entries.extend(part for part in stripped.split() if part)
    return entries


def collect_local_users() -> Dict[str, List[str]]:
    users_output = _run(["cmd", "/c", "net", "user"])
    admins_output = _run(["cmd", "/c", "net", "localgroup", "administrators"])
    return {
        "users": _parse_lines(users_output),
        "administrators": _parse_lines(admins_output),
    }
