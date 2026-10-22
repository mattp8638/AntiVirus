import re
from typing import List, Dict
from uuid import uuid4
import socket
from modules.investigator.common import SUSPICIOUS_COMMAND_PATTERNS, utc_now


def analyse_commands(processes: List[Dict]) -> List[Dict]:
    findings: List[Dict] = []
    for proc in processes:
        command = proc.get("cmdline_text") or ""
        if not command:
            continue
        for title, pattern, severity in SUSPICIOUS_COMMAND_PATTERNS:
            if pattern.search(command):
                findings.append({
                    "finding_id": f"FND-{uuid4().hex[:10].upper()}",
                    "module": "Suspicious Command Line Analyser",
                    "title": title,
                    "severity": severity,
                    "confidence": "medium",
                    "asset": socket.gethostname(),
                    "description": f"Suspicious command-line pattern matched process {proc.get('name')} with PID {proc.get('pid')}.",
                    "evidence": {
                        "pid": proc.get("pid"),
                        "process": proc.get("name"),
                        "path": proc.get("exe"),
                        "command": command,
                        "rule": title,
                    },
                    "recommended_action": "Validate whether the command was authorised. If not, isolate the host and preserve evidence before remediation.",
                    "created_at": utc_now(),
                })
    return findings
