import json
import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()

DEFAULT_SCANNER_PATH = Path("external") / "av" / "windows-scanner" / "bin" / "fenrir-scannercli.exe"
SCAN_RESULTS_DIR = Path("data") / "av_scans"
SCAN_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

class AVScanRequest(BaseModel):
    path: str = Field(..., description="File or directory path to scan on the local Windows endpoint/server.")
    no_remediation: bool = True
    no_telemetry: bool = False
    exclusions: List[str] = Field(default_factory=list)
    realtime_operation: Optional[str] = Field(default=None, description="Optional create/open/write/execute/rename/section-map simulation.")

class AVFinding(BaseModel):
    path: str = ""
    sizeBytes: Optional[int] = None
    disposition: str = "review"
    tacticId: str = ""
    techniqueId: str = ""
    confidence: Optional[int] = None
    sha256: str = ""
    contentType: str = ""
    reputation: str = ""
    signer: str = ""
    heuristicScore: Optional[int] = None
    remediationStatus: str = "not_applied"
    quarantineRecordId: str = ""
    evidenceRecordId: str = ""
    quarantinedPath: str = ""
    remediationError: str = ""


def configured_scanner_path() -> Path:
    configured = os.getenv("FENRIR_SCANNERCLI_PATH")
    return Path(configured) if configured else DEFAULT_SCANNER_PATH


def scanner_available() -> Dict[str, Any]:
    scanner = configured_scanner_path()
    return {
        "available": scanner.exists(),
        "configured_path": str(scanner),
        "platform": platform.system(),
        "mode": "external_cli",
        "expected_binary": "fenrir-scannercli.exe",
    }


def build_command(request: AVScanRequest) -> List[str]:
    scanner = configured_scanner_path()
    command = [str(scanner), "--json"]
    if request.no_remediation:
        command.append("--no-remediation")
    if request.no_telemetry:
        command.append("--no-telemetry")
    for exclusion in request.exclusions:
        command.extend(["--exclude", exclusion])
    if request.realtime_operation:
        command.extend(["--realtime-op", request.realtime_operation])
    command.extend(["--path", request.path])
    return command


def parse_findings(stdout: str) -> List[Dict[str, Any]]:
    if not stdout.strip():
        return []
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=502, detail=f"Scanner did not return valid JSON: {exc}") from exc
    findings = parsed.get("findings", []) if isinstance(parsed, dict) else []
    return findings if isinstance(findings, list) else []


def normalise_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    finding = AVFinding(**{key: raw.get(key) for key in AVFinding.model_fields.keys() if key in raw}).model_dump()
    disposition = str(finding.get("disposition") or "review").lower()
    remediation = str(finding.get("remediationStatus") or "not_applied").lower()
    if disposition in {"block", "quarantine", "deny"}:
        severity = "high"
    elif disposition in {"review", "warn"}:
        severity = "medium"
    else:
        severity = "low"
    finding["severity"] = severity
    finding["status"] = remediation
    finding["summary"] = f"{disposition} verdict for {finding.get('path') or 'unknown file'}"
    finding["recommended_action"] = "Review the finding, validate whether the file is expected, and keep remediation disabled unless you intentionally want quarantine."
    if remediation == "quarantined":
        finding["recommended_action"] = "File was quarantined by the AV engine. Review evidence and restore only if confirmed safe."
    return finding


@router.get("/status")
def av_status():
    status = scanner_available()
    status["message"] = "AV scanner bridge is configured." if status["available"] else "AV scanner binary not found. Build/copy fenrir-scannercli.exe or set FENRIR_SCANNERCLI_PATH."
    return status


@router.post("/scan")
def scan(request: AVScanRequest):
    status = scanner_available()
    if platform.system().lower() != "windows":
        raise HTTPException(status_code=400, detail="The imported AV scanner CLI is Windows-specific. Use this bridge on a Windows host or Windows agent.")
    if not status["available"]:
        raise HTTPException(status_code=404, detail=status["message"] if "message" in status else "Scanner binary not found")

    target = Path(request.path)
    if not target.exists() and not request.realtime_operation:
        raise HTTPException(status_code=404, detail="Scan target does not exist")

    command = build_command(request)
    started = datetime.utcnow().isoformat() + "Z"
    completed_process = subprocess.run(command, capture_output=True, text=True, timeout=900)
    completed = datetime.utcnow().isoformat() + "Z"
    findings = [normalise_finding(item) for item in parse_findings(completed_process.stdout)]
    result = {
        "status": "findings_detected" if findings else "clean",
        "scanner": "fenrir-scannercli",
        "scanner_path": status["configured_path"],
        "target": request.path,
        "started_at": started,
        "completed_at": completed,
        "exit_code": completed_process.returncode,
        "finding_count": len(findings),
        "findings": findings,
        "stderr": completed_process.stderr[-2000:] if completed_process.stderr else "",
        "remediation_mode": "disabled" if request.no_remediation else "enabled",
    }
    output_path = SCAN_RESULTS_DIR / f"av-scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["stored_result"] = str(output_path)
    return result
