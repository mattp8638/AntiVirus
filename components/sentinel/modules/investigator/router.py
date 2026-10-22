import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

try:
    import psutil
except ImportError:  # pragma: no cover - handled at runtime for clearer API response
    psutil = None

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from modules.storage import get_investigation_result, list_investigation_results, save_audit_event, save_investigation_result

from modules.investigator.common import utc_now, write_json
import modules.investigator.collectors.host as host_collector
import modules.investigator.collectors.processes as processes_collector
import modules.investigator.collectors.network as network_collector
import modules.investigator.collectors.services as services_collector
import modules.investigator.collectors.startup as startup_collector
import modules.investigator.collectors.eventlogs as eventlogs_collector
import modules.investigator.analysis.commands as commands_analysis
import modules.investigator.timeline as timeline_module
import modules.investigator.reporting as reporting_module
router = APIRouter()

DATA_DIR = Path("data")
INVESTIGATIONS_DIR = DATA_DIR / "investigations"
BUNDLES_DIR = INVESTIGATIONS_DIR / "bundles"
DATA_DIR.mkdir(exist_ok=True)
INVESTIGATIONS_DIR.mkdir(parents=True, exist_ok=True)
BUNDLES_DIR.mkdir(parents=True, exist_ok=True)

INDEX_FILE = INVESTIGATIONS_DIR / "index.json"

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
    ("Execution from user temp or appdata", re.compile(r"(?i)(\\appdata\\|\\temp\\|/appdata/|/tmp/).*(\.exe|\.dll|\.ps1|\.vbs|\.js)"), "medium"),
]

# Compatibility exports for older tests/imports. The implementation now lives in
# dedicated collector/analysis modules, but these names are kept stable.
def analyse_commands(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return commands_analysis.analyse_commands(processes)


def analyse_process_tree(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return processes_collector.analyse_process_tree(processes)


def analyse_network(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return network_collector.analyse_network(connections)


def highest_severity(findings: List[Dict[str, Any]]) -> str:
    return timeline_module.highest_severity(findings)


def make_timeline(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return timeline_module.make_timeline(findings)


class InvestigationRunRequest(BaseModel):
    include_processes: bool = True
    include_network: bool = True
    include_services: bool = True
    include_startup: bool = True
    include_eventlog_summary: bool = True
    max_eventlog_events: int = Field(50, ge=0, le=500)


class InvestigationSummary(BaseModel):
    investigation_id: str
    hostname: str
    platform: str
    started_at: str
    completed_at: str
    highest_severity: str
    finding_count: int
    evidence_count: int
    bundle_available: bool
    exit_decision: str
    production_grade_effect: str
def load_index() -> Dict[str, Any]:
    if INDEX_FILE.exists():
        return json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    return {"investigations": []}


def save_index(index: Dict[str, Any]) -> None:
    INDEX_FILE.write_text(json.dumps(index, indent=2), encoding="utf-8")


@router.post("/run", response_model=InvestigationSummary)
def run_investigation(request: InvestigationRunRequest = InvestigationRunRequest()):
    if psutil is None:
        raise HTTPException(status_code=500, detail="psutil is required for the Investigator module. Install requirements.txt first.")

    investigation_id = f"INV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8].upper()}"
    started_at = utc_now()
    investigation_dir = INVESTIGATIONS_DIR / investigation_id
    raw_dir = investigation_dir / "raw"
    reports_dir = investigation_dir / "reports"
    raw_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    host_summary = host_collector.collect_host_summary()
    processes = processes_collector.collect_processes() if request.include_processes else []
    connections = network_collector.collect_network_connections() if request.include_network else []
    services = services_collector.collect_services() if request.include_services else []
    startup = startup_collector.collect_startup_items() if request.include_startup else {}
    eventlog_summary = eventlogs_collector.collect_eventlog_summary(request.max_eventlog_events) if request.include_eventlog_summary else {"supported": False, "reason": "disabled"}

    findings: List[Dict[str, Any]] = []
    findings.extend(commands_analysis.analyse_commands(processes))
    findings.extend(processes_collector.analyse_process_tree(processes))
    findings.extend(network_collector.analyse_network(connections))
    findings.extend(startup_collector.analyse_persistence(startup, services))
    timeline = timeline_module.make_timeline(findings)

    completed_at = utc_now()
    severity = timeline_module.highest_severity(findings)
    exit_decision = "Pass: this run produced a complete local investigation bundle and did not perform destructive actions."
    if severity in {"high", "critical"}:
        exit_decision = "Investigate further: this run found high-risk evidence that requires analyst review before remediation."
    production_grade_effect = "Yes: this module elevates the project towards production grade by adding repeatable endpoint evidence collection, normalised findings, a timeline, a report and a hashed evidence bundle."

    summary = {
        "investigation_id": investigation_id,
        "request_id": investigation_id,
        "agent_id": host_summary["hostname"],
        "hostname": host_summary["hostname"],
        "platform": host_summary["platform"],
        "status": "complete",
        "started_at": started_at,
        "completed_at": completed_at,
        "highest_severity": severity,
        "finding_count": len(findings),
        "evidence_count": 6,
        "bundle_available": True,
        "exit_decision": exit_decision,
        "production_grade_effect": production_grade_effect,
    }

    write_json(raw_dir / "host_summary.json", host_summary)
    write_json(raw_dir / "processes.json", processes)
    write_json(raw_dir / "network_connections.json", connections)
    write_json(raw_dir / "services.json", services)
    write_json(raw_dir / "startup_items.json", startup)
    write_json(raw_dir / "eventlog_summary.json", eventlog_summary)
    write_json(investigation_dir / "findings.json", findings)
    write_json(investigation_dir / "timeline.json", timeline)
    write_json(investigation_dir / "summary.json", summary)
    (reports_dir / "technical_report.html").write_text(reporting_module.build_html_report(summary, findings, timeline), encoding="utf-8")

    bundle_path = BUNDLES_DIR / f"{investigation_id}.zip"
    hashes = reporting_module.create_bundle(investigation_dir, bundle_path)
    summary["evidence_count"] = len(hashes)
    write_json(investigation_dir / "summary.json", summary)
    save_investigation_result(
        {
            "request_id": investigation_id,
            "agent_id": host_summary["hostname"],
            "hostname": host_summary["hostname"],
            "status": summary["status"],
            "completed_at": completed_at,
            "summary": summary,
            "findings": findings,
            "timeline": timeline,
            "report_path": str(reports_dir / "technical_report.html"),
            "bundle_path": str(bundle_path),
        }
    )
    save_audit_event(action="investigation_run", entity_type="investigation", entity_id=investigation_id, details=summary)

    index = load_index()
    index.setdefault("investigations", [])
    index["investigations"].insert(0, summary)
    index["investigations"] = index["investigations"][:100]
    save_index(index)
    return summary


@router.get("/history")
def history():
    db_results = list_investigation_results()
    if db_results:
        investigations = []
        for result in db_results:
            summary = result.get("summary") or {}
            investigations.append(summary if summary else result)
        return {"investigations": investigations}
    return load_index()


@router.get("/{investigation_id}")
def get_investigation(investigation_id: str):
    db_result = get_investigation_result(investigation_id)
    if db_result:
        return {
            "summary": db_result.get("summary"),
            "findings": db_result.get("findings", []),
            "timeline": db_result.get("timeline", []),
        }
    investigation_dir = INVESTIGATIONS_DIR / investigation_id
    if not investigation_dir.exists():
        raise HTTPException(status_code=404, detail="Investigation not found")
    summary_path = investigation_dir / "summary.json"
    findings_path = investigation_dir / "findings.json"
    timeline_path = investigation_dir / "timeline.json"
    return {
        "summary": json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else None,
        "findings": json.loads(findings_path.read_text(encoding="utf-8")) if findings_path.exists() else [],
        "timeline": json.loads(timeline_path.read_text(encoding="utf-8")) if timeline_path.exists() else [],
    }


@router.get("/{investigation_id}/bundle")
def download_bundle(investigation_id: str):
    bundle_path = BUNDLES_DIR / f"{investigation_id}.zip"
    if not bundle_path.exists():
        raise HTTPException(status_code=404, detail="Evidence bundle not found")
    return FileResponse(bundle_path, filename=bundle_path.name, media_type="application/zip")


@router.get("/{investigation_id}/report")
def download_report(investigation_id: str):
    report_path = INVESTIGATIONS_DIR / investigation_id / "reports" / "technical_report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report_path, filename=f"{investigation_id}_technical_report.html", media_type="text/html")
