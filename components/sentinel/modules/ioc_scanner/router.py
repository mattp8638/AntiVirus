import hashlib
import ipaddress
import os
import platform
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from modules.ioc_validator.router import extract_iocs, classify, IOCType
from modules.investigator.collectors.network import collect_network_connections
from modules.investigator.collectors.processes import collect_processes
from modules.investigator.collectors.startup import collect_startup_items
from modules.storage import save_audit_event

router = APIRouter()

DEFAULT_SCAN_PATHS = [str(Path.home() / "Downloads"), str(Path.home() / "Desktop"), str(Path.home() / "Documents")]
MAX_FILE_SIZE = 25 * 1024 * 1024
TEXT_EXTENSIONS = {".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".url", ".ini", ".conf", ".yaml", ".yml"}


class IOCScanRequest(BaseModel):
    indicators: str = Field(..., description="Raw IOC list, one per line or pasted text")
    scan_paths: List[str] = Field(default_factory=lambda: DEFAULT_SCAN_PATHS)
    include_files: bool = True
    include_processes: bool = True
    include_network: bool = True
    include_registry_autoruns: bool = True
    include_dns_cache: bool = True
    include_recent_logs: bool = True
    max_files: int = 1500


def utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def sha256_file(path: Path) -> Optional[str]:
    try:
        if not path.exists() or not path.is_file() or path.stat().st_size > MAX_FILE_SIZE:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


def safe_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return ""
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")[:1024 * 1024]
    except Exception:
        return ""


def build_indicator_objects(raw: str) -> List[Dict[str, str]]:
    values = extract_iocs(raw)
    objects = []
    for value in values:
        ioc_type = classify(value)
        if ioc_type == IOCType.unknown:
            continue
        objects.append({"value": value, "type": str(ioc_type.value if hasattr(ioc_type, "value") else ioc_type), "normalised": value.lower()})
    return objects


def match_text(text: str, indicators: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    haystack = str(text or "").lower()
    hits = []
    for indicator in indicators:
        if indicator["normalised"] in haystack:
            hits.append(indicator)
    return hits


def severity_for(indicator_type: str, source: str) -> str:
    if indicator_type == "hash":
        return "high"
    if source in {"process", "network", "registry_autorun"}:
        return "high" if indicator_type in {"url", "domain", "ip"} else "medium"
    return "medium"


def finding(indicator: Dict[str, str], source: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    severity = severity_for(indicator["type"], source)
    return {
        "finding_id": "IOC-" + hashlib.sha1(f"{indicator['value']}{source}{evidence}".encode("utf-8", errors="ignore")).hexdigest()[:12].upper(),
        "indicator": indicator["value"],
        "indicator_type": indicator["type"],
        "source": source,
        "severity": severity,
        "title": f"IOC match in {source}",
        "reason": f"The {indicator['type']} indicator was observed in {source} evidence.",
        "evidence": evidence,
        "recommended_action": "Validate the IOC source and confidence, preserve evidence, then investigate related process, user and network activity before containment.",
        "timestamp": utc_now(),
    }


def scan_files(indicators: List[Dict[str, str]], roots: List[str], max_files: int) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    scanned = 0
    hash_indicators = {item["normalised"]: item for item in indicators if item["type"] == "hash"}
    for root in roots:
        root_path = Path(root).expanduser()
        if not root_path.exists():
            continue
        for current_root, _, files in os.walk(root_path):
            for name in files:
                if scanned >= max_files:
                    return findings
                scanned += 1
                path = Path(current_root) / name
                try:
                    stat = path.stat()
                    if stat.st_size > MAX_FILE_SIZE:
                        continue
                    file_hash = sha256_file(path)
                    if file_hash and file_hash.lower() in hash_indicators:
                        findings.append(finding(hash_indicators[file_hash.lower()], "file_hash", {"path": str(path), "sha256": file_hash, "size_bytes": stat.st_size}))
                    text_hits = match_text(str(path) + "\n" + safe_text(path), [item for item in indicators if item["type"] != "hash"])
                    for hit in text_hits:
                        findings.append(finding(hit, "file_content_or_path", {"path": str(path), "sha256": file_hash, "size_bytes": stat.st_size}))
                except Exception:
                    continue
    return findings


def scan_processes(indicators: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        processes = collect_processes()
    except Exception:
        processes = []
    for proc in processes:
        text = " ".join(str(proc.get(k, "")) for k in ["name", "pid", "exe", "path", "cmdline", "command_line", "username", "parent_name"])
        for hit in match_text(text, indicators):
            findings.append(finding(hit, "process", proc))
    return findings


def scan_network(indicators: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        connections = collect_network_connections()
    except Exception:
        connections = []
    for conn in connections:
        text = " ".join(str(conn.get(k, "")) for k in ["remote_ip", "remote_address", "local_address", "process_name", "process_path"])
        for hit in match_text(text, [item for item in indicators if item["type"] in {"ip", "domain", "url", "hash"}]):
            findings.append(finding(hit, "network", conn))
    return findings


def scan_registry_autoruns(indicators: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        startup = collect_startup_items()
    except Exception:
        startup = {}
    for output in startup.get("registry_run_keys", []):
        for hit in match_text(str(output), indicators):
            findings.append(finding(hit, "registry_autorun", {"registry_output": str(output)[:3000]}))
    for folder in startup.get("startup_folders", []):
        for item in folder.get("items", []):
            for hit in match_text(str(item), indicators):
                findings.append(finding(hit, "startup_folder", item))
    return findings


def run_command(command: List[str]) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return ""


def scan_dns_cache(indicators: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    if platform.system().lower() != "windows":
        return []
    output = run_command(["ipconfig", "/displaydns"])
    findings = []
    for hit in match_text(output, [item for item in indicators if item["type"] in {"domain", "ip", "url"}]):
        findings.append(finding(hit, "dns_cache", {"matched_output_excerpt": output[:4000]}))
    return findings


def scan_recent_logs(indicators: List[Dict[str, str]], roots: List[str]) -> List[Dict[str, Any]]:
    log_roots = []
    for root in roots:
        root_path = Path(root).expanduser()
        if root_path.exists():
            log_roots.append(str(root_path))
    return scan_files([item for item in indicators if item["type"] != "hash"], log_roots, max_files=500)


def summarise(findings: List[Dict[str, Any]], indicators: List[Dict[str, str]]) -> Dict[str, Any]:
    high = len([item for item in findings if item.get("severity") == "high"])
    medium = len([item for item in findings if item.get("severity") == "medium"])
    verdict = "No IOC matches found"
    severity = "low"
    if high:
        verdict = "High-confidence IOC matches require urgent review"
        severity = "high"
    elif medium:
        verdict = "IOC matches require validation"
        severity = "medium"
    return {"verdict": verdict, "severity": severity, "indicator_count": len(indicators), "match_count": len(findings), "high": high, "medium": medium}


@router.post("/scan")
def scan_iocs(request: IOCScanRequest):
    indicators = build_indicator_objects(request.indicators)
    findings: List[Dict[str, Any]] = []
    if request.include_files:
        findings.extend(scan_files(indicators, request.scan_paths, request.max_files))
    if request.include_processes:
        findings.extend(scan_processes(indicators))
    if request.include_network:
        findings.extend(scan_network(indicators))
    if request.include_registry_autoruns:
        findings.extend(scan_registry_autoruns(indicators))
    if request.include_dns_cache:
        findings.extend(scan_dns_cache(indicators))
    if request.include_recent_logs:
        findings.extend(scan_recent_logs(indicators, request.scan_paths))
    deduped = {item["finding_id"]: item for item in findings}
    findings = list(deduped.values())
    summary = summarise(findings, indicators)
    payload = {
        "status": "complete",
        "summary": summary,
        "risk_score": max(0, 100 - (summary["high"] * 30) - (summary["medium"] * 15)),
        "severity": summary["severity"],
        "indicators": indicators,
        "findings": findings,
        "evidence": findings,
        "timeline": [{"timestamp": item.get("timestamp"), "source": item.get("source"), "event": item.get("title"), "severity": item.get("severity"), "evidence_ref": item.get("indicator")} for item in findings],
        "recommended_actions": [
            "Validate the IOC source, age and confidence before action.",
            "Preserve matched files, commands, registry values and connection evidence.",
            "Correlate matches with process ancestry, persistence and timeline data.",
            "Only block or remove artefacts after confirming business impact and evidence preservation.",
        ],
        "metadata": {"generated_at": utc_now(), "host": platform.node(), "platform": platform.platform(), "scan_paths": request.scan_paths, "max_files": request.max_files},
    }
    save_audit_event(action="ioc_scan_run", entity_type="host", entity_id=platform.node(), details={"indicator_count": len(indicators), "match_count": len(findings)})
    return payload
