import ipaddress
import platform
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from modules.investigator.collectors.network import collect_network_connections
from modules.storage import save_audit_event

router = APIRouter()

SUSPICIOUS_PROCESS_NAMES = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
USER_WRITABLE_MARKERS = ["\\appdata\\", "\\temp\\", "\\users\\public\\", "/tmp/", "/appdata/"]


class NetworkSnapshotRequest(BaseModel):
    include_listening: bool = True
    include_loopback: bool = False
    include_private_remote: bool = True


def utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


def classify_ip(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {"classification": "none", "is_external": False}
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_loopback:
            return {"classification": "loopback", "is_external": False}
        if ip.is_private:
            return {"classification": "private", "is_external": False}
        if ip.is_multicast:
            return {"classification": "multicast", "is_external": False}
        if ip.is_reserved:
            return {"classification": "reserved", "is_external": False}
        return {"classification": "external", "is_external": True}
    except Exception:
        return {"classification": "unknown", "is_external": False}


def normalise_connection(conn: Dict[str, Any]) -> Dict[str, Any]:
    remote = conn.get("remote_ip")
    classification = classify_ip(remote)
    process_name = (conn.get("process_name") or "unknown").lower()
    process_path = (conn.get("process_path") or "").lower()
    reasons = []
    severity = "low"
    if classification.get("is_external"):
        reasons.append("external destination observed")
    if process_name in SUSPICIOUS_PROCESS_NAMES and remote:
        severity = "high"
        reasons.append("script/system utility process has a remote connection")
    if any(marker in process_path for marker in USER_WRITABLE_MARKERS) and remote:
        severity = "medium" if severity == "low" else severity
        reasons.append("process path is user-writable or commonly abused")
    if conn.get("status") == "LISTEN":
        reasons.append("listening port exposed locally")
    if not reasons:
        reasons.append("network connection observed")
    return {
        "pid": conn.get("pid"),
        "process_name": conn.get("process_name") or "unknown",
        "process_path": conn.get("process_path") or "not available",
        "local_address": conn.get("local_address"),
        "remote_address": conn.get("remote_address"),
        "remote_ip": remote,
        "remote_port": conn.get("remote_port"),
        "status": conn.get("status"),
        "destination_classification": classification.get("classification"),
        "is_external": classification.get("is_external"),
        "risk_rating": severity,
        "reason_flagged": "; ".join(reasons),
        "reputation": "not enriched",
        "asn": "not enriched",
        "country": "not enriched",
        "recommended_action": "Validate the process and destination. Enrich unknown external IPs with IOC/reputation checks before containment.",
    }


def summarise(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    external = len([item for item in items if item.get("is_external")])
    listening = len([item for item in items if item.get("status") == "LISTEN"])
    high = len([item for item in items if item.get("risk_rating") == "high"])
    medium = len([item for item in items if item.get("risk_rating") == "medium"])
    verdict = "Network snapshot collected"
    severity = "low"
    if high:
        verdict = "High-risk network activity requires review"
        severity = "high"
    elif medium:
        verdict = "Suspicious network activity requires validation"
        severity = "medium"
    return {"verdict": verdict, "severity": severity, "total": len(items), "external": external, "listening": listening, "high": high, "medium": medium}


@router.post("/snapshot")
def network_snapshot(request: NetworkSnapshotRequest = NetworkSnapshotRequest()):
    raw = collect_network_connections()
    items = [normalise_connection(conn) for conn in raw]
    if not request.include_listening:
        items = [item for item in items if item.get("status") != "LISTEN"]
    if not request.include_loopback:
        items = [item for item in items if item.get("destination_classification") != "loopback"]
    if not request.include_private_remote:
        items = [item for item in items if item.get("destination_classification") != "private"]
    summary = summarise(items)
    findings = [item for item in items if item.get("risk_rating") in {"medium", "high"}]
    payload = {
        "status": "complete",
        "summary": summary,
        "risk_score": max(0, 100 - (summary["high"] * 25) - (summary["medium"] * 10) - max(0, summary["external"] - 5)),
        "severity": summary["severity"],
        "connections": items,
        "findings": findings,
        "evidence": items,
        "timeline": [{"timestamp": utc_now(), "source": "network", "event": f"{item.get('process_name')} -> {item.get('remote_address') or item.get('local_address')}", "severity": item.get("risk_rating"), "evidence_ref": item.get("remote_address") or item.get("local_address")} for item in items],
        "recommended_actions": [
            "Review high-risk process and destination pairs first.",
            "Enrich unknown external IPs using IOC/reputation sources.",
            "Confirm listening ports are expected and firewall-restricted.",
            "Correlate suspicious connections with process command lines and persistence artefacts.",
        ],
        "metadata": {"generated_at": utc_now(), "host": platform.node(), "platform": platform.platform(), "enrichment": "placeholder"},
    }
    save_audit_event(action="network_snapshot_run", entity_type="host", entity_id=platform.node(), details={"connection_count": len(items), "severity": summary["severity"]})
    return payload
