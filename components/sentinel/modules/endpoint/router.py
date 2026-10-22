import hashlib
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from modules.storage import (
    delete_agent as delete_agent_record,
    get_agent as get_agent_record,
    get_agent_pending_request,
    list_investigation_requests,
    get_latest_evidence,
    get_latest_software_inventory,
    get_latest_posture,
    list_agents as list_agent_records,
    save_agent,
    save_audit_event,
    save_evidence_file,
    save_software_inventory,
    save_posture,
    save_investigation_request,
    update_investigation_request_status,
    save_investigation_result,
)

router = APIRouter()

DATA_DIR = Path("data")
EVIDENCE_DIR = DATA_DIR / "evidence"
DATA_DIR.mkdir(exist_ok=True)
EVIDENCE_DIR.mkdir(exist_ok=True)

class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class Endpoint(BaseModel):
    hostname: str = Field(..., examples=["LAPTOP-001"])
    operating_system: str = "Windows 11"
    defender_enabled: bool
    defender_realtime_enabled: bool = True
    firewall_enabled: bool
    bitlocker_enabled: bool
    rdp_enabled: bool
    smb_v1_enabled: bool
    local_admin_count: int = 1
    powershell_logging_enabled: bool = False
    audit_policy_enabled: bool = True
    secure_boot_enabled: bool = False
    windows_update_enabled: bool = True
    controlled_folder_access_enabled: bool = False
    defender_tamper_protection_enabled: bool = False
    risky_services: int = 0

class AgentRegister(BaseModel):
    hostname: str
    operating_system: str = "Windows"
    existing_agent_id: str | None = None

class AgentInvestigationRequest(BaseModel):
    priority: str = "normal"
    reason: str = "Analyst requested endpoint investigation"
    scope: Dict[str, Any] = Field(default_factory=dict)

class AgentInvestigationResult(BaseModel):
    request_id: str
    status: str = "complete"
    completed_at: str | None = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    software_inventory: List[Dict[str, Any]] = Field(default_factory=list)
    report_path: str | None = None
    bundle_path: str | None = None

class EndpointPosture(Endpoint):
    agent_id: str

class Finding(BaseModel):
    control: str
    severity: Severity
    points: int
    status: str
    remediation: str

class ScoreResponse(BaseModel):
    hostname: str
    operating_system: str
    risk_score: int
    risk_band: Severity
    findings: List[Finding]
    summary: str

CHECKS = [
    {"field": "defender_enabled", "expected": True, "control": "Microsoft Defender enabled", "severity": Severity.critical, "points": 25, "remediation": "Enable Microsoft Defender or ensure another managed EDR/AV product is active."},
    {"field": "defender_realtime_enabled", "expected": True, "control": "Real-time protection enabled", "severity": Severity.high, "points": 15, "remediation": "Enable real-time protection and prevent local tampering by policy."},
    {"field": "defender_tamper_protection_enabled", "expected": True, "control": "Defender tamper protection enabled", "severity": Severity.high, "points": 10, "remediation": "Enable Defender tamper protection where supported to reduce local security bypass risk."},
    {"field": "firewall_enabled", "expected": True, "control": "Windows Firewall enabled", "severity": Severity.high, "points": 20, "remediation": "Enable Windows Firewall for Domain, Private and Public profiles."},
    {"field": "bitlocker_enabled", "expected": True, "control": "Disk encryption enabled", "severity": Severity.medium, "points": 10, "remediation": "Enable BitLocker or equivalent full-disk encryption."},
    {"field": "secure_boot_enabled", "expected": True, "control": "Secure Boot enabled", "severity": Severity.medium, "points": 8, "remediation": "Enable Secure Boot in UEFI where hardware and operating system support it."},
    {"field": "windows_update_enabled", "expected": True, "control": "Windows Update service enabled", "severity": Severity.high, "points": 15, "remediation": "Ensure Windows Update is enabled and the endpoint is receiving security updates."},
    {"field": "controlled_folder_access_enabled", "expected": True, "control": "Controlled Folder Access enabled", "severity": Severity.medium, "points": 8, "remediation": "Enable Controlled Folder Access where appropriate to reduce ransomware impact."},
    {"field": "rdp_enabled", "expected": False, "control": "RDP disabled unless explicitly required", "severity": Severity.medium, "points": 10, "remediation": "Disable RDP where not required or restrict it with VPN, firewall rules and MFA."},
    {"field": "smb_v1_enabled", "expected": False, "control": "SMBv1 disabled", "severity": Severity.high, "points": 15, "remediation": "Disable SMBv1 and use modern SMB versions only."},
    {"field": "powershell_logging_enabled", "expected": True, "control": "PowerShell logging enabled", "severity": Severity.medium, "points": 10, "remediation": "Enable PowerShell script block logging and module logging via Group Policy or MDM."},
    {"field": "audit_policy_enabled", "expected": True, "control": "Audit policy enabled", "severity": Severity.medium, "points": 10, "remediation": "Enable audit policy for logon events, account changes, privilege use and process creation."},
]

def band_from_score(score: int) -> Severity:
    if score < 50:
        return Severity.critical
    if score < 70:
        return Severity.high
    if score < 85:
        return Severity.medium
    return Severity.low

def score(endpoint: Endpoint) -> ScoreResponse:
    final_score = 100
    findings: List[Finding] = []
    for check in CHECKS:
        actual = getattr(endpoint, check["field"], None)
        if actual != check["expected"]:
            final_score -= check["points"]
            findings.append(Finding(control=check["control"], severity=check["severity"], points=check["points"], status="failed", remediation=check["remediation"]))
    if endpoint.local_admin_count > 2:
        penalty = min(20, (endpoint.local_admin_count - 2) * 5)
        final_score -= penalty
        findings.append(Finding(control="Excessive local administrators", severity=Severity.medium, points=penalty, status="failed", remediation="Review local administrators and remove unnecessary privileged accounts."))
    if endpoint.risky_services > 0:
        penalty = min(20, endpoint.risky_services * 5)
        final_score -= penalty
        findings.append(Finding(control="Risky or exposed services detected", severity=Severity.high, points=penalty, status="failed", remediation="Review exposed services, remove unused services and restrict access by policy/firewall."))
    final_score = max(0, final_score)
    risk_band = band_from_score(final_score)
    return ScoreResponse(hostname=endpoint.hostname, operating_system=endpoint.operating_system, risk_score=final_score, risk_band=risk_band, findings=findings, summary=f"{endpoint.hostname} scored {final_score}/100 with {len(findings)} finding(s).")

@router.get("/sample")
def sample_endpoint():
    endpoint = Endpoint(hostname="LAPTOP-001", operating_system="Windows 11 Pro", defender_enabled=True, defender_realtime_enabled=True, firewall_enabled=True, bitlocker_enabled=False, rdp_enabled=True, smb_v1_enabled=False, local_admin_count=4, powershell_logging_enabled=False, audit_policy_enabled=True, secure_boot_enabled=True, windows_update_enabled=True, controlled_folder_access_enabled=False, defender_tamper_protection_enabled=False, risky_services=1)
    return {"endpoint": endpoint, "assessment": score(endpoint)}

@router.post("/score", response_model=ScoreResponse)
def score_endpoint(endpoint: Endpoint):
    return score(endpoint)

@router.post("/agent/register")
def register_agent(agent: AgentRegister):
    if agent.existing_agent_id:
        existing = get_agent_record(agent.existing_agent_id)
        if existing:
            existing["hostname"] = agent.hostname
            existing["operating_system"] = agent.operating_system
            existing["status"] = existing.get("status") or "registered"
            updated = save_agent(existing)
            save_audit_event(action="agent_registered", entity_type="agent", entity_id=agent.existing_agent_id, details={"hostname": agent.hostname})
            return updated
    for existing in list_agent_records():
        if existing.get("hostname") == agent.hostname:
            existing["operating_system"] = agent.operating_system
            updated = save_agent(existing)
            save_audit_event(action="agent_reused", entity_type="agent", entity_id=existing["agent_id"], details={"hostname": agent.hostname})
            return updated
    agent_id = str(uuid4())
    saved = save_agent({"agent_id": agent_id, "hostname": agent.hostname, "operating_system": agent.operating_system, "registered_at": datetime.utcnow().isoformat() + "Z", "last_seen": None, "status": "registered", "investigation": "idle"})
    save_audit_event(action="agent_registered", entity_type="agent", entity_id=agent_id, details={"hostname": agent.hostname, "operating_system": agent.operating_system})
    return saved

@router.post("/agent/posture")
def ingest_posture(posture: EndpointPosture):
    agent = get_agent_record(posture.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not registered")
    now = datetime.utcnow().isoformat() + "Z"
    assessment = score(posture).model_dump()
    agent["last_seen"] = now
    agent["risk_score"] = assessment["risk_score"]
    agent["risk_band"] = assessment["risk_band"]
    agent["status"] = "active"
    agent.setdefault("investigation", "idle")
    save_agent(agent)
    save_posture(posture.agent_id, now, posture.model_dump(), assessment)
    save_audit_event(action="posture_received", entity_type="agent", entity_id=posture.agent_id, details={"hostname": posture.hostname, "risk_score": assessment["risk_score"]})
    return {"status": "received", "agent_id": posture.agent_id, "assessment": assessment}

@router.get("/agents")
def list_agents():
    enriched = []
    for agent in list_agent_records():
        item = dict(agent)
        latest_posture = get_latest_posture(agent["agent_id"])
        if latest_posture:
            item["latest_assessment"] = latest_posture.get("assessment")
            item["latest_posture"] = latest_posture.get("posture")
            item["last_posture_received_at"] = latest_posture.get("received_at")
        pending_request = get_agent_pending_request(agent["agent_id"])
        if pending_request:
            item["investigation_instruction"] = pending_request
        latest_inventory = get_latest_software_inventory(agent["agent_id"])
        if latest_inventory:
            item["latest_software_inventory"] = latest_inventory
        enriched.append(item)
    return {"count": len(enriched), "agents": enriched}

@router.get("/agent/{agent_id}")
def get_agent(agent_id: str):
    agent = get_agent_record(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    latest = get_latest_posture(agent_id)
    pending_request = get_agent_pending_request(agent_id)
    latest_inventory = get_latest_software_inventory(agent_id)
    return {"agent": agent, "latest": latest, "pending_request": pending_request, "latest_evidence": get_latest_evidence(agent_id), "latest_software_inventory": latest_inventory}

@router.post("/agent/{agent_id}/investigate")
def trigger_investigation(agent_id: str, request: AgentInvestigationRequest = AgentInvestigationRequest()):
    agent = get_agent_record(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    now = datetime.utcnow().isoformat() + "Z"
    request_id = f"AIR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8].upper()}"
    instruction = {"request_id": request_id, "agent_id": agent_id, "hostname": agent.get("hostname"), "status": "pending", "priority": request.priority, "reason": request.reason, "scope": request.scope, "requested_at": now}
    agent["investigation"] = "pending"
    agent["investigation_request_id"] = request_id
    agent["investigation_requested_at"] = now
    agent["investigation_priority"] = request.priority
    agent["investigation_reason"] = request.reason
    agent["investigation_scope"] = request.scope
    agent["investigation_instruction"] = instruction
    save_agent(agent)
    save_investigation_request(instruction)
    save_audit_event(action="investigation_requested", entity_type="investigation_request", entity_id=request_id, details=instruction)
    return {"status": "investigation_requested", **instruction}

@router.post("/agent/{agent_id}/evidence")
def upload_evidence(agent_id: str, file: UploadFile = File(...)):
    agent = get_agent_record(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    filename = f"{agent_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.enc"
    path = EVIDENCE_DIR / filename
    contents = file.file.read()
    with open(path, "wb") as f:
        f.write(contents)
    sha256 = hashlib.sha256(contents).hexdigest()
    request_id = agent.get("investigation_request_id")
    agent["investigation"] = "complete"
    agent["evidence_file"] = filename
    agent["evidence_uploaded_at"] = datetime.utcnow().isoformat() + "Z"
    save_agent(agent)
    save_evidence_file(agent_id=agent_id, request_id=request_id, filename=filename, path=str(path), sha256=sha256, metadata={"content_type": file.content_type})
    if request_id:
        update_investigation_request_status(request_id, "complete")
        try:
            save_investigation_result({"request_id": request_id, "agent_id": agent_id, "hostname": agent.get("hostname"), "status": "complete", "completed_at": datetime.utcnow().isoformat() + "Z", "summary": {"investigation_id": request_id, "request_id": request_id, "agent_id": agent_id, "hostname": agent.get("hostname"), "status": "complete"}, "findings": [], "timeline": [], "report_path": None, "bundle_path": str(path)})
        except Exception:
            pass
    save_audit_event(action="evidence_uploaded", entity_type="evidence_file", entity_id=filename, details={"agent_id": agent_id, "request_id": request_id, "sha256": sha256})
    return {"status": "stored", "agent_id": agent_id, "evidence_file": filename}

@router.post("/agent/{agent_id}/result")
def submit_investigation_result(agent_id: str, result: AgentInvestigationResult):
    agent = get_agent_record(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    request_id = result.request_id
    completed_at = result.completed_at or datetime.utcnow().isoformat() + "Z"
    payload = {"request_id": request_id, "agent_id": agent_id, "hostname": agent.get("hostname"), "status": result.status, "completed_at": completed_at, "summary": result.summary or {"investigation_id": request_id, "request_id": request_id, "agent_id": agent_id, "hostname": agent.get("hostname"), "status": result.status}, "findings": result.findings, "timeline": result.timeline, "software_inventory": result.software_inventory, "report_path": result.report_path, "bundle_path": result.bundle_path}
    save_investigation_result(payload)
    if result.software_inventory:
        save_software_inventory(agent_id=agent_id, collected_at=completed_at, inventory=result.software_inventory)
    update_investigation_request_status(request_id, result.status)
    agent["investigation"] = result.status
    save_agent(agent)
    save_audit_event(action="investigation_result_submitted", entity_type="investigation_request", entity_id=request_id, details={"agent_id": agent_id, "status": result.status})
    return {"status": "saved", "request_id": request_id, "investigation": payload["summary"]}

@router.get("/agent/{agent_id}/task")
def get_agent_task(agent_id: str):
    agent = get_agent_record(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    requests = [r for r in list_investigation_requests() if r.get("agent_id") == agent_id and r.get("status") in ("assigned", "pending")]
    if not requests:
        return {"status": "idle"}
    req = requests[0]
    request_id = req.get("request_id")
    if req.get("status") != "in-progress":
        update_investigation_request_status(request_id, "in-progress")
        agent["investigation"] = "in-progress"
        save_agent(agent)
        save_audit_event(action="investigation_assigned_to_agent", entity_type="investigation_request", entity_id=request_id, details={"agent_id": agent_id})
    return {"status": "in-progress", "instruction": req}

@router.get("/agent/{agent_id}/evidence/download")
def download_evidence(agent_id: str):
    agent = get_agent_record(agent_id)
    if not agent or not agent.get("evidence_file"):
        raise HTTPException(status_code=404, detail="Evidence not found")
    path = EVIDENCE_DIR / agent["evidence_file"]
    if not path.exists():
        raise HTTPException(status_code=404, detail="Evidence file missing")
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")

@router.delete("/agent/{agent_id}")
def delete_agent(agent_id: str):
    if not get_agent_record(agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    delete_agent_record(agent_id)
    save_audit_event(action="agent_deleted", entity_type="agent", entity_id=agent_id)
    return {"status": "deleted", "agent_id": agent_id}
