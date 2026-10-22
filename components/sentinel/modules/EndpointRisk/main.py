from enum import Enum
from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="EndpointRisk API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    risky_services: int = 0


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
    {
        "field": "defender_enabled",
        "expected": True,
        "control": "Microsoft Defender enabled",
        "severity": Severity.critical,
        "points": 25,
        "remediation": "Enable Microsoft Defender or ensure another managed EDR/AV product is active.",
    },
    {
        "field": "defender_realtime_enabled",
        "expected": True,
        "control": "Real-time protection enabled",
        "severity": Severity.high,
        "points": 15,
        "remediation": "Enable real-time protection and prevent local tampering by policy.",
    },
    {
        "field": "firewall_enabled",
        "expected": True,
        "control": "Windows Firewall enabled",
        "severity": Severity.high,
        "points": 20,
        "remediation": "Enable Windows Firewall for Domain, Private and Public profiles.",
    },
    {
        "field": "bitlocker_enabled",
        "expected": True,
        "control": "Disk encryption enabled",
        "severity": Severity.medium,
        "points": 10,
        "remediation": "Enable BitLocker or equivalent full-disk encryption.",
    },
    {
        "field": "rdp_enabled",
        "expected": False,
        "control": "RDP disabled unless explicitly required",
        "severity": Severity.medium,
        "points": 10,
        "remediation": "Disable RDP where not required or restrict it with VPN, firewall rules and MFA.",
    },
    {
        "field": "smb_v1_enabled",
        "expected": False,
        "control": "SMBv1 disabled",
        "severity": Severity.high,
        "points": 15,
        "remediation": "Disable SMBv1 and use modern SMB versions only.",
    },
    {
        "field": "powershell_logging_enabled",
        "expected": True,
        "control": "PowerShell logging enabled",
        "severity": Severity.medium,
        "points": 10,
        "remediation": "Enable PowerShell script block logging and module logging via Group Policy or MDM.",
    },
    {
        "field": "audit_policy_enabled",
        "expected": True,
        "control": "Audit policy enabled",
        "severity": Severity.medium,
        "points": 10,
        "remediation": "Enable audit policy for logon events, account changes, privilege use and process creation.",
    },
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
        actual = getattr(endpoint, check["field"])
        if actual != check["expected"]:
            final_score -= check["points"]
            findings.append(
                Finding(
                    control=check["control"],
                    severity=check["severity"],
                    points=check["points"],
                    status="failed",
                    remediation=check["remediation"],
                )
            )

    if endpoint.local_admin_count > 2:
        penalty = min(20, (endpoint.local_admin_count - 2) * 5)
        final_score -= penalty
        findings.append(
            Finding(
                control="Excessive local administrators",
                severity=Severity.medium,
                points=penalty,
                status="failed",
                remediation="Review local administrators and remove unnecessary privileged accounts.",
            )
        )

    if endpoint.risky_services > 0:
        penalty = min(20, endpoint.risky_services * 5)
        final_score -= penalty
        findings.append(
            Finding(
                control="Risky or exposed services detected",
                severity=Severity.high,
                points=penalty,
                status="failed",
                remediation="Review exposed services, remove unused services and restrict access by policy/firewall.",
            )
        )

    final_score = max(0, final_score)
    risk_band = band_from_score(final_score)

    return ScoreResponse(
        hostname=endpoint.hostname,
        operating_system=endpoint.operating_system,
        risk_score=final_score,
        risk_band=risk_band,
        findings=findings,
        summary=f"{endpoint.hostname} scored {final_score}/100 with {len(findings)} finding(s).",
    )


@app.get("/")
def root():
    return {"status": "EndpointRisk API running", "version": "0.2.0"}


@app.get("/sample")
def sample_endpoint():
    endpoint = Endpoint(
        hostname="LAPTOP-001",
        operating_system="Windows 11 Pro",
        defender_enabled=True,
        defender_realtime_enabled=True,
        firewall_enabled=True,
        bitlocker_enabled=False,
        rdp_enabled=True,
        smb_v1_enabled=False,
        local_admin_count=4,
        powershell_logging_enabled=False,
        audit_policy_enabled=True,
        risky_services=1,
    )
    return {"endpoint": endpoint, "assessment": score(endpoint)}


@app.post("/score", response_model=ScoreResponse)
def score_endpoint(endpoint: Endpoint):
    return score(endpoint)
