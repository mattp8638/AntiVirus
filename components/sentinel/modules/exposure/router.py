from fastapi import APIRouter
from pydantic import BaseModel
import socket

router = APIRouter()

class ScanRequest(BaseModel):
    target: str

RISKY_PORTS = {
    21: "FTP exposed",
    22: "SSH exposed",
    80: "HTTP exposed",
    443: "HTTPS exposed",
    445: "SMB exposed",
    3389: "RDP exposed",
    5985: "WinRM exposed",
    8080: "Alternative HTTP/admin port exposed",
}

@router.post("/scan")
def scan(req: ScanRequest):
    findings = []
    for port, label in RISKY_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            result = sock.connect_ex((req.target, port))
            sock.close()
            if result == 0:
                severity = "high" if port in [445, 3389, 5985] else "medium"
                findings.append({"port": port, "issue": label, "severity": severity})
        except Exception:
            continue
    risk_score = min(100, len(findings) * 15)
    risk_band = "high" if risk_score >= 60 else "medium" if risk_score >= 30 else "low"
    return {"target": req.target, "risk_score": risk_score, "risk_band": risk_band, "findings": findings}
