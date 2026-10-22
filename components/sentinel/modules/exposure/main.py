from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import socket
import json

from .database import SessionLocal, engine
from .models import Base, Scan

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ExposureScout API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

@app.post("/scan")
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

    db = SessionLocal()
    record = Scan(target=req.target, findings=json.dumps(findings))
    db.add(record)
    db.commit()
    db.close()

    return {"target": req.target, "risk_score": risk_score, "risk_band": risk_band, "findings": findings}

@app.get("/history")
def history():
    db = SessionLocal()
    return db.query(Scan).all()
