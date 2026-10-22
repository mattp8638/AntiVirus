from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json

from .database import SessionLocal, engine
from .models import Base, CVEScan

Base.metadata.create_all(bind=engine)

app = FastAPI(title="CVE-Watchdog API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Asset(BaseModel):
    name: str
    product: str
    version: str

# simple static dataset (MVP)
CVE_DATA = [
    {"product": "openssl", "version": "1.1.1", "cve": "CVE-2023-1234", "severity": "high"},
    {"product": "apache", "version": "2.4.49", "cve": "CVE-2021-41773", "severity": "critical"},
]

@app.post("/scan")
def scan(asset: Asset):
    matches = []

    for cve in CVE_DATA:
        if asset.product.lower() in cve["product"] and asset.version == cve["version"]:
            matches.append(cve)

    risk = "high" if any(m["severity"] == "critical" for m in matches) else "medium" if matches else "low"

    db = SessionLocal()
    record = CVEScan(asset=asset.name, product=asset.product, version=asset.version, findings=json.dumps(matches))
    db.add(record)
    db.commit()
    db.close()

    return {"asset": asset.name, "risk": risk, "vulnerabilities": matches}

@app.get("/history")
def history():
    db = SessionLocal()
    return db.query(CVEScan).all()
