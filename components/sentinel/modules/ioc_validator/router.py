import re
from enum import Enum
from typing import List

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class IOCType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"
    cve = "cve"
    email = "email"
    unknown = "unknown"

class ValidationRequest(BaseModel):
    input: str

class IOCResult(BaseModel):
    value: str
    type: IOCType
    valid: bool
    confidence: int
    recommendation: str
    reason: str

PATTERNS = {
    IOCType.url: re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    IOCType.email: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    IOCType.cve: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    IOCType.hash: re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"),
    IOCType.ip: re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    IOCType.domain: re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
}

def refang(value: str) -> str:
    return value.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[.]", ".").replace("(.)", ".")

def classify(value: str) -> IOCType:
    for ioc_type in [IOCType.url, IOCType.email, IOCType.cve, IOCType.hash, IOCType.ip, IOCType.domain]:
        if PATTERNS[ioc_type].fullmatch(value):
            return ioc_type
    return IOCType.unknown

def score(ioc_type: IOCType):
    scores = {
        IOCType.hash: (80, "monitor", "High-specificity indicator; verify source confidence before blocking."),
        IOCType.url: (75, "monitor", "URL indicators are actionable but may expire quickly."),
        IOCType.cve: (70, "review", "CVE should be matched to asset exposure before action."),
        IOCType.domain: (65, "review", "Domain should be enriched before blocking."),
        IOCType.ip: (55, "review", "IP indicators can be noisy due to shared infrastructure."),
        IOCType.email: (50, "review", "Email indicators support phishing correlation."),
    }
    return scores.get(ioc_type, (10, "ignore", "Indicator could not be confidently classified."))

def extract_iocs(raw: str) -> List[str]:
    normalised = refang(raw)
    found = []
    for pattern in PATTERNS.values():
        found.extend(pattern.findall(normalised))
    return sorted(set(item.strip().rstrip(".,;)") for item in found if item.strip()))

@router.post("/validate")
def validate(data: ValidationRequest):
    results = []
    for value in extract_iocs(data.input):
        ioc_type = classify(value)
        confidence, recommendation, reason = score(ioc_type)
        results.append(IOCResult(value=value, type=ioc_type, valid=ioc_type != IOCType.unknown, confidence=confidence, recommendation=recommendation, reason=reason))
    return {"count": len(results), "valid_count": sum(1 for r in results if r.valid), "results": results}
