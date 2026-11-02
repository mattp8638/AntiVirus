import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from modules.storage import get_connection, get_latest_software_inventory, save_audit_event

router = APIRouter()

DATA_DIR = Path("data")
FEEDS_DIR = DATA_DIR / "feeds"
VULN_FEED_FILE = FEEDS_DIR / "vulnerabilities.json"
KEV_FEED_FILE = FEEDS_DIR / "kev.json"
DATA_DIR.mkdir(exist_ok=True)
FEEDS_DIR.mkdir(parents=True, exist_ok=True)

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "unknown": 0}

DEFAULT_VULNERABILITIES = [
    {"cve": "CVE-2024-30078", "vendor": "Microsoft", "product": "Windows", "affected_versions": ["10", "11", "Server 2019", "Server 2022"], "severity": "high", "cvss": 8.8, "known_exploited": False, "summary": "Windows Wi-Fi driver remote code execution vulnerability affecting supported Windows platforms.", "remediation": "Apply the relevant Microsoft security update and validate patch deployment across affected endpoints.", "source": "local_seed_feed"},
    {"cve": "CVE-2024-38112", "vendor": "Microsoft", "product": "Windows", "affected_versions": ["10", "11", "Server 2019", "Server 2022"], "severity": "critical", "cvss": 9.8, "known_exploited": True, "summary": "Windows MSHTML spoofing vulnerability reported as exploited in the wild.", "remediation": "Prioritise patching immediately and review endpoint/browser telemetry for suspicious activity.", "source": "local_seed_feed"},
    {"cve": "CVE-2023-23397", "vendor": "Microsoft", "product": "Outlook", "affected_versions": ["2016", "2019", "2021", "365"], "severity": "critical", "cvss": 9.8, "known_exploited": True, "summary": "Microsoft Outlook elevation of privilege vulnerability involving NTLM credential leakage.", "remediation": "Patch Outlook, run Microsoft-provided detection scripts where appropriate, and review NTLM exposure.", "source": "local_seed_feed"},
    {"cve": "CVE-2024-3094", "vendor": "XZ Utils", "product": "xz", "affected_versions": ["5.6.0", "5.6.1"], "severity": "critical", "cvss": 10.0, "known_exploited": True, "summary": "Backdoor discovered in XZ Utils versions 5.6.0 and 5.6.1.", "remediation": "Downgrade to a known-good version, rebuild affected packages and investigate systems that ran affected builds.", "source": "local_seed_feed"},
    {"cve": "CVE-2023-38545", "vendor": "curl", "product": "curl", "affected_versions": ["7.69.0-8.3.0"], "severity": "high", "cvss": 8.8, "known_exploited": False, "summary": "SOCKS5 heap buffer overflow vulnerability in curl/libcurl.", "remediation": "Upgrade curl/libcurl to a fixed version and identify applications statically linking vulnerable libcurl.", "source": "local_seed_feed"},
    {"cve": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j", "affected_versions": ["2.0-2.14.1"], "severity": "critical", "cvss": 10.0, "known_exploited": True, "summary": "Apache Log4j remote code execution vulnerability known as Log4Shell.", "remediation": "Upgrade Log4j to a fixed release, remove vulnerable classes where required and review exposure logs.", "source": "local_seed_feed"},
    {"cve": "CVE-2023-4863", "vendor": "Google", "product": "Chrome", "affected_versions": ["<116.0.5845.187"], "severity": "critical", "cvss": 9.6, "known_exploited": True, "summary": "Heap buffer overflow in WebP affecting Chrome and other WebP consumers.", "remediation": "Update Chrome and any other software bundling vulnerable WebP libraries.", "source": "local_seed_feed"},
]

class CVERequest(BaseModel):
    product: str
    version: str = ""
    vendor: Optional[str] = None
    include_non_exact: bool = True

class SoftwareItem(BaseModel):
    product: str
    version: str = ""
    vendor: Optional[str] = None

class InventoryScanRequest(BaseModel):
    software: List[Dict[str, Any]] = Field(default_factory=list)
    agent_id: Optional[str] = None


def normalise(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def token_match(needle: str, haystack: str) -> bool:
    n = normalise(needle)
    h = normalise(haystack)
    if not n or not h:
        return False
    return n in h or h in n


def parse_version_parts(version: str) -> List[int]:
    return [int(part) for part in re.findall(r"\d+", str(version or ""))[:4]]


def version_lte(left: str, right: str) -> bool:
    l_parts = parse_version_parts(left)
    r_parts = parse_version_parts(right)
    if not l_parts or not r_parts:
        return False
    width = max(len(l_parts), len(r_parts))
    l_parts += [0] * (width - len(l_parts))
    r_parts += [0] * (width - len(r_parts))
    return l_parts <= r_parts


def version_gte(left: str, right: str) -> bool:
    l_parts = parse_version_parts(left)
    r_parts = parse_version_parts(right)
    if not l_parts or not r_parts:
        return False
    width = max(len(l_parts), len(r_parts))
    l_parts += [0] * (width - len(l_parts))
    r_parts += [0] * (width - len(r_parts))
    return l_parts >= r_parts


def version_in_range(version: str, affected: str) -> bool:
    raw = str(affected or "").strip()
    if not version:
        return True
    if not raw:
        return False
    if raw.startswith("<"):
        limit = raw.replace("<", "").strip()
        return version_lte(version, limit) and normalise(version) != normalise(limit)
    if "-" in raw:
        start, end = [part.strip() for part in raw.split("-", 1)]
        return version_gte(version, start) and version_lte(version, end)
    return token_match(version, raw)


def load_feed(path: Path, fallback: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data.get("vulnerabilities", data.get("items", []))
            if isinstance(data, list):
                return data
        except Exception:
            return fallback
    return fallback


def load_vulnerabilities() -> List[Dict[str, Any]]:
    return load_feed(VULN_FEED_FILE, DEFAULT_VULNERABILITIES)


def _normalize_inventory_item(item: Dict[str, Any]) -> SoftwareItem:
    return SoftwareItem(
        product=str(item.get("product") or item.get("DisplayName") or item.get("name") or "").strip(),
        version=str(item.get("version") or item.get("DisplayVersion") or item.get("display_version") or "").strip(),
        vendor=(str(item.get("vendor") or item.get("Publisher") or item.get("publisher") or "").strip() or None),
    )


def match_vulnerability(item: SoftwareItem, vuln: Dict[str, Any], include_non_exact: bool = True) -> Optional[Dict[str, Any]]:
    product_match = token_match(item.product, vuln.get("product", ""))
    vendor_match = True if not item.vendor else token_match(item.vendor, vuln.get("vendor", ""))
    if not product_match or not vendor_match:
        return None
    affected_versions = vuln.get("affected_versions", []) or []
    exact_version_match = bool(item.version) and any(version_in_range(item.version, affected) for affected in affected_versions)
    uncertain_version_match = include_non_exact and not item.version
    broad_product_match = include_non_exact and bool(item.version) and not affected_versions
    if not (exact_version_match or uncertain_version_match or broad_product_match):
        return None
    severity = str(vuln.get("severity", "unknown")).lower()
    known_exploited = bool(vuln.get("known_exploited", False))
    cvss = float(vuln.get("cvss", 0) or 0)
    priority_score = (SEVERITY_RANK.get(severity, 0) * 25) + (35 if known_exploited else 0) + int(cvss)
    match_confidence = "high" if exact_version_match else "medium" if uncertain_version_match else "low"
    return {
        "cve": vuln.get("cve", "Unknown CVE"),
        "vendor": vuln.get("vendor", "Unknown vendor"),
        "product": vuln.get("product", item.product),
        "detected_version": item.version or "not supplied",
        "affected_versions": affected_versions,
        "severity": severity,
        "cvss": cvss,
        "known_exploited": known_exploited,
        "priority_score": priority_score,
        "match_confidence": match_confidence,
        "summary": vuln.get("summary", "No summary supplied by the current feed."),
        "remediation": vuln.get("remediation", "Confirm affected version and apply vendor remediation or upgrade guidance."),
        "source": vuln.get("source", "local_feed"),
        "status": "review",
    }


def scan_items(items: List[SoftwareItem], include_non_exact: bool = True) -> Dict[str, Any]:
    feed = load_vulnerabilities()
    matches: List[Dict[str, Any]] = []
    for item in items:
        for vuln in feed:
            match = match_vulnerability(item, vuln, include_non_exact=include_non_exact)
            if match:
                matches.append(match)
    deduped = {match["cve"] + match["product"] + match["detected_version"]: match for match in matches}
    vulnerabilities = sorted(deduped.values(), key=lambda row: row.get("priority_score", 0), reverse=True)
    kev_count = len([v for v in vulnerabilities if v.get("known_exploited")])
    critical_count = len([v for v in vulnerabilities if v.get("severity") == "critical"])
    high_count = len([v for v in vulnerabilities if v.get("severity") == "high"])
    verdict = "No matching vulnerabilities found"
    if kev_count:
        verdict = "Known exploited vulnerabilities require urgent review"
    elif critical_count:
        verdict = "Critical vulnerabilities found"
    elif high_count:
        verdict = "High severity vulnerabilities found"
    elif vulnerabilities:
        verdict = "Vulnerabilities found"
    return {
        "status": verdict,
        "scanned_items": len(items),
        "feed_items": len(feed),
        "count": len(vulnerabilities),
        "known_exploited_count": kev_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "vulnerabilities": vulnerabilities,
        "feed_note": "Uses local vulnerability feed files in data/feeds. Replace or enrich these with NVD, CISA KEV, vendor advisories or commercial feeds for production use.",
    }


def persist_vulnerability_scan(agent_id: str, result: Dict[str, Any]) -> None:
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO vulnerability_matches (agent_id, collected_at, matches_json) VALUES (?, ?, ?)",
            (agent_id, result.get("generated_at") or datetime.utcnow().isoformat() + "Z", json.dumps(result, ensure_ascii=True, default=str)),
        )
    save_audit_event(action="vulnerability_scan_saved", entity_type="agent", entity_id=agent_id, details={"match_count": result.get("count", 0)})


def latest_vulnerability_scan(agent_id: str) -> Optional[Dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM vulnerability_matches WHERE agent_id = ? ORDER BY id DESC LIMIT 1", (agent_id,)).fetchone()
    if not row:
        return None
    data = dict(row)
    try:
        data["matches"] = json.loads(data.pop("matches_json") or "{}")
    except Exception:
        data["matches"] = {}
    return data


@router.post("/scan")
def scan(req: CVERequest):
    item = SoftwareItem(product=req.product, version=req.version, vendor=req.vendor)
    result = scan_items([item], include_non_exact=req.include_non_exact)
    result["product"] = req.product
    result["version"] = req.version
    result["vendor"] = req.vendor
    return result

@router.post("/inventory-scan")
def inventory_scan(req: InventoryScanRequest):
    software_items = [_normalize_inventory_item(item) for item in req.software]
    software_items = [item for item in software_items if item.product]
    result = scan_items(software_items, include_non_exact=True)
    if req.agent_id:
        result["agent_id"] = req.agent_id
        persist_vulnerability_scan(req.agent_id, result)
    return result

@router.post("/agent/{agent_id}/inventory-scan")
def scan_agent_inventory(agent_id: str):
    inventory = get_latest_software_inventory(agent_id)
    if not inventory or not inventory.get("inventory"):
        raise HTTPException(status_code=404, detail="No stored software inventory found for this endpoint")
    software_items = [_normalize_inventory_item(item) for item in inventory.get("inventory", [])]
    software_items = [item for item in software_items if item.product]
    result = scan_items(software_items, include_non_exact=True)
    result["agent_id"] = agent_id
    result["inventory_collected_at"] = inventory.get("collected_at")
    persist_vulnerability_scan(agent_id, result)
    return result

@router.get("/agent/{agent_id}/latest")
def get_agent_latest_scan(agent_id: str):
    latest = latest_vulnerability_scan(agent_id)
    if not latest:
        return {"status": "not_scanned", "agent_id": agent_id, "matches": None}
    return {"status": "ok", "agent_id": agent_id, "latest": latest}

@router.get("/feed/status")
def feed_status():
    feed = load_vulnerabilities()
    return {
        "status": "available",
        "feed_items": len(feed),
        "vulnerability_feed_file": str(VULN_FEED_FILE),
        "kev_feed_file": str(KEV_FEED_FILE),
        "using_seed_feed": not VULN_FEED_FILE.exists(),
        "message": "Drop JSON feed files into data/feeds to replace the built-in seed feed.",
    }
