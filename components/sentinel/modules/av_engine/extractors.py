import re
from pathlib import Path
from typing import Dict, List

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_iocs(path: Path, max_bytes: int = 1024 * 1024) -> Dict[str, List[str]]:
    try:
        data = path.read_bytes()[:max_bytes]
    except Exception:
        return {"urls": [], "ips": [], "domains": []}
    text = data.decode("utf-8", errors="ignore")
    urls = sorted(set(URL_RE.findall(text)))[:100]
    ips = sorted(set(IP_RE.findall(text)))[:100]
    domains = sorted(set(match for match in DOMAIN_RE.findall(text) if not match.lower().endswith((".dll", ".exe"))))[:100]
    return {"urls": urls, "ips": ips, "domains": domains}
