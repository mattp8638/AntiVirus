import json
from pathlib import Path
from typing import Any, Dict, List

FEED_STATE_FILE = Path("data") / "feeds" / "threat-feed-bundle.json"


def lookup_feed_matches(sha256_value: str, extracted_iocs: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    if not FEED_STATE_FILE.exists():
        return []
    try:
        bundle = json.loads(FEED_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []
    matches = []
    hashes = bundle.get("hashes", []) if isinstance(bundle, dict) else []
    urls = bundle.get("urls", []) if isinstance(bundle, dict) else []
    for item in hashes:
        if str(item.get("value", "")).lower() == sha256_value.lower():
            matches.append({"type": "hash", "source": item.get("source"), "value": sha256_value, "malware_family": item.get("malware_family"), "tags": item.get("tags", [])})
    observed_urls = set(extracted_iocs.get("urls", []))
    observed_domains = set(extracted_iocs.get("domains", []))
    for item in urls:
        url = item.get("url")
        host = item.get("host")
        if url in observed_urls or host in observed_domains:
            matches.append({"type": "url", "source": item.get("source"), "value": url or host, "threat": item.get("threat"), "tags": item.get("tags", [])})
    return matches
