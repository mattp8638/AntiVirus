from typing import List, Dict


def make_timeline(findings: List[Dict]) -> List[Dict]:
    timeline = []
    for finding in findings:
        timeline.append({
            "time": finding.get("created_at"),
            "source": finding.get("module"),
            "event": finding.get("title"),
            "severity": finding.get("severity"),
            "evidence_ref": finding.get("finding_id"),
        })
    return sorted(timeline, key=lambda item: item.get("time") or "")


def highest_severity(findings: List[Dict]) -> str:
    from modules.investigator.common import SEVERITY_ORDER
    if not findings:
        return "informational"
    return max((finding.get("severity", "informational") for finding in findings), key=lambda s: SEVERITY_ORDER.get(s, 0))
