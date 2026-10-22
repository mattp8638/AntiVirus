import json
from pathlib import Path
from typing import List

from .models import AVRuleMatch, AVSeverity

RULE_PACK_PATH = Path("external") / "av" / "native-signatures" / "fenrir-native-rules.json"

FALLBACK_RULES = [
    {
        "rule_id": "PS_ENCODED_COMMAND",
        "name": "PowerShell encoded command",
        "severity": "high",
        "confidence": 82,
        "patterns": ["-enc", "encodedcommand", "frombase64string"],
        "reason": "PowerShell encoded command indicators were found.",
        "tactic_id": "TA0005",
        "technique_id": "T1027",
        "source": "sentinel_fallback",
    },
    {
        "rule_id": "SHADOW_COPY_DELETE",
        "name": "Shadow copy deletion",
        "severity": "critical",
        "confidence": 90,
        "patterns": ["vssadmin delete shadows", "wmic shadowcopy delete", "delete shadows /all"],
        "reason": "Shadow copy deletion is commonly used by ransomware.",
        "tactic_id": "TA0040",
        "technique_id": "T1490",
        "source": "sentinel_fallback",
    },
]


def _severity(value: str) -> AVSeverity:
    try:
        return AVSeverity(str(value).lower())
    except Exception:
        return AVSeverity.medium


def load_rule_pack() -> dict:
    if RULE_PACK_PATH.exists():
        try:
            data = json.loads(RULE_PACK_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("rules"), list):
                return data
        except Exception:
            pass
    return {"name": "Fallback Native Rules", "version": "fallback", "rules": FALLBACK_RULES}


def rule_pack_status() -> dict:
    pack = load_rule_pack()
    return {
        "rule_pack": pack.get("name", "Unknown"),
        "rule_pack_version": pack.get("version", "unknown"),
        "rule_count": len(pack.get("rules", [])),
        "rule_pack_path": str(RULE_PACK_PATH),
        "using_fallback": not RULE_PACK_PATH.exists(),
    }


def match_native_rules(path: Path, max_bytes: int = 2 * 1024 * 1024) -> List[AVRuleMatch]:
    try:
        data = path.read_bytes()[:max_bytes]
    except Exception:
        return []
    text = data.decode("utf-8", errors="ignore").lower()
    pack = load_rule_pack()
    matches = []
    for rule in pack.get("rules", []):
        patterns = [str(pattern).lower() for pattern in rule.get("patterns", []) if pattern]
        if patterns and any(pattern in text for pattern in patterns):
            matches.append(AVRuleMatch(
                rule_id=str(rule.get("rule_id") or rule.get("id") or "UNKNOWN_RULE"),
                name=str(rule.get("name") or rule.get("rule_id") or "Unnamed native rule"),
                severity=_severity(rule.get("severity", "medium")),
                confidence=int(rule.get("confidence", 50)),
                reason=str(rule.get("reason") or "Native Sentinel rule matched."),
                tactic_id=rule.get("tactic_id"),
                technique_id=rule.get("technique_id"),
                source=str(rule.get("source") or "sentinel_native_pack"),
            ))
    return matches
