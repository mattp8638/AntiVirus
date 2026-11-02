from pathlib import Path
from typing import Any, Dict, List

RULE_DIR = Path("data") / "rules" / "yara"


def yara_available() -> bool:
    try:
        import yara  # type: ignore
        return True
    except Exception:
        return False


def scan_yara(path: Path) -> List[Dict[str, Any]]:
    try:
        import yara  # type: ignore
    except Exception:
        return []
    if not RULE_DIR.exists():
        return []
    rule_files = list(RULE_DIR.glob("*.yar")) + list(RULE_DIR.glob("*.yara"))
    matches = []
    for rule_file in rule_files:
        try:
            rules = yara.compile(filepath=str(rule_file))
            for match in rules.match(str(path)):
                matches.append({
                    "rule": str(match.rule),
                    "namespace": str(match.namespace),
                    "source": str(rule_file),
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                })
        except Exception as exc:
            matches.append({"rule": "YARA_ERROR", "source": str(rule_file), "error": str(exc)})
    return matches
