import shutil
from datetime import datetime
from pathlib import Path

QUARANTINE_DIR = Path("data") / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def quarantine_file(path: Path, sha256_value: str) -> str:
    safe_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{sha256_value}_{path.name}.quarantine"
    target = QUARANTINE_DIR / safe_name
    shutil.move(str(path), str(target))
    return str(target)
