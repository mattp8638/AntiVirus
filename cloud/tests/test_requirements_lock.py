"""The Docker image installs only requirements.lock (hash-locked). Every package named in requirements.txt must be in
it, or production fails at import time while tests, which install requirements.txt, still pass."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _name(line: str) -> str | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "--")):
        return None
    m = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", line)
    return re.sub(r"[-_.]+", "-", m.group(0)).lower() if m else None


def test_every_requirement_is_in_the_deploy_lock():
    wanted = {n for n in map(_name, (ROOT / "requirements.txt").read_text().splitlines()) if n}
    locked = {re.sub(r"[-_.]+", "-", m.group(1)).lower()
              for m in re.finditer(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==", (ROOT / "requirements.lock").read_text(), re.M)}
    missing = sorted(wanted - locked)
    assert not missing, f"Regenerate requirements.lock (see requirements-deploy.in): missing {missing}"
