#!/usr/bin/env python3
"""Supply-chain check (AGT-09): every dependency install in CI and the image build is locked.

Fails when a workflow or Dockerfile
  * installs Python packages from ranges instead of a hash lock (``pip install --require-hashes -r <lock>``) or
    exact ``==`` pins,
  * runs ``npm install`` instead of ``npm ci`` (a one-off tool is allowed only at an exact ``@x.y.z``),
  * runs cargo build/test/run/clippy/install without ``--locked``,
or when a Python lock no longer satisfies the requirement ranges it was compiled from (someone edited
requirements.txt without regenerating the lock), or a lock entry has no hash.

A line that must stay unlocked carries ``supply-chain: unlocked`` and the reason in a comment on the same line,
so every exception is visible in review. Standard library only; run from anywhere:
    python3 scripts/supply_chain_check.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOW = "supply-chain: unlocked"
# Python locks and the inputs they were compiled from.
LOCKS = {
    "cloud/requirements.lock": ["cloud/requirements.txt"],
    "cloud/requirements-dev.lock": ["cloud/requirements.txt"],
    "ml/requirements-ci.lock": ["ml/requirements.txt"],
}

EXACT_PY = re.compile(r"^[A-Za-z0-9_.\-\[\]]+==[0-9][0-9A-Za-z.\-+]*$")
EXACT_NPM = re.compile(r"^(@[^/]+/)?[^@\s]+@\d+\.\d+\.\d+$")


def _commands(path: Path):
    """(line number, logical command line) pairs, with backslash continuations joined."""
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        start, text = i + 1, lines[i]
        while text.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            text = text.rstrip()[:-1] + " " + lines[i].strip()
        yield start, text
        i += 1


def _args_after(text: str, verb: str) -> list[str]:
    tail = text.split(verb, 1)[1]
    tail = re.split(r"&&|\|\||;|#|\|", tail, maxsplit=1)[0]
    return [a.strip("\"'") for a in tail.split()]


def check_installs(path: Path) -> list[str]:
    problems = []
    rel = path.relative_to(ROOT)
    for no, text in _commands(path):
        if ALLOW in text:
            continue
        code = text.split(" #", 1)[0]
        if re.search(r"\bpip3? install\b", code):
            args = _args_after(code, "install")
            if "-r" in args or "--requirement" in args:
                files = [args[k + 1] for k, a in enumerate(args) if a in ("-r", "--requirement") and k + 1 < len(args)]
                if "--require-hashes" not in args or not all(f.endswith(".lock") for f in files):
                    problems.append(f"{rel}:{no}: pip installs {', '.join(files)} without --require-hashes from a .lock")
            else:
                pkgs = [a for a in args if not a.startswith("-") and not a.startswith("$")]
                loose = [p for p in pkgs if not EXACT_PY.match(p) and p not in (".", "-e")]
                if loose:
                    problems.append(f"{rel}:{no}: pip installs unpinned {', '.join(loose)}")
        if re.search(r"\bnpm (install|i)\b", code):
            args = _args_after(code, "npm install" if "npm install" in code else "npm i")
            pkgs, skip = [], False
            for a in args:
                if skip:
                    skip = False
                    continue
                if a in ("--prefix", "--registry"):
                    skip = True
                    continue
                if not a.startswith("-"):
                    pkgs.append(a)
            if not pkgs:
                problems.append(f"{rel}:{no}: npm install (use npm ci against package-lock.json)")
            else:
                loose = [p for p in pkgs if not EXACT_NPM.match(p)]
                if loose:
                    problems.append(f"{rel}:{no}: npm installs unpinned {', '.join(loose)}")
        if re.search(r"\bcargo (build|test|run|clippy|install)\b", code) and "--locked" not in code:
            problems.append(f"{rel}:{no}: cargo without --locked")
    return problems


def _parse_lock(path: Path) -> dict[str, tuple[str, int]]:
    """name -> (version, number of hashes)."""
    out: dict[str, tuple[str, int]] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s\\;]+)", line)
        if m:
            current = _norm(m.group(1))
            out[current] = (m.group(2), 0)
        elif current and "--hash=sha256:" in line:
            v, n = out[current]
            out[current] = (v, n + 1)
        elif line and not line.startswith(" "):
            current = None
    return out


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _version_tuple(v: str):
    parts = []
    for p in re.split(r"[.+-]", v):
        parts.append((0, int(p)) if p.isdigit() else (1, p))
    return parts


def _satisfies(version: str, spec: str) -> bool:
    for clause in filter(None, (c.strip() for c in spec.split(","))):
        m = re.match(r"(==|>=|<=|~=|!=|>|<)\s*(.+)", clause)
        if not m:
            continue
        op, want = m.groups()
        a, b = _version_tuple(version), _version_tuple(want.rstrip(".*"))
        if op == "==" and not (want.endswith(".*") and a[: len(b)] == b or a == b):
            return False
        if op == "!=" and a == b:
            return False
        if op == ">=" and a < b or op == ">" and a <= b or op == "<=" and a > b or op == "<" and a >= b:
            return False
        if op == "~=" and (a < b or a[: len(b) - 1] != b[: len(b) - 1]):
            return False
    return True


def check_locks() -> list[str]:
    problems = []
    for lock, inputs in LOCKS.items():
        lock_path = ROOT / lock
        if not lock_path.exists():
            problems.append(f"{lock}: missing")
            continue
        pinned = _parse_lock(lock_path)
        for name, (version, hashes) in pinned.items():
            if hashes == 0:
                problems.append(f"{lock}: {name}=={version} has no hash")
        for req_file in inputs:
            for raw in (ROOT / req_file).read_text(encoding="utf-8").splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*([^;]*)", line)
                if not m:
                    continue
                name, spec = _norm(m.group(1)), m.group(3).strip()
                if name not in pinned:
                    problems.append(f"{lock}: {name} from {req_file} is not locked; regenerate the lock")
                elif not _satisfies(pinned[name][0], spec):
                    problems.append(f"{lock}: {name}=={pinned[name][0]} does not satisfy {spec!r} in {req_file}")
    return problems


def main() -> int:
    files = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    files += sorted(ROOT.glob("deploy/**/Dockerfile*")) + sorted(ROOT.glob("components/**/Dockerfile*"))
    problems = []
    for f in files:
        problems += check_installs(f)
    problems += check_locks()
    for p in problems:
        print(p)
    print(f"supply-chain check: {len(files)} build files, {len(LOCKS)} locks, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
