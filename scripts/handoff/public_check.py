#!/usr/bin/env python3
"""Before the final public release: list private names and hard-coded addresses left in the repository.

    python3 scripts/handoff/public_check.py                     # report
    python3 scripts/handoff/public_check.py --private "Acme,OFFICE-PC1"   # also look for your own private words
    python3 scripts/handoff/public_check.py --strict            # exit 1 if anything is found (for CI)

Two kinds of finding:
- private: words that identify you, your company or your machines (built-in list plus --private and the
  FENRIR_PRIVATE_WORDS environment variable, comma-separated). These must go before publishing.
- static: hard-coded addresses of services the project used to run (feed, signing timestamp, download hosts).
  A fork must be able to run with none of them; each should be a setting with no default, or removed.

Tracked files only (git ls-files). Binary files and third-party code are skipped.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILT_IN_PRIVATE = ["palmertech", "palmer tech"]
# The public repository's own address is allowed to appear (install command, docs site, signing info link).
ALLOWED = ["Palmertech-Webdev/fenrir-security"]
STATIC = [r"fenrir-security\.co\.uk", r"api\.fenrir-security", r"palmertech\.co\.uk"]
SKIP_PARTS = ("third_party/", "node_modules/", "/vendor/", "components/", "dist/")
SKIP_SUFFIX = (".png", ".jpg", ".ico", ".exe", ".dll", ".zip", ".pfx", ".onnx", ".bin", ".gz", ".woff", ".woff2", ".pdf", ".jar")


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [p for p in out.splitlines() if not p.startswith(SKIP_PARTS) and not any(s in p for s in SKIP_PARTS[1:])
            and not p.lower().endswith(SKIP_SUFFIX) and p != "scripts/handoff/public_check.py"]


def scan(private: list[str]) -> list[tuple[str, str, int, str]]:
    patterns = [("private", re.compile(re.escape(w), re.I)) for w in private if w] + \
               [("static", re.compile(p, re.I)) for p in STATIC]
    findings = []
    for path in tracked():
        try:
            text = (ROOT / path).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for allowed in ALLOWED:
                line = re.sub(re.escape(allowed), "", line, flags=re.I)
            for kind, pattern in patterns:
                if pattern.search(line):
                    findings.append((kind, path, number, line.strip()[:140]))
                    break
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--private", default="", help="extra private words, comma-separated")
    parser.add_argument("--strict", action="store_true", help="exit 1 if anything is found")
    args = parser.parse_args()
    words = BUILT_IN_PRIVATE + [w.strip() for w in (args.private + "," + os.getenv("FENRIR_PRIVATE_WORDS", "")).split(",")]
    findings = scan(words)
    for kind in ("private", "static"):
        rows = [f for f in findings if f[0] == kind]
        print(f"\n{kind.upper()} ({len(rows)})")
        for _, path, number, line in rows:
            print(f"  {path}:{number}: {line}")
    if not findings:
        print("Nothing found: ready to publish.")
    return 1 if findings and args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
