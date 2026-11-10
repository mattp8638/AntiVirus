#!/usr/bin/env python3
"""Checksums for the community catalogue: every app and script file must be listed in MANIFEST.sha256.

    python3 catalogue/manifest.py --write   # after adding or changing files (part of every catalogue pull request)
    python3 catalogue/manifest.py --check   # CI: fails if a file changed without its checksum, or is not listed

The server loads only files whose checksum matches the manifest, so an unreviewed edit on a server is ignored.
"""
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "MANIFEST.sha256"


def files() -> list[Path]:
    return sorted([*ROOT.glob("apps/*.yml"), *ROOT.glob("scripts/windows/*.ps1"), *ROOT.glob("scripts/unix/*.sh")])


def entries() -> str:
    return "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT).as_posix()}\n" for p in files())


def main(argv: list[str]) -> int:
    if "--write" in argv:
        MANIFEST.write_text(entries())
        print(f"wrote {len(files())} entries to {MANIFEST.name}")
        return 0
    if "--check" in argv:
        current = MANIFEST.read_text() if MANIFEST.exists() else ""
        if current != entries():
            print("MANIFEST.sha256 is out of date: run python3 catalogue/manifest.py --write and commit it", file=sys.stderr)
            return 1
        print(f"manifest matches {len(files())} files")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
