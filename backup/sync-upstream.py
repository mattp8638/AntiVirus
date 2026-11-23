#!/usr/bin/env python3
"""Keep backup/ in step with Fenrir-Backup, where the shared backup code lives.

Fenrir-Backup (github.com/zy538324/Fenrir-Backup) is the standalone backup product and the single source of
the code both products use: the agent, CLI, engine, formats, file browsing, boot checks and recovery
environment. Change that code there first, then bring it here:

    python3 backup/sync-upstream.py ../Fenrir-Backup          # copy the shared code, record the commit
    python3 backup/sync-upstream.py ../Fenrir-Backup --check  # exit 1 if backup/ has drifted from it

Everything else under backup/ (this script, UPSTREAM, Cargo.lock, THIRD_PARTY.md, docs/DEPLOY.md, ci/) belongs to
Fenrir Cloud. After a sync, run `cargo check` in backup/ and update THIRD_PARTY.md if dependencies changed.
"""

import filecmp
import shutil
import subprocess
import sys
from pathlib import Path

SHARED = [
    "crates/agent", "crates/cli", "crates/core-format", "crates/engine", "crates/filebrowse",
    "crates/nbd-server", "crates/protocol", "crates/snapshot-linux", "crates/snapshot-win",
    "crates/vdisk", "crates/vmboot", "crates/s3store", "recovery-env", "fuzz",
    "deny.toml", "SECURITY.md", "scripts/third-party.py",
    "docs/CLI.md", "docs/FORMAT.md", "docs/SECURITY-CODE-OF-PRACTICE.md", "docs/design",
]
SKIP = {"target", "node_modules", "__pycache__", "corpus", "artifacts", "coverage"}
HERE = Path(__file__).resolve().parent


def files(root: Path):
    if root.is_file():
        yield Path()
        return
    if not root.is_dir():
        return
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if p.is_file() and not SKIP.intersection(rel.parts):
            yield rel


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    check = "--check" in sys.argv
    if len(args) != 1:
        raise SystemExit(__doc__)
    src = Path(args[0]).resolve()
    if not (src / "crates" / "server").is_dir():
        raise SystemExit(f"{src} is not a Fenrir-Backup checkout")
    commit = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()

    drift = []
    for item in SHARED:
        a, b = src / item, HERE / item
        ours, theirs = set(files(b)), set(files(a))
        for rel in sorted(theirs | ours):
            fa, fb = a / rel, b / rel
            if rel not in theirs:
                drift.append(f"only in Fenrir Cloud: {item}/{rel}".rstrip("/."))
                if not check:
                    fb.unlink()
            elif rel not in ours or not filecmp.cmp(fa, fb, shallow=False):
                drift.append(f"{'missing' if rel not in ours else 'differs'}: {item}/{rel}".rstrip("/."))
                if not check:
                    fb.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(fa, fb)
        if not check and b.is_dir():
            for d in sorted((p for p in b.rglob("*") if p.is_dir()), reverse=True):
                if not any(d.iterdir()):
                    d.rmdir()

    if check:
        pinned = (HERE / "UPSTREAM").read_text().split()[-1] if (HERE / "UPSTREAM").exists() else "?"
        if drift:
            print(f"backup/ differs from Fenrir-Backup {commit[:12]} (UPSTREAM pins {pinned[:12]}):")
            print("\n".join(f"  {d}" for d in drift))
            print("Make shared changes in Fenrir-Backup, then run backup/sync-upstream.py here.")
            raise SystemExit(1)
        print(f"backup/ matches Fenrir-Backup {commit[:12]}")
        return
    (HERE / "UPSTREAM").write_text(f"https://github.com/zy538324/Fenrir-Backup {commit}\n")
    print(f"{len(drift)} file(s) updated from Fenrir-Backup {commit[:12]}")
    print("\n".join(f"  {d}" for d in drift))
    print("Next: cargo check in backup/, and update THIRD_PARTY.md if dependencies changed.")


if __name__ == "__main__":
    main()
