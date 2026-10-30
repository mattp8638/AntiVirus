#!/usr/bin/env python3
"""Prints what a Windows agent holds locally: its recent scan verdicts, quarantine records, command journal and the
telemetry still waiting to upload. Run it as an administrator on the device when the console does not show
something the agent should have reported.

    python agent_state.py                 # finds agent-runtime.db under ProgramData or Program Files
    python agent_state.py --db path\\to\\agent-runtime.db
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

QUERIES = (
    ("Telemetry waiting to upload, by type",
     "SELECT event_type, COUNT(*) FROM telemetry_queue GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 10"),
    ("Latest scan verdicts",
     "SELECT recorded_at, subject_path, disposition, confidence, remediation_status, quarantine_record_id"
     " FROM scan_history ORDER BY scan_id DESC LIMIT 5"),
    ("Quarantine records", "SELECT record_id, captured_at, original_path, local_status FROM quarantine_index LIMIT 10"),
    ("Latest commands", "SELECT type, status, substr(coalesce(last_error, ''), 1, 160) FROM command_journal"
                        " ORDER BY updated_at DESC LIMIT 8"),
)


def find_database(roots: list[Path]) -> Path | None:
    for root in roots:
        for folder, _, files in os.walk(root):  # unreadable folders are skipped
            if "agent-runtime.db" in files:
                return Path(folder) / "agent-runtime.db"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--db", type=Path)
    parser.add_argument("--search", type=Path, action="append", default=[],
                        help="folder to search for agent-runtime.db (default: ProgramData and Program Files)")
    args = parser.parse_args()
    roots = args.search or [Path(os.environ.get(name, default)) for name, default in
                            (("ProgramData", r"C:\ProgramData"), ("ProgramFiles", r"C:\Program Files"))]
    path = args.db or find_database(roots)
    if path is None or not path.exists():
        print("No agent-runtime.db found.")
        return 1
    print(f"Agent database: {path}")
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    except sqlite3.Error as exc:
        print(f"Cannot open it: {exc}")
        return 1
    for title, sql in QUERIES:
        print(f"-- {title}")
        try:
            rows = db.execute(sql).fetchall()
        except sqlite3.Error as exc:
            print(f"   (unreadable: {exc})")
            continue
        for row in rows or [("(none)",)]:
            print("   " + " | ".join("" if v is None else str(v) for v in row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
