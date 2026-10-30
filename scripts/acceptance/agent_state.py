#!/usr/bin/env python3
"""Prints what a Windows agent holds locally: its recent scan verdicts, quarantine records, command journal and the
telemetry still waiting to upload. Run it as an administrator on the device when the console does not show
something the agent should have reported.

    python agent_state.py                 # finds agent-runtime.db under ProgramData or Program Files
    python agent_state.py --db path\\to\\agent-runtime.db
"""
from __future__ import annotations

import argparse
import json
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
    print("-- Why the latest files were flagged (rule codes from their evidence records)")
    try:
        rows = db.execute("SELECT s.subject_path, s.disposition, e.record_path FROM scan_history s"
                          " JOIN evidence_index e ON e.record_id = s.evidence_record_id"
                          " ORDER BY s.scan_id DESC LIMIT 8").fetchall()
    except sqlite3.Error as exc:
        rows = []
        print(f"   (unreadable: {exc})")
    for subject, disposition, record_path in rows:
        print(f"   {subject} [{disposition}]: {', '.join(reason_codes(Path(record_path))) or '(no evidence file)'}")
    return 0


def reason_codes(record: Path) -> list[str]:
    try:
        return [r.get("code", "") for r in json.loads(record.read_text(encoding="utf-8", errors="replace")).get("reasons", [])]
    except (OSError, ValueError, AttributeError):
        return []


if __name__ == "__main__":
    sys.exit(main())
