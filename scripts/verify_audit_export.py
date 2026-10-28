#!/usr/bin/env python3
"""Verify a Fenrir audit export offline (CORE-06). Uses only the Python standard library.

    python3 verify_audit_export.py fenrir-audit-YYYYMMDDHHMM.jsonl [--checkpoint SEQ:HASH ...]

Checks that every row with content still matches its hash, that each row links to the previous one, that no
positions are missing, and that the chain passes through every checkpoint in the export header - and through any
checkpoint you kept elsewhere (for example from a webhook), given with --checkpoint. Redacted rows (another
customer's activity) are linked but their content cannot be rechecked. Exit code 0 means the export verifies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys


def row_digest(prev_hash: str, row: dict) -> str:
    canonical = json.dumps({"tenant": row["tenant"], "actor": row["actor"], "action": row["action"], "target": row["target"],
                            "details": row["details"], "at": row["at"]}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def verify(lines: list[dict], extra_checkpoints: dict[int, str]) -> list[str]:
    header, rows = lines[0], lines[1:]
    if header.get("format") != "fenrir-audit-export/1":
        return ["not a Fenrir audit export (format header missing)"]
    problems = []
    anchor = header.get("anchor") or {}
    prev_hash, prev_seq = anchor.get("hash", ""), anchor.get("seq", 0)
    seen: dict[int, str] = {}
    for row in rows:
        seq = row.get("seq")
        if seq is not None and prev_seq is not None and seq != prev_seq + 1:
            problems.append(f"positions {prev_seq + 1}..{seq - 1} are missing before row {seq}")
        if row.get("prevHash") != prev_hash:
            problems.append(f"row {seq} does not link to the previous row")
        if not row.get("redacted") and row_digest(row["prevHash"], row) != row["hash"]:
            problems.append(f"row {seq} was changed after it was written")
        seen[seq] = row["hash"]
        prev_hash, prev_seq = row["hash"], seq
    checkpoints = {c["seq"]: c["hash"] for c in header.get("checkpoints", [])} | extra_checkpoints
    for seq, expected in sorted(checkpoints.items()):
        if seq <= (anchor.get("seq") or 0):
            continue
        if seq not in seen:
            if seq <= (prev_seq or 0):
                problems.append(f"checkpoint at {seq} is missing from the chain")
        elif seen[seq] != expected:
            problems.append(f"chain does not match the checkpoint at {seq}: rows up to it were rewritten")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("export")
    parser.add_argument("--checkpoint", action="append", default=[], help="SEQ:HASH kept outside Fenrir")
    args = parser.parse_args()
    with open(args.export, encoding="utf-8") as handle:
        lines = [json.loads(line) for line in handle if line.strip()]
    extra = {}
    for item in args.checkpoint:
        seq, _, digest = item.partition(":")
        extra[int(seq)] = digest
    problems = verify(lines, extra)
    rows = len(lines) - 1
    if problems:
        print(f"FAILED: {len(problems)} problem(s) in {rows} rows")
        for p in problems[:100]:
            print(" -", p)
        return 1
    print(f"OK: {rows} rows verify" + (f" (from anchor {lines[0]['anchor']['seq']})" if lines[0].get("anchor") else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
