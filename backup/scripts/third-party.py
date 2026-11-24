#!/usr/bin/env python3
"""Print every non-dev dependency of the workspace as name|version|licence.

Used to refresh THIRD_PARTY.md. Run from the repository root.
"""
import json
import subprocess

m = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1"]))
ws = set(m["workspace_members"])
pkgs = {p["id"]: p for p in m["packages"]}
nodes = {n["id"]: n for n in m["resolve"]["nodes"]}
seen, stack = set(), list(ws)
while stack:
    i = stack.pop()
    if i in seen:
        continue
    seen.add(i)
    for d in nodes[i]["deps"]:
        if any(k["kind"] in (None, "build") for k in d["dep_kinds"]):
            stack.append(d["pkg"])
for name, ver, lic in sorted((pkgs[i]["name"], pkgs[i]["version"], pkgs[i]["license"] or "?") for i in seen - ws):
    print(f"{name}|{ver}|{lic}")
