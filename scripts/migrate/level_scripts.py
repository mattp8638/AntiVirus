#!/usr/bin/env python3
"""Move your Level.io scripts into Fenrir's script library, categorised and grouped.

Run it on the machine where the Level CLI (`lvl`) is signed in. Standard library only.

    lvl auth login && lvl auth status

    # 1. Export every script from Level (bodies included) to level-scripts.json
    python3 level_scripts.py export

    # 2. Work out category, group, language and platforms; writes level-plan.csv for you to check and edit
    python3 level_scripts.py plan

    # 3. Import into Fenrir (an API credential with the "configure" scope: Settings > API credentials)
    FENRIR_URL=https://rmm.example.com FENRIR_API_KEY=<key> python3 level_scripts.py import --dry-run
    FENRIR_URL=https://rmm.example.com FENRIR_API_KEY=<key> python3 level_scripts.py import

How it maps Level to Fenrir:
- Category: Level's own folder/category/tags when present, otherwise from what the script does (keywords in its
  name, description and body: Maintenance, Security, Software, Networking, ...). Grouping uses Fenrir's
  "Group / Category" naming, e.g. "Level / Security", so the library's category filter keeps them together.
  Change either column in level-plan.csv before importing.
- Language and platforms: from Level's shell/language field, else from the body (shebang, PowerShell syntax).
- Level variables written as {{name}} become Fenrir script parameters (a form when the script is run) and are
  rewritten as $name / ${name}. Custom-field variables ({{cf_owner}}) read the device's Fenrir custom field instead
  ($env:FENRIR_CF_OWNER); the plan's notes list the custom fields to create in Fenrir.
- Importing again updates scripts with the same name instead of duplicating them (--skip-existing leaves them).
  Imported or changed scripts wait for a second person's review before they can run, as with any library edit.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

LANGS = {"powershell": ("windows",), "cmd": ("windows",), "bash": ("linux", "macos"), "sh": ("linux", "macos"),
         "zsh": ("macos",), "python": ("windows", "linux", "macos")}
LANG_ALIASES = {"ps": "powershell", "ps1": "powershell", "pwsh": "powershell", "powershell": "powershell",
                "batch": "cmd", "bat": "cmd", "cmd": "cmd", "bash": "bash", "shell": "sh", "sh": "sh", "zsh": "zsh",
                "python": "python", "python3": "python", "py": "python"}
OS_ALIASES = {"windows": "windows", "win": "windows", "linux": "linux", "mac": "macos", "macos": "macos", "darwin": "macos",
              "osx": "macos"}
# First match wins: (category, keywords in name/description/body). Ordered from specific to general.
CATEGORIES = [
    ("Security", r"defender|antivirus|bitlocker|firewall|mfa|password|credential|security|vulnerab|cve|tls|smb ?v?1|"
                 r"audit ?policy|local admin|laps|uac|encrypt|malware|threat"),
    ("Patching", r"windows ?update|wuauserv|patch|hotfix|kb\d{6,}|upgrade os|feature update|softwareupdate"),
    ("Software", r"install|uninstall|winget|choco|msiexec|\.msi\b|brew |apt(-get)? |yum |dnf |package|application"),
    ("Networking", r"network|dns|dhcp|ip ?config|wifi|wi-fi|vpn|proxy|ping|tracert|netsh|adapter|port\b|nslookup"),
    ("Users and identity", r"user profile|active directory|\bad\b|azure ?ad|entra|intune|group policy|gpupdate|"
                           r"local user|logged.?on|sign.?in"),
    ("Maintenance", r"clean|temp files|disk ?cleanup|cache|restart|reboot|service|chkdsk|sfc |dism|defrag|"
                    r"spooler|print|log ?files|optimi[sz]e|repair|reset"),
    ("Monitoring", r"check|monitor|health|uptime|disk (space|usage)|free space|df -h|cpu|memory|event ?log|alert|status|battery"),
    ("Inventory", r"inventory|serial|warranty|hardware|software list|installed|report|bios|model|asset"),
    ("Backup", r"backup|restore|snapshot|vss|shadow copy"),
]
VAR = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.\-]{0,63})\s*\}\}")
PLAN_FIELDS = ["import", "level_id", "name", "group", "category", "language", "platforms", "run_as", "timeout_seconds",
               "parameters", "description", "notes"]


def first(d: dict, *keys, default=None):
    for key in keys:
        value = d.get(key)
        if value not in (None, "", []):
            return value
    return default


# --------------------------------------------------------------------------- export


def parse_json(text: str):
    """JSON, or JSON Lines (one object per line), as some CLIs print for lists."""
    text = text.strip()
    try:
        return json.loads(text)
    except ValueError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows


def run_lvl(command: str) -> object:
    out = subprocess.run(shlex.split(command), capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"`{command}` failed ({out.returncode}): {out.stderr.strip()[:500]}")
    try:
        return parse_json(out.stdout)
    except ValueError:
        raise SystemExit(f"`{command}` did not print JSON. First output: {out.stdout[:300]!r}") from None


def _looks_like_script(d: dict) -> bool:
    keys = {k.lower() for k in d}
    return bool(keys & {"name", "title"}) and bool(keys & {"id", "uuid", "scriptid", "content", "body", "script", "code",
                                                           "language", "shell", "scripttype", "description"})


def as_list(data) -> list[dict]:
    """The scripts in whatever shape the CLI printed: a list, or a list somewhere inside wrapper objects
    (data, items, nodes, edges[].node...). Picks the largest list of script-like objects found."""
    best: list[dict] = []

    def walk(node, depth=0):
        nonlocal best
        if depth > 6:
            return
        if isinstance(node, list):
            items = [x.get("node", x) if isinstance(x, dict) and isinstance(x.get("node"), dict) else x for x in node]
            dicts = [x for x in items if isinstance(x, dict)]
            if dicts and sum(_looks_like_script(x) for x in dicts) >= max(1, len(dicts) // 2) and len(dicts) > len(best):
                best = dicts
            for x in items:
                walk(x, depth + 1)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value, depth + 1)

    if isinstance(data, dict) and _looks_like_script(data):
        return [data]
    walk(data)
    if best:
        return best
    # Nothing obviously script-shaped: fall back to a plain list, or one under a usual wrapper key.
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for key in ("scripts", "data", "items", "results", "nodes"):
            if isinstance(data.get(key), (list, dict)):
                return as_list(data[key])
    return []


def describe(data) -> str:
    if isinstance(data, list):
        return f"a list of {len(data)} items" + (f"; first item keys: {sorted(data[0])[:15]}" if data and isinstance(data[0], dict) else "")
    if isinstance(data, dict):
        return f"an object with keys {sorted(data)[:15]}"
    return type(data).__name__


def body_of(script: dict) -> str:
    return str(first(script, "content", "body", "script", "code", "source", "command", "scriptContent", default="") or "")


def export(args) -> None:
    raw = run_lvl(args.list_cmd)
    scripts = as_list(raw)
    if not scripts:
        raise SystemExit(f"No scripts found in the output of `{args.list_cmd}` (it printed {describe(raw)}). "
                         "If Level has scripts, run that command yourself and send the first lines of its output.")
    print(f"{len(scripts)} scripts listed")
    missing = [s for s in scripts if not body_of(s)]
    for n, script in enumerate(missing, 1):
        sid = first(script, "id", "uuid", "scriptId")
        if not sid:
            continue
        try:
            detail = run_lvl(args.show_cmd.format(id=shlex.quote(str(sid))))
        except SystemExit as exc:
            print(f"  could not fetch {first(script, 'name', 'title', default=sid)}: {exc}", flush=True)
            continue
        found = as_list(detail)
        detail = found[0] if found else (detail.get("script", detail) if isinstance(detail, dict) else {})
        script.update({k: v for k, v in detail.items() if v not in (None, "", [])})
        print(f"  fetched {n}/{len(missing)}: {first(script, 'name', 'title', default=sid)}", flush=True)
    Path(args.out).write_text(json.dumps(scripts, indent=2))
    empty = sum(1 for s in scripts if not body_of(s))
    print(f"Saved {len(scripts)} scripts to {args.out}" + (f" ({empty} without a body: check the show command)" if empty else ""))


def export_from_file(args) -> None:
    raw = parse_json(Path(args.from_file).read_text())
    scripts = as_list(raw)
    if not scripts:
        raise SystemExit(f"No scripts found in {args.from_file} (it holds {describe(raw)}).")
    Path(args.out).write_text(json.dumps(scripts, indent=2))
    print(f"Copied {len(scripts)} scripts to {args.out}")


# --------------------------------------------------------------------------- plan


def language_of(script: dict, body: str) -> str:
    named = str(first(script, "language", "shell", "scriptType", "type", "interpreter", default="")).strip().lower()
    if named in LANG_ALIASES:
        return LANG_ALIASES[named]
    first_line = body.lstrip().split("\n", 1)[0].lower()
    if first_line.startswith("#!"):
        for word, lang in (("python", "python"), ("zsh", "zsh"), ("bash", "bash"), ("sh", "sh"), ("pwsh", "powershell")):
            if word in first_line:
                return lang
    if re.search(r"\$env:|Get-[A-Z]|Set-[A-Z]|Write-(Host|Output)|\[CmdletBinding|-ErrorAction|\$PSVersionTable", body):
        return "powershell"
    if re.search(r"^@echo off|^\s*(set|if exist|goto) ", body, re.I | re.M):
        return "cmd"
    if re.search(r"^\s*(echo|if \[|fi$|apt|brew|sudo|export \w+=)", body, re.M):
        return "bash"
    return "powershell"


def platforms_of(script: dict, language: str) -> list[str]:
    raw = first(script, "platforms", "platform", "os", "operatingSystems", "operatingSystem", default=[])
    raw = raw if isinstance(raw, list) else re.split(r"[,/ ]+", str(raw))
    found = sorted({OS_ALIASES[str(p).strip().lower()] for p in raw if str(p).strip().lower() in OS_ALIASES})
    allowed = LANGS[language]
    return [p for p in found if p in allowed] or list(allowed)


def category_of(script: dict, body: str) -> tuple[str, str]:
    """(category, where it came from)."""
    level = first(script, "category", "folder", "folderName", "group", "groupName", "collection")
    if isinstance(level, dict):
        level = first(level, "name", "title")
    tags = first(script, "tags", "labels", default=[])
    if level:
        return str(level).strip()[:60], "level"
    if isinstance(tags, list) and tags:
        tag = tags[0].get("name") if isinstance(tags[0], dict) else tags[0]
        if tag:
            return str(tag).strip()[:60], "level tag"
    text = " ".join([str(first(script, "name", "title", default="")), str(first(script, "description", default="")), body[:4000]])
    for category, pattern in CATEGORIES:
        if re.search(pattern, text, re.I):
            return category, "auto"
    return "General", "auto"


def parameters_of(body: str, script: dict) -> tuple[list[dict], list[str]]:
    params, notes, seen = [], [], set()
    declared = {str(first(v, "name", "key", default="")): v for v in (first(script, "variables", "parameters", "inputs", default=[]) or [])
                if isinstance(v, dict)}
    for raw in VAR.findall(body):
        name = re.sub(r"[^A-Za-z0-9_]", "_", raw)
        if name in seen:
            continue
        seen.add(name)
        if cf_key(raw):
            notes.append(f"{{{{{raw}}}}} reads Fenrir custom field '{cf_key(raw)}': create it in Settings > Custom fields")
            continue
        spec = declared.get(raw, {})
        params.append({"name": name, "label": str(first(spec, "label", "displayName", default=raw.replace('_', ' ')))[:80],
                       "type": "string", "default": str(first(spec, "default", "defaultValue", default="")),
                       "required": bool(first(spec, "required", default=False))})
    return params, notes


def cf_key(raw: str) -> str:
    """The Fenrir custom field key for a Level custom-field variable ({{cf_owner}} -> owner), or ""."""
    match = re.match(r"(?i)^(cf_|custom_field_|customfield_|custom_fields\.)(.+)$", raw)
    return re.sub(r"[^a-z0-9_]", "_", match.group(2).lower())[:60] if match else ""


def _reference(raw: str, language: str) -> str:
    key = cf_key(raw)
    if key:  # Fenrir sets FENRIR_CF_<KEY> for every script run on a device
        env = f"FENRIR_CF_{key.upper()}"
        return {"powershell": f"$env:{env}", "cmd": f"%{env}%", "python": f"os.environ.get('{env}', '')"}.get(language, "${" + env + "}")
    name = re.sub(r"[^A-Za-z0-9_]", "_", raw)
    return {"powershell": f"${name}", "cmd": f"%{name}%", "python": name}.get(language, "${" + name + "}")


QUOTED_VAR = re.compile(r"'\{\{\s*([A-Za-z_][A-Za-z0-9_.\-]{0,63})\s*\}\}'")


def rewrite_variables(body: str, language: str) -> str:
    """Level pastes values into the text; Fenrir passes them as variables. '{{x}}' on its own becomes a double-quoted
    (expanding) reference; other placeholders inside single quotes are left for review (see quoting_notes)."""
    if language in ("powershell", "bash", "sh", "zsh"):
        body = QUOTED_VAR.sub(lambda m: f'"{_reference(m.group(1), language)}"', body)
    return VAR.sub(lambda m: _reference(m.group(1), language), body)


def quoting_notes(body: str, language: str) -> list[str]:
    if language not in ("powershell", "bash", "sh", "zsh"):
        return []
    rest = QUOTED_VAR.sub("", body)
    inside = [m for line in rest.splitlines() for m in re.findall(r"'[^']*\{\{[^}]+\}\}[^']*'", line)]
    return [f"check quoting: {inside[0][:60]} is in single quotes, which do not expand variables"] if inside else []


def plan(args) -> None:
    scripts = json.loads(Path(args.export).read_text())
    rows = []
    for script in scripts:
        body = body_of(script)
        name = str(first(script, "name", "title", default="")).strip()
        language = language_of(script, body)
        category, source = category_of(script, body)
        params, notes = parameters_of(body, script)
        notes += quoting_notes(body, language)
        if not body:
            notes.append("no script body in the export")
        if source == "auto":
            notes.append("category guessed from the content")
        timeout = first(script, "timeout", "timeoutSeconds", "timeout_seconds", default=args.timeout)
        try:
            timeout = max(10, min(86400, int(timeout)))
        except (TypeError, ValueError):
            timeout = args.timeout
        run_as = "user" if str(first(script, "runAs", "run_as", "context", default="system")).lower() in ("user", "logged_in_user", "current_user") else "system"
        rows.append({"import": "yes" if body and name else "no", "level_id": first(script, "id", "uuid", default=""), "name": name[:200],
                     "group": args.group, "category": category, "language": language,
                     "platforms": ",".join(platforms_of(script, language)), "run_as": run_as, "timeout_seconds": timeout,
                     "parameters": ",".join(p["name"] for p in params),
                     "description": str(first(script, "description", "summary", default="")).replace("\n", " ")[:500],
                     "notes": "; ".join(notes)})
    names = {}
    for row in rows:
        names.setdefault(row["name"].lower(), []).append(row)
    for dupes in names.values():
        for n, row in enumerate(dupes[1:], 2):
            row["name"] = f"{row['name']} ({n})"
            row["notes"] = "; ".join(filter(None, [row["notes"], "renamed: another Level script has the same name"]))
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=PLAN_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    from collections import Counter
    counts = Counter(f"{r['group']} / {r['category']}" if r["group"] else r["category"] for r in rows)
    print(f"Planned {len(rows)} scripts in {args.out}. Check and edit the group, category and import columns, then run import.")
    for key, count in sorted(counts.items()):
        print(f"  {key}: {count}")
    flagged = [r for r in rows if r["notes"] and "guessed" not in r["notes"]]
    if flagged:
        print(f"{len(flagged)} have notes to read (custom fields, missing bodies, renamed duplicates).")


# --------------------------------------------------------------------------- import


class Fenrir:
    def __init__(self, url: str, key: str, insecure: bool) -> None:
        self.url, self.key = url.rstrip("/"), key
        self.context = ssl._create_unverified_context() if insecure else None

    def call(self, method: str, path: str, body: dict | None = None):
        req = urllib.request.Request(f"{self.url}/api/console/rmm/{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60, context=self.context) as resp:
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from None


def import_scripts(args) -> None:
    url, key = os.getenv("FENRIR_URL", args.url or ""), os.getenv("FENRIR_API_KEY", "")
    if not url or not key:
        raise SystemExit("Set FENRIR_URL and FENRIR_API_KEY (an API credential with the configure scope).")
    if not Path(args.export).exists():
        raise SystemExit(f"{args.export} not found: run `export` first.")
    if not Path(args.plan).exists():
        raise SystemExit(f"{args.plan} not found: run `plan` first, check the CSV (group, category, import), then import.")
    by_id = {str(first(s, "id", "uuid", default="")): s for s in json.loads(Path(args.export).read_text())}
    by_name = {str(first(s, "name", "title", default="")).strip(): s for s in by_id.values()}
    rows = [r for r in csv.DictReader(open(args.plan, newline="")) if r["import"].strip().lower() in ("yes", "y", "1", "true")]
    fenrir = Fenrir(url, key, args.insecure)
    existing = {} if args.dry_run else {s["name"]: s for s in fenrir.call("GET", "scripts") if s.get("tenantId")}
    created = updated = skipped = failed = unchanged = 0
    for row in rows:
        source = by_id.get(row["level_id"]) or by_name.get(row["name"].split(" (")[0]) or {}
        language = row["language"].strip().lower()
        if language not in LANGS:
            print(f"  SKIP {row['name']}: language {language!r} is not one of {sorted(LANGS)}")
            skipped += 1
            continue
        raw_body = body_of(source)
        params, _ = parameters_of(raw_body, source)
        wanted = {p.strip() for p in row["parameters"].split(",") if p.strip()}
        category = f"{row['group'].strip()} / {row['category'].strip()}" if row["group"].strip() else row["category"].strip()
        payload = {"name": row["name"], "description": row["description"], "category": category[:80] or "General",
                   "language": language, "platforms": [p for p in row["platforms"].split(",") if p.strip()] or list(LANGS[language]),
                   "body": rewrite_variables(raw_body, language), "parameters": [p for p in params if p["name"] in wanted],
                   "runAs": row["run_as"] or "system", "timeoutSeconds": int(row["timeout_seconds"] or args.timeout)}
        if args.tenant:
            payload["tenantId"] = args.tenant
        if not payload["body"].strip():
            print(f"  SKIP {row['name']}: no body")
            skipped += 1
            continue
        if args.dry_run:
            print(f"  would import {row['name']!r} -> {payload['category']} ({language}, {', '.join(payload['platforms'])}, "
                  f"{len(payload['parameters'])} parameters)")
            continue
        try:
            current = existing.get(row["name"])
            if current and args.skip_existing:
                skipped += 1
                continue
            same = current and all(current.get(k) == v for k, v in payload.items() if k != "tenantId")
            if same:
                unchanged += 1
                continue
            if current:
                fenrir.call("PATCH", f"scripts/{current['id']}", {k: v for k, v in payload.items() if k != "tenantId"})
                updated += 1
                print(f"  updated {row['name']}")
            else:
                fenrir.call("POST", "scripts", payload)
                created += 1
                print(f"  created {row['name']}")
        except RuntimeError as exc:
            failed += 1
            print(f"  FAILED {row['name']}: {exc}")
    if args.dry_run:
        print(f"Dry run: {len(rows) - skipped} would be imported, {skipped} skipped. Nothing was changed.")
    else:
        print(f"Done: {created} created, {updated} updated, {unchanged} unchanged, {skipped} skipped, {failed} failed. "
              "They wait for a second person's review (Scripts) before they can run.")
    if failed:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("\n\n", 1)[1])
    sub = parser.add_subparsers(dest="step", required=True)
    e = sub.add_parser("export", help="save Level's scripts (with their bodies) to JSON")
    e.add_argument("--list-cmd", default="lvl script list --limit all -o json")
    e.add_argument("--show-cmd", default="lvl script get {id} -o json",
                   help="command for one script's full detail when the list leaves out bodies; {id} is replaced")
    e.add_argument("--from", dest="from_file", help="use a JSON file you saved from the Level CLI instead of running it")
    e.add_argument("--out", default="level-scripts.json")
    p = sub.add_parser("plan", help="categorise and group; writes a CSV to check")
    p.add_argument("--export", default="level-scripts.json")
    p.add_argument("--group", default="Level", help='group prefix for categories, e.g. "Level / Security" ("" for none)')
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--out", default="level-plan.csv")
    i = sub.add_parser("import", help="create or update the scripts in Fenrir")
    i.add_argument("--export", default="level-scripts.json")
    i.add_argument("--plan", default="level-plan.csv")
    i.add_argument("--url", help="Fenrir server URL (or FENRIR_URL)")
    i.add_argument("--tenant", help="customer (tenant id) to own the scripts; default: the API credential's own")
    i.add_argument("--timeout", type=int, default=600)
    i.add_argument("--skip-existing", action="store_true", help="leave scripts that already exist by name")
    i.add_argument("--dry-run", action="store_true")
    i.add_argument("--insecure", action="store_true", help="accept a self-signed HTTPS certificate")
    args = parser.parse_args()
    if args.step == "export":
        export_from_file(args) if args.from_file else export(args)
    elif args.step == "plan":
        plan(args)
    else:
        import_scripts(args)


if __name__ == "__main__":
    main()
