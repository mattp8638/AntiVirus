#!/usr/bin/env python3
"""Fenrir acceptance harness: proves what the platform actually does on real devices.

It talks to a running Fenrir server through its public API, sends real work to enrolled devices and waits for the
agent's own result - a script's output, a quarantined test file, a temporary admin account that exists and is then
gone. Each check passes, fails or is skipped, with the evidence it saw, written to report.json and report.md.

Run it against a lab (see docs/ACCEPTANCE_LAB.md), never against customers' machines:

    python3 scripts/acceptance/fenrir_acceptance.py --server https://rmm.lab.example --email lab-admin@example.com \\
        --password ... [--mfa-code 123456] --device LAB-WIN11 --device LAB-UBUNTU --out acceptance-report

    --token fac_...      an API credential instead; it can run the read-only checks, but credentials deliberately cannot
                         run scripts or grant admin rights, so most checks need a lab administrator's sign-in
    --scenario a,b       run only these (``--list`` shows them all)
    --disruptive         also run checks that cut the device off for a moment (network isolation)
    --insecure           accept a self-signed lab certificate

Only the Python standard library is used, so it runs anywhere Python 3.10+ does. Exit code 0 means every check that
ran passed.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

TERMINAL_COMMAND_STATES = {"completed", "failed", "cancelled", "expired", "rejected", "superseded"}
MARKER = "fenrir-acceptance"


class ApiError(RuntimeError):
    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}")
        self.status, self.detail = status, detail


class Api:
    """A small JSON client for the console API."""

    def __init__(self, server: str, insecure: bool = False, timeout: float = 30.0):
        self.base = server.rstrip("/")
        self.token = ""
        self.timeout = timeout
        self.context = ssl._create_unverified_context() if insecure else ssl.create_default_context()  # noqa: S323 - lab option

    def call(self, method: str, path: str, body: dict | None = None, query: dict | None = None):
        url = f"{self.base}/api/console/{path.lstrip('/')}"
        if query:
            url += "?" + urllib.parse.urlencode({k: v for k, v in query.items() if v not in (None, "")})
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            try:
                detail = json.loads(detail).get("detail", detail)
            except (ValueError, AttributeError):
                pass
            raise ApiError(exc.code, str(detail)[:500]) from None
        return json.loads(raw) if raw else None

    def get(self, path: str, **query):
        return self.call("GET", path, query=query)

    def post(self, path: str, body: dict | None = None):
        return self.call("POST", path, body or {})

    def login(self, email: str, password: str, code: str = "") -> None:
        body = {"email": email, "password": password, **({"code": code} if code else {})}
        self.token = self.call("POST", "auth/login", body)["token"]


@dataclass
class Outcome:
    scenario: str
    device: str
    status: str  # pass | fail | skip
    detail: str
    seconds: float = 0.0
    evidence: dict = field(default_factory=dict)


def annotate(outcome: Outcome) -> None:
    """Under GitHub Actions, each result also becomes an annotation on the run (and its pull request)."""
    if os.environ.get("GITHUB_ACTIONS") != "true" or outcome.status == "skip":
        return

    def escape(text: str, title: bool = False) -> str:
        text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        return text.replace(":", "%3A").replace(",", "%2C") if title else text

    level = "notice" if outcome.status == "pass" else "error"
    detail = outcome.detail + (f" {json.dumps(outcome.evidence)[:600]}" if outcome.evidence else "")
    print(f"::{level} title={escape(f'{outcome.scenario} on {outcome.device}', title=True)}::{escape(detail[:1500])}",
          flush=True)


class Check(Exception):
    """Raised by a scenario to fail with a reason; ``Skip`` to skip."""


class Skip(Exception):
    pass


def wait_for(what: str, probe, timeout: float, interval: float = 5.0):
    """Calls probe() until it returns something truthy, or fails after timeout seconds."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last:
            return last
        time.sleep(interval)
    raise Check(f"timed out after {int(timeout)} s waiting for {what}")


def iso_age_seconds(value: str | None) -> float:
    if not value:
        return float("inf")
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - moment).total_seconds()


class Context:
    """What scenarios share: the API, options and a cache of scripts this run created."""

    def __init__(self, api: Api, args: argparse.Namespace):
        self.api, self.args = api, args
        self.scripts: dict[str, str] = {}

    def device(self, device_id: str) -> dict:
        return self.api.get(f"devices/{device_id}")

    def command(self, device: dict, kind: str, payload: dict | None = None, target_path: str = "", timeout: float | None = None) -> dict:
        """Queues a command and waits for the agent to finish it; returns the finished command."""
        queued = self.api.post(f"devices/{device['id']}/commands", {"type": kind, "payload": payload or {}, "targetPath": target_path,
                                                                    "reason": f"Acceptance check ({kind})"})

        def finished():
            for row in self.api.get("commands", device_id=device["id"]):
                if row["id"] == queued["id"] and row["status"] in TERMINAL_COMMAND_STATES:
                    return row
            return None

        row = wait_for(f"{kind} to finish on {device['hostname']}", finished, timeout or self.args.timeout)
        if row["status"] != "completed":
            raise Check(f"{kind} ended {row['status']}: {json.dumps(row.get('result') or {})[:300]}")
        return row

    def script(self, device: dict, name: str, language: str, body: str, timeout: float | None = None) -> dict:
        """Runs a script through the library and job system (as a technician would) and returns the device's result."""
        key = f"{name}/{language}"
        if key not in self.scripts:
            full_name = f"Fenrir acceptance: {name}"
            platforms = ["windows"] if language == "powershell" else ["linux", "macos"]
            existing = next((s for s in self.api.get("rmm/scripts") if s.get("name") == full_name and s.get("language") == language), None)
            if existing and existing.get("body") != body:
                self.api.call("PATCH", f"rmm/scripts/{existing['id']}", {"body": body})
            script = existing or self.api.post("rmm/scripts", {"name": full_name, "language": language, "body": body,
                                                               "platforms": platforms, "category": "Acceptance", "timeoutSeconds": 300,
                                                               "description": "Created by scripts/acceptance/fenrir_acceptance.py"})
            self.scripts[key] = script["id"]
        job = self.api.post(f"rmm/scripts/{self.scripts[key]}/run", {"targets": {"deviceIds": [device["id"]]}})

        def result():
            detail = self.api.get(f"rmm/jobs/{job['id']}")
            rows = detail.get("results") or []
            return rows[0] if rows and rows[0]["status"] in TERMINAL_COMMAND_STATES else None

        row = wait_for(f"script {name!r} on {device['hostname']}", result, timeout or self.args.timeout)
        if row["status"] != "completed":
            raise Check(f"script {name!r} ended {row['status']}: {row.get('error') or row.get('stderr') or ''}"[:400])
        return row


# --------------------------------------------------------------------------- scenarios

SCENARIOS: dict[str, dict] = {}


def scenario(name: str, platforms: tuple[str, ...], description: str, disruptive: bool = False):
    def register(fn):
        SCENARIOS[name] = {"run": fn, "platforms": platforms, "description": description, "disruptive": disruptive}
        return fn
    return register


def is_windows(device: dict) -> bool:
    return (device.get("platform") or "").lower() == "windows"


@scenario("checks_in", ("windows", "linux", "macos"), "Approved, reporting, and still checking in")
def checks_in(ctx: Context, device: dict) -> tuple[str, dict]:
    if not device.get("approved"):
        raise Check("the device is waiting for approval in the console")
    first = device.get("lastSeenAt")
    if iso_age_seconds(first) > 600:
        raise Check(f"last check-in was {first}; the agent is not reporting")

    def newer():
        seen = ctx.device(device["id"])["device"].get("lastSeenAt")
        return seen if seen and seen != first else None

    seen = wait_for("a new check-in", newer, max(ctx.args.timeout, 180), interval=10)
    return f"checked in again at {seen}", {"agentVersion": device.get("agentVersion"), "os": device.get("osVersion"), "lastSeenAt": seen}


@scenario("policy", ("windows", "linux", "macos"), "Takes the current policy revision")
def policy(ctx: Context, device: dict) -> tuple[str, dict]:
    ctx.command(device, "policy.refresh")
    detail = wait_for("the policy to be applied", lambda: (d := ctx.device(device["id"]))["policy"]["applied"] and d, ctx.args.timeout)
    return f"policy revision {str(detail['policy']['revision'])[:12]} applied", {"revision": detail["policy"]["revision"]}


@scenario("inventory", ("windows", "linux", "macos"), "Reports hardware and software inventory on request")
def inventory(ctx: Context, device: dict) -> tuple[str, dict]:
    ctx.command(device, "inventory.refresh")
    data = ctx.device(device["id"])["device"].get("inventory") or {}
    if not data:
        raise Check("the device finished inventory.refresh but sent no inventory")
    shown = {k: v for k, v in data.items() if isinstance(v, (str, int, float)) and v != ""}
    return f"{len(data)} inventory fields", dict(list(shown.items())[:12])


@scenario("script", ("windows", "linux", "macos"), "Runs a library script and returns its real output")
def script(ctx: Context, device: dict) -> tuple[str, dict]:
    if is_windows(device):
        row = ctx.script(device, "echo", "powershell", f'Write-Output "{MARKER}-$($env:COMPUTERNAME)"; exit 0')
    else:
        row = ctx.script(device, "echo", "bash", f'#!/bin/sh\necho "{MARKER}-$(hostname)"\n')
    if row.get("exitCode") not in (0, None) or MARKER not in (row.get("stdout") or ""):
        raise Check(f"unexpected output (exit {row.get('exitCode')}): {(row.get('stdout') or '')[:200]!r}")
    return "script ran and returned its output", {"stdout": row["stdout"].strip()[:200], "exitCode": row.get("exitCode"),
                                                   "durationMs": row.get("durationMs")}


# The EICAR test string, built at run time so neither this file nor the script text is itself flagged.
_EICAR_PARTS = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*")


@scenario("eicar", ("windows", "linux", "macos"), "Detects and quarantines the EICAR anti-malware test file")
def eicar(ctx: Context, device: dict) -> tuple[str, dict]:
    # The scripts assemble the string from parts, so no script text or command payload holds the whole test string.
    if is_windows(device):
        parts = "+".join("'" + p.replace("'", "''") + "'" for p in _EICAR_PARTS)
        row = ctx.script(device, "write EICAR test file", "powershell", f"""
$folder = 'C:\\ProgramData\\FenrirAcceptance'
New-Item -ItemType Directory -Force -Path $folder | Out-Null
$path = Join-Path $folder ('eicar-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + '.com')
[IO.File]::WriteAllText($path, {parts})
Write-Output ('PATH=' + $path)""")
    else:
        assignments = "\n".join(f"p{i}='{p}'" for i, p in enumerate(_EICAR_PARTS))
        row = ctx.script(device, "write EICAR test file", "bash", f"""#!/bin/sh
{assignments}
folder=/var/tmp/fenrir-acceptance
mkdir -p "$folder"
path="$folder/eicar-$(date +%s).com"
printf '%s%s%s' "$p0" "$p1" "$p2" > "$path"
echo "PATH=$path"
""")
    path = next((line[5:].strip() for line in (row.get("stdout") or "").splitlines() if line.startswith("PATH=")), "")
    if not path:
        raise Check(f"the test file was not written: {(row.get('stdout') or row.get('stderr') or '')[:200]!r}")
    scan: dict = {}
    try:  # real-time protection may already have taken it; a targeted scan covers agents that only scan on demand
        scan = ctx.command(device, "scan.targeted", target_path=path).get("result") or {}
    except Check as exc:
        scan = {"error": str(exc)}
    name = path.replace("\\", "/").rsplit("/", 1)[-1]

    def caught():
        held = [q for q in ctx.api.get("protection/quarantine", device_id=device["id"]) if name in str(q.get("path", ""))]
        if held:
            return {"via": "quarantine", "threat": held[0].get("threat"), "path": held[0].get("path")}
        flagged = [a for a in ctx.api.get("alerts", device_id=device["id"], snoozed="all") if name in json.dumps(a.get("details") or {})]
        return {"via": "alert", "threat": flagged[0]["title"]} if flagged else None

    try:
        found = wait_for(f"{name} to be quarantined or alerted", caught, ctx.args.timeout)
    except Check as exc:  # say what the device did report, so the cause is in the log
        events = (ctx.api.get("events", device_id=device["id"], hours=1, limit=2000) or {}).get("events", [])
        keys = ("disposition", "remediationStatus", "quarantineRecordId", "remediationError", "heuristicScore", "reputation")
        scans = [f"{str(e.get('occurredAt') or '')[11:19]} {e.get('eventType')} "
                 + json.dumps({k: (e.get('fields') or {}).get(k) for k in keys if (e.get('fields') or {}).get(k) not in (None, '')})
                 for e in events if str(e.get("eventType", "")).startswith(("scan.", "quarantine", "realtime.protection", "threat."))][:8]
        latest = [f"{str(e.get('occurredAt') or '')[11:19]} {e.get('eventType')}" for e in events[:5]]
        raise Check(f"{exc}. Targeted scan result: {json.dumps(scan)[:300]}. Scan and quarantine events the server holds: "
                    f"{scans or 'none'}. Latest events: {latest}") from None
    return f"detected via {found['via']} as {found.get('threat')}", {**found, "file": path, "scan": scan}


_PAM_USER = "fenrir-acc-user"


@scenario("pam", ("windows",), "Grants a temporary admin account, then removes it")
def pam(ctx: Context, device: dict) -> tuple[str, dict]:
    # A standard (non-admin) local user to grant rights to; created on first use, removed at the end.
    setup = ctx.script(device, "pam user", "powershell", f"""
$name = '{_PAM_USER}'
if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {{
  $secret = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'aA1!') -AsPlainText -Force
  New-LocalUser -Name $name -Password $secret -Description 'Fenrir acceptance test user' | Out-Null
}}
Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $name -ErrorAction SilentlyContinue
Write-Output ("SID=" + (Get-LocalUser -Name $name).SID.Value)
Write-Output ("HOST=" + $env:COMPUTERNAME)""")
    lines = dict(line.split("=", 1) for line in (setup.get("stdout") or "").splitlines() if "=" in line)
    sid, host = lines.get("SID", "").strip(), lines.get("HOST", "").strip()
    if not sid.startswith("S-1-5-21-"):
        raise Check(f"could not prepare the test user: {(setup.get('stdout') or '')[:200]!r}")
    granted = ctx.api.post("elevation-requests", {"deviceId": device["id"], "user": f"{host}\\{_PAM_USER}", "userSid": sid,
                                                  "minutes": 5, "reason": "Acceptance check: temporary admin account"})
    request_id = granted["id"]

    def state(want: set[str]):
        row = ctx.api.get(f"elevation-requests/{request_id}")
        return row if row["status"] in want else None

    row = wait_for("the temporary admin account", lambda: state({"granted", "failed"}), ctx.args.timeout)
    if row["status"] != "granted" or not row.get("account"):
        raise Check(f"grant ended {row['status']}: {row.get('note')}")
    account = row["account"]
    check = """
$name = '{account}'
$user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
$admin = [bool](Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like "*\\$name" }})
Write-Output ("EXISTS=" + [bool]$user)
Write-Output ("ADMIN=" + $admin)"""
    present = ctx.script(device, "pam check", "powershell", check.format(account=account))
    if "EXISTS=True" not in present.get("stdout", "") or "ADMIN=True" not in present.get("stdout", ""):
        raise Check(f"{account} should exist and be an administrator: {present.get('stdout')!r}")
    ctx.api.post(f"elevation-requests/{request_id}/revoke")

    def removed():  # endedAt is set when the device reports that the account is gone
        row = ctx.api.get(f"elevation-requests/{request_id}")
        return row if row.get("endedAt") else None

    ended = wait_for("the device to report the account removed", removed, ctx.args.timeout)
    gone = ctx.script(device, "pam check", "powershell", check.format(account=account))
    if "EXISTS=False" not in gone.get("stdout", ""):
        raise Check(f"{account} still exists after revocation: {gone.get('stdout')!r}")
    ctx.script(device, "pam cleanup", "powershell", f"Remove-LocalUser -Name '{_PAM_USER}' -ErrorAction SilentlyContinue; exit 0")
    trail = [e["type"] for e in ended.get("events") or []]
    return f"{account} created as an administrator, then removed", {"account": account, "timeline": trail, "endReason": ended.get("endReason")}


@scenario("isolation", ("windows", "linux", "macos"), "Isolates the device and releases it again", disruptive=True)
def isolation(ctx: Context, device: dict) -> tuple[str, dict]:
    ctx.command(device, "device.isolate")
    if not ctx.device(device["id"])["device"].get("isolated"):
        raise Check("isolate finished but the device is not marked isolated")
    ctx.command(device, "device.release")
    released = wait_for("release", lambda: not ctx.device(device["id"])["device"].get("isolated"), ctx.args.timeout)
    return "isolated and released; the device still reports", {"released": bool(released)}


@scenario("patch_scan", ("windows", "linux"), "Scans for missing updates")
def patch_scan(ctx: Context, device: dict) -> tuple[str, dict]:
    row = ctx.command(device, "patch.scan", timeout=max(ctx.args.timeout, 900))
    result = row.get("result") or {}
    return "update scan finished", {k: v for k, v in result.items() if isinstance(v, (str, int, float, bool))}


@scenario("telemetry_volume", ("windows", "linux", "macos"), "Sends a sustainable amount of telemetry")
def telemetry_volume(ctx: Context, device: dict) -> tuple[str, dict]:
    """Two budgets. Busy: events a minute since the agent enrolled, while the other checks ran scripts, scans and
    admin changes, against --max-busy-events-per-minute (the server's per-device cap by default). Idle: events a
    minute over --idle-seconds with nothing asked of the device, against --max-events-per-minute: what every device
    costs all day. Stored and capped events both count."""
    enrolled = str(ctx.device(device["id"])["device"].get("enrolledAt") or "")
    try:
        started = datetime.fromisoformat(enrolled.replace("Z", "+00:00"))
        minutes = max(1, min(60, int((datetime.now(timezone.utc) - started).total_seconds() // 60)))
    except ValueError:
        minutes = 60

    def counted(window: int) -> tuple[int, dict]:
        volume = ctx.api.get("platform/telemetry-volume", device_id=device["id"], minutes=window)
        return volume["events"] + volume.get("notStored", 0), volume

    busy_total, busy = counted(minutes)
    busy_rate = busy_total / minutes
    time.sleep(45)  # let the busy period's last batches arrive
    before, before_volume = counted(60)
    idle_from = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    time.sleep(ctx.args.idle_seconds)
    after, idle = counted(60)
    idle_rate = (after - before) / (ctx.args.idle_seconds / 60)
    earlier = {t["eventType"]: t["events"] for t in before_volume["byType"]}
    idle_types = sorted(((t["eventType"], t["events"] - earlier.get(t["eventType"], 0)) for t in idle["byType"]),
                        key=lambda item: -item[1])
    # Which processes started while nothing was asked of the device, and what started them.
    events = (ctx.api.get("events", device_id=device["id"], hours=1, limit=2000) or {}).get("events", [])
    started = {}
    for event in events:
        if str(event.get("eventType", "")).startswith("process.start") and str(event.get("occurredAt", "")) >= idle_from:
            fields = event.get("fields") or {}
            key = f"{str(fields.get('Image') or '').rsplit(chr(92), 1)[-1]} <- {str(fields.get('ParentImage') or '').rsplit(chr(92), 1)[-1]}"
            started[key] = started.get(key, 0) + 1
    evidence = {"busyPerMinute": round(busy_rate, 1), "busyMinutes": minutes, "idlePerMinute": round(idle_rate, 1),
                "idleSeconds": ctx.args.idle_seconds, "notStored": idle.get("notStored", 0),
                "idleTopTypes": dict((k, v) for k, v in idle_types[:8] if v > 0),
                "idleProcesses": dict(sorted(started.items(), key=lambda item: -item[1])[:8]),
                "busyTopTypes": {t["eventType"]: t["events"] for t in busy["byType"][:8]}}
    problems = []
    if busy_rate > ctx.args.max_busy_events_per_minute:
        problems.append(f"{busy_rate:.0f} a minute while busy (budget {ctx.args.max_busy_events_per_minute:.0f})")
    if idle_rate > ctx.args.max_events_per_minute:
        problems.append(f"{idle_rate:.0f} a minute idle (budget {ctx.args.max_events_per_minute:.0f})")
    if problems:
        raise Check(f"too much telemetry: {'; '.join(problems)}; idle: {evidence['idleTopTypes']}, processes started "
                    f"while idle (image <- parent): {evidence['idleProcesses']}; busy: {evidence['busyTopTypes']}")
    return f"{idle_rate:.0f} events a minute idle, {busy_rate:.0f} while busy", evidence


@scenario("false_positives", ("windows", "linux", "macos"), "Quarantines and alerts on nothing but the test files")
def false_positives(ctx: Context, device: dict) -> tuple[str, dict]:
    """Run it last. Everything the agent quarantined or raised as malware since it was installed, its own first scan
    included, must be one of the harness's test files. On Windows it also scans signed Microsoft programs outside
    System32, the case that once quarantined the Azure guest agent."""
    scanned = ""
    if is_windows(device):
        scanned = r"C:\Program Files\Windows Defender"
        try:
            ctx.command(device, "scan.targeted", target_path=scanned, timeout=max(ctx.args.timeout, 600))
        except Check as exc:
            if "does not exist" not in str(exc):
                raise
            scanned = ""

    def ours(text: str) -> bool:
        return "fenriracceptance" in text.lower().replace("-", "").replace("_", "")

    held = [str(q.get("path") or "") for q in ctx.api.get("protection/quarantine", device_id=device["id"])
            if not ours(str(q.get("path") or ""))]
    flagged = [f"{a.get('title')}: {(a.get('details') or {}).get('file') or a.get('summary') or ''}"
               for a in ctx.api.get("alerts", device_id=device["id"], snoozed="all")
               if str(a.get("ruleId") or "").startswith("fenrir-av-") and not ours(json.dumps(a.get("details") or {}))]
    if held or flagged:
        raise Check(f"legitimate files were treated as malware. Quarantined: {held[:10]}. Alerted: {flagged[:10]}")
    return "nothing but the test files was quarantined or alerted", {"alsoScanned": scanned}


# --------------------------------------------------------------------------- runner


def find_device(api: Api, name: str, wait: float) -> dict:
    """The enrolled device with this hostname (or id), waiting up to ``wait`` seconds for a freshly installed agent."""
    short = name.lower().split(".")[0]  # Windows reports NETBIOS names; Linux may report a full domain name

    def lookup():
        matches = [d for d in api.get("devices", q=short)
                   if d["id"] == name or d["hostname"].lower() == name.lower() or d["hostname"].lower().split(".")[0] == short]
        return max(matches, key=lambda d: d.get("lastSeenAt") or "") if matches else None

    found = lookup()
    if found is None and wait > 0:
        print(f"Waiting up to {int(wait)} s for {name} to enrol…", flush=True)
        try:
            found = wait_for(f"{name} to enrol", lookup, wait)
        except Check:
            found = None
    if found is None:
        raise SystemExit(f"No device called {name!r}. Enrol it first; see docs/ACCEPTANCE_LAB.md.")
    return found


def run(api: Api, args: argparse.Namespace) -> list[Outcome]:
    chosen = [s.strip() for s in args.scenario.split(",")] if args.scenario else list(SCENARIOS)
    unknown = [s for s in chosen if s not in SCENARIOS]
    if unknown:
        raise SystemExit(f"Unknown scenario(s): {', '.join(unknown)}. Use --list.")
    ctx = Context(api, args)
    outcomes: list[Outcome] = []
    for name in args.device:
        device = find_device(api, name, args.wait_for_device)
        for key in chosen:
            spec = SCENARIOS[key]
            platform = (device.get("platform") or "").lower()
            started = time.monotonic()
            if platform not in spec["platforms"]:
                outcome = Outcome(key, device["hostname"], "skip", f"not for {platform}")
            elif spec["disruptive"] and not args.disruptive:
                outcome = Outcome(key, device["hostname"], "skip", "disruptive: run with --disruptive")
            else:
                print(f"[{device['hostname']}] {key}: {spec['description']}…", flush=True)
                try:
                    detail, evidence = spec["run"](ctx, ctx.device(device["id"])["device"])
                    outcome = Outcome(key, device["hostname"], "pass", detail, evidence=evidence)
                except Skip as exc:
                    outcome = Outcome(key, device["hostname"], "skip", str(exc))
                except (Check, ApiError) as exc:
                    outcome = Outcome(key, device["hostname"], "fail", str(exc))
            outcome.seconds = round(time.monotonic() - started, 1)
            print(f"[{device['hostname']}] {key}: {outcome.status.upper()} - {outcome.detail}", flush=True)
            annotate(outcome)
            outcomes.append(outcome)
    return outcomes


def write_report(outcomes: list[Outcome], out: Path, server: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (out / "report.json").write_text(json.dumps({"server": server, "finishedAt": stamp,
                                                 "outcomes": [asdict(o) for o in outcomes]}, indent=2))
    icon = {"pass": "PASS", "fail": "FAIL", "skip": "skip"}
    lines = [f"# Fenrir acceptance report", "", f"Server: {server} · finished {stamp}", "",
             "| Device | Check | Result | Detail | Seconds |", "|---|---|---|---|---|"]
    for o in outcomes:
        lines.append(f"| {o.device} | {o.scenario} | {icon[o.status]} | {o.detail.replace('|', '/')} | {o.seconds} |")
    counts = {s: sum(1 for o in outcomes if o.status == s) for s in ("pass", "fail", "skip")}
    lines += ["", f"{counts['pass']} passed, {counts['fail']} failed, {counts['skip']} skipped.", "",
              "Evidence for each check is in report.json."]
    (out / "report.md").write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--server", help="Fenrir URL, e.g. https://rmm.lab.example")
    parser.add_argument("--token", help="API credential (fac_...)")
    parser.add_argument("--email")
    parser.add_argument("--password")
    parser.add_argument("--mfa-code", default="")
    parser.add_argument("--device", action="append", default=[], help="hostname or device id; repeat for several")
    parser.add_argument("--scenario", default="", help="comma-separated; default all")
    parser.add_argument("--disruptive", action="store_true")
    parser.add_argument("--timeout", type=float, default=300.0, help="seconds to wait for each result")
    parser.add_argument("--max-events-per-minute", type=float, default=60.0,
                        help="telemetry_volume: events a minute an idle device may send (default 60)")
    parser.add_argument("--max-busy-events-per-minute", type=float, default=600.0,
                        help="telemetry_volume: events a minute while the checks keep it busy (default 600, the server's cap)")
    parser.add_argument("--idle-seconds", type=float, default=120.0, help="telemetry_volume: length of the idle window")
    parser.add_argument("--wait-for-device", type=float, default=0.0, help="seconds to wait for a just-installed agent to enrol")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--out", default="acceptance-report")
    parser.add_argument("--list", action="store_true", help="list the checks and exit")
    args = parser.parse_args(argv)
    if args.list:
        for name, spec in SCENARIOS.items():
            print(f"{name:16} {'/'.join(spec['platforms']):22} {'(disruptive) ' if spec['disruptive'] else ''}{spec['description']}")
        return 0
    if not args.server or not args.device or not (args.token or (args.email and args.password)):
        parser.error("--server, at least one --device, and --token or --email/--password are required")
    api = Api(args.server, insecure=args.insecure)
    if args.token:
        api.token = args.token
    else:
        api.login(args.email, args.password, args.mfa_code)
    outcomes = run(api, args)
    write_report(outcomes, Path(args.out), args.server)
    failed = [o for o in outcomes if o.status == "fail"]
    print(f"\n{len(outcomes) - len(failed)} of {len(outcomes)} checks did not fail; report in {args.out}/report.md")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
