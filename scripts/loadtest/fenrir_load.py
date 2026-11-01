#!/usr/bin/env python3
"""Load test: many simulated agents against a Fenrir server, to measure what it can carry.

    python3 scripts/loadtest/fenrir_load.py --server http://127.0.0.1:8080 --email admin@example.com \\
        --password ... --devices 500 --minutes 5 --out load-500

Each simulated agent enrols, then behaves like the real ones: it asks for commands every 15 seconds, uploads a
telemetry batch every 30 seconds (--events-per-minute events: process starts, network connections, DNS lookups,
file writes and script scans), sends a heartbeat with health metrics every 60 seconds and checks in its policy every
5 minutes. Start times are spread out so the load is steady rather than a stampede.

The report gives latency percentiles and errors for each call, the telemetry rate the server absorbed, whether every
event was stored, and whether background work (scheduler, maintenance, event outbox) kept up during the run. It
exits non-zero if more than 1% of calls failed or the 95th percentile of any call exceeded --max-p95-ms.

Standard library only. Run it against a lab server: it creates a customer called "Load Test" and N devices.
"""
from __future__ import annotations

import argparse
import heapq
import json
import os
import random
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "acceptance"))
from fenrir_acceptance import Api  # noqa: E402

COMMANDS_EVERY, TELEMETRY_EVERY, HEARTBEAT_EVERY, POLICY_EVERY = 15.0, 30.0, 60.0, 300.0
PROCESSES = [r"C:\Windows\System32\svchost.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
             r"C:\Windows\explorer.exe", r"C:\Windows\System32\conhost.exe"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _event(device: str, i: int) -> dict:
    image = random.choice(PROCESSES)
    roll = random.random()
    if roll < 0.5:
        kind, payload = "process.start", {"processImagePath": image, "commandLine": f'"{image}" --task {i}',
                                          "parentProcessImagePath": r"C:\Windows\explorer.exe", "pid": random.randint(1000, 60000)}
    elif roll < 0.7:
        kind, payload = "network.connection", {"processImagePath": image, "remoteAddress": f"52.{i % 250}.{random.randint(0, 250)}.10",
                                               "remotePort": 443, "protocol": "tcp"}
    elif roll < 0.85:
        kind, payload = "dns.query", {"processImagePath": image, "queryName": f"cdn{random.randint(1, 40)}.example.com"}
    elif roll < 0.95:
        kind, payload = "file.created", {"path": rf"C:\Users\user\AppData\Local\Temp\tmp{random.randint(1, 99999)}.dat",
                                         "processImagePath": image}
    else:
        kind, payload = "amsi.scan", {"appName": "PowerShell", "contentName": "", "blocked": False, "disposition": "allow",
                                      "preview": "Get-ChildItem -Path C:\\Users"}
    return {"eventId": f"{device}-{uuid.uuid4().hex[:16]}", "eventType": kind, "source": "load-test", "occurredAt": _now(),
            "summary": f"{kind} {image.rsplit(chr(92), 1)[-1]}", "payloadJson": json.dumps(payload)}


class Recorder:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.calls: dict[str, list[float]] = {}
        self.errors: dict[str, list[str]] = {}
        self.events_sent = 0

    def record(self, name: str, seconds: float, error: str = "") -> None:
        with self.lock:
            self.calls.setdefault(name, []).append(seconds * 1000)
            if error:
                self.errors.setdefault(name, []).append(error)

    def summary(self) -> dict:
        out = {}
        with self.lock:
            for name, values in sorted(self.calls.items()):
                ordered = sorted(values)

                def pct(p: float) -> float:
                    return round(ordered[min(len(ordered) - 1, int(len(ordered) * p))], 1)

                out[name] = {"calls": len(values), "errors": len(self.errors.get(name, [])), "p50": pct(0.5),
                             "p95": pct(0.95), "p99": pct(0.99), "max": round(ordered[-1], 1),
                             "mean": round(statistics.fmean(values), 1),
                             "sampleErrors": sorted(set(self.errors.get(name, [])))[:3]}
        return out


class Agent:
    def __init__(self, server: str, index: int, recorder: Recorder, events_per_minute: int, timeout: float) -> None:
        self.server, self.index, self.recorder, self.timeout = server.rstrip("/"), index, recorder, timeout
        self.events_per_batch = max(1, round(events_per_minute * TELEMETRY_EVERY / 60))
        self.device_id = ""
        self.key = ""
        self.revision = ""

    def call(self, name: str, method: str, path: str, body: dict | None = None, headers: dict | None = None) -> dict | None:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.server + path, data=data, method=method,
                                         headers={"Content-Type": "application/json", **(headers or {})})
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read()
            self.recorder.record(name, time.monotonic() - started)
            return json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            self.recorder.record(name, time.monotonic() - started, f"HTTP {exc.code}")
        except Exception as exc:  # noqa: BLE001 - timeouts and resets count as errors
            self.recorder.record(name, time.monotonic() - started, type(exc).__name__)
        return None

    def enrol(self, token: str) -> bool:
        result = self.call("enrol", "POST", "/api/v1/enroll",
                           {"hostname": f"LOAD-{self.index:05d}", "osVersion": "Windows 11 Pro 23H2", "platform": "windows",
                            "serialNumber": f"LOAD-{self.index:05d}", "agentVersion": "load-test"},
                           {"X-Fenrir-Token": token})
        if not result:
            return False
        self.device_id, self.key = result["deviceId"], result["deviceApiKey"]
        return True

    @property
    def auth(self) -> dict:
        return {"X-Device-Api-Key": self.key}

    def commands(self) -> None:
        self.call("commands.pending", "GET", f"/api/v1/devices/{self.device_id}/commands/pending?limit=20", headers=self.auth)

    def telemetry(self) -> None:
        events = [_event(self.device_id, i) for i in range(self.events_per_batch)]
        if self.call("telemetry", "POST", f"/api/v1/devices/{self.device_id}/telemetry", {"events": events}, self.auth) is not None:
            with self.recorder.lock:
                self.recorder.events_sent += len(events)

    def heartbeat(self) -> None:
        self.call("heartbeat", "POST", f"/api/v1/devices/{self.device_id}/heartbeat",
                  {"agentVersion": "load-test", "healthState": "healthy",
                   "metrics": {"cpuPercent": random.randint(2, 60), "memoryPercent": random.randint(30, 85),
                               "uptimeSeconds": 86400, "disks": [{"name": "C:", "freePercent": random.randint(15, 70)}]}},
                  self.auth)

    def policy(self) -> None:
        result = self.call("policy-check-in", "POST", f"/api/v1/devices/{self.device_id}/policy-check-in",
                           {"currentPolicyRevision": self.revision}, self.auth)
        if result:
            self.revision = result.get("policy", {}).get("revision", self.revision)


def run(args: argparse.Namespace) -> dict:
    api = Api(args.server, insecure=args.insecure)
    api.login(args.email, args.password)
    tenant = next((t for t in api.get("tenants") if t.get("name") == args.customer), None)
    tenant = tenant or api.post("tenants", {"name": args.customer, "template": "balanced"})
    token = api.post("enrollment-tokens", {"tenantId": tenant["id"], "label": "load test"})["token"]

    # Load a healthy server only: then background work falling behind during the run is the load's doing.
    waited = time.monotonic()
    while not _background(args).get("ok"):
        if time.monotonic() - waited > args.wait_healthy:
            raise SystemExit(f"/health/background was not ok within {args.wait_healthy:.0f} s before the load: {_background(args)}")
        time.sleep(5)

    recorder = Recorder()
    agents = [Agent(args.server, i, recorder, args.events_per_minute, args.request_timeout) for i in range(args.devices)]
    print(f"Enrolling {args.devices} simulated agents...", flush=True)
    with ThreadPoolExecutor(max_workers=min(args.concurrency, 32)) as pool:
        enrolled = [a for a, ok in zip(agents, pool.map(lambda a: a.enrol(token), agents)) if ok]
    print(f"{len(enrolled)} enrolled; running for {args.minutes} min at {args.events_per_minute} events a minute each", flush=True)

    actions = [("commands", COMMANDS_EVERY), ("telemetry", TELEMETRY_EVERY), ("heartbeat", HEARTBEAT_EVERY), ("policy", POLICY_EVERY)]
    start = time.monotonic()
    end = start + args.minutes * 60
    queue: list[tuple[float, int, int, str, float]] = []
    for n, agent in enumerate(enrolled):
        for kind, every in actions:
            heapq.heappush(queue, (start + random.uniform(0, every), n, id(agent), kind, every))
    background: list[dict] = []
    next_sample = start
    lock = threading.Lock()
    lag: list[float] = []

    def execute(agent: Agent, kind: str, due: float) -> None:
        with lock:
            lag.append(max(0.0, time.monotonic() - due))
        getattr(agent, kind)()

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        while queue and queue[0][0] < end:
            due, n, _, kind, every = heapq.heappop(queue)
            wait = due - time.monotonic()
            if wait > 0:
                time.sleep(min(wait, 1.0))
                if due - time.monotonic() > 0:
                    heapq.heappush(queue, (due, n, id(enrolled[n]), kind, every))
                    continue
            pool.submit(execute, enrolled[n], kind, due)
            heapq.heappush(queue, (due + every, n, id(enrolled[n]), kind, every))
            if time.monotonic() >= next_sample:
                next_sample = time.monotonic() + 30
                pool.submit(lambda: background.append(_background(args)))
    elapsed = time.monotonic() - start

    stored = api.get("platform/telemetry-volume", tenant_id=tenant["id"], minutes=int(elapsed // 60) + 2)
    return {
        "devices": len(enrolled), "minutes": round(elapsed / 60, 1), "eventsPerMinutePerDevice": args.events_per_minute,
        "eventsSent": recorder.events_sent, "eventsPerSecond": round(recorder.events_sent / elapsed, 1),
        "eventsStoredOrChecked": stored["events"] + stored.get("notStored", 0),
        "schedulerLagSeconds": {"p95": round(sorted(lag)[int(len(lag) * 0.95)] if lag else 0, 2),
                                "max": round(max(lag) if lag else 0, 2)},
        "calls": recorder.summary(),
        "background": {"samples": len(background), "allOk": all(b.get("ok") for b in background),
                       "problems": sorted({p for b in background for p in b.get("problems", [])}),
                       "maxOutboxPending": max((b.get("checks", {}).get("outbox", {}).get("pending", 0) for b in background), default=0)},
    }


def _background(args: argparse.Namespace) -> dict:
    try:
        with urllib.request.urlopen(args.server.rstrip("/") + "/health/background", timeout=10) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read() or b"{}") or {"ok": False}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "problems": [type(exc).__name__]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--server", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--customer", default=f"Load Test {datetime.now():%Y-%m-%d %H:%M:%S}",
                        help="customer the simulated devices enrol into (default: a new one per run)")
    parser.add_argument("--devices", type=int, default=200)
    parser.add_argument("--minutes", type=float, default=3)
    parser.add_argument("--events-per-minute", type=int, default=60, help="telemetry each simulated agent sends (default 60)")
    parser.add_argument("--concurrency", type=int, default=64, help="requests in flight at once (default 64)")
    parser.add_argument("--request-timeout", type=float, default=30.0)
    parser.add_argument("--max-p95-ms", type=float, default=2000.0)
    parser.add_argument("--wait-healthy", type=float, default=180.0, help="seconds to wait for background health first")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    report = run(args)
    calls = report["calls"]
    lines = [f"Fenrir load test: {report['devices']} agents for {report['minutes']} min, "
             f"{report['eventsPerSecond']} events/s ({report['eventsSent']} sent, {report['eventsStoredOrChecked']} stored or checked)",
             "", "| Call | Calls | Errors | p50 ms | p95 ms | p99 ms | max ms |", "|---|---|---|---|---|---|---|"]
    lines += [f"| {name} | {c['calls']} | {c['errors']} | {c['p50']} | {c['p95']} | {c['p99']} | {c['max']} |" for name, c in calls.items()]
    background = report["background"]
    lines += ["", f"Background work: {'kept up' if background['allOk'] else 'FELL BEHIND: ' + ', '.join(background['problems'])} "
                  f"({background['samples']} samples, outbox peak {background['maxOutboxPending']})",
              f"Load generator lag: p95 {report['schedulerLagSeconds']['p95']} s (high means the generator, not the server, was the limit)"]
    text = "\n".join(lines)
    print(text)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.json").write_text(json.dumps(report, indent=2))
        (args.out / "report.md").write_text(text + "\n")

    total = sum(c["calls"] for c in calls.values()) or 1
    failed = sum(c["errors"] for c in calls.values())
    slow = [name for name, c in calls.items() if name != "enrol" and c["p95"] > args.max_p95_ms]
    ok = failed / total <= 0.01 and not slow and background["allOk"]
    if os.environ.get("GITHUB_ACTIONS") == "true":  # readable from the run's API, like the acceptance results
        headline = (f"{report['devices']} agents, {report['eventsPerSecond']} events/s, {failed}/{total} calls failed; p95 ms: "
                    + ", ".join(f"{name} {c['p95']}" for name, c in calls.items())
                    + f"; background {'kept up' if background['allOk'] else 'fell behind'}")
        print(f"::{'notice' if ok else 'error'} title=Load test::{headline}", flush=True)
    if not ok:
        print(f"FAIL: {failed}/{total} calls failed; slow: {slow or 'none'}; background ok: {background['allOk']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
