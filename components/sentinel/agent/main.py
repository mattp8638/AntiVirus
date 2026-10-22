import json
import logging
import platform
import time
from pathlib import Path

from api import fetch_task, register, send_posture, submit_result, upload_evidence
from collector import collect
from exporter import export_bundle, export_html, export_json
from investigation import analyze_collection, collect_scoped_data, write_release1_artifacts

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"
STATE_FILE = BASE_DIR / "agent_state.json"
LOG_FILE = BASE_DIR / "sentinel-agent.log"
OUTPUT_DIR = BASE_DIR / "evidence"
OUTPUT_DIR.mkdir(exist_ok=True)

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

with open(CONFIG_FILE) as f:
    CONFIG = json.load(f)

interval = CONFIG.get("interval_seconds", 300)
hostname = platform.node()
os_name = platform.platform()
TOOL_VERSION = CONFIG.get("tool_version", "sentinel-agent-mvp")


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def get_or_register_agent():
    state = load_state()
    existing_agent_id = state.get("agent_id")
    agent = register(hostname, os_name, existing_agent_id=existing_agent_id)
    state.update(agent)
    save_state(state)
    return agent.get("agent_id")


def run_investigation(agent_id, task=None):
    logging.info("Investigation triggered")
    print("Investigation triggered")
    scope = {}
    request_id = None
    if task:
        request_id = task.get("request_id")
        scope = task.get("scope") or {}

    data = collect_scoped_data(scope)
    findings, timeline = analyze_collection(data)
    software_inventory = data.get("software_inventory", []) or []
    release1_artifacts = write_release1_artifacts(data, OUTPUT_DIR)
    summary = {
        "investigation_id": request_id or f"LOCAL-{agent_id}",
        "request_id": request_id or f"LOCAL-{agent_id}",
        "agent_id": agent_id,
        "hostname": data.get("hostname") or hostname,
        "status": "complete",
        "scope": scope,
        "scope_collected": data.get("collected_sections", []),
        "artifact_count": len(release1_artifacts) + 2,
        "release1_artifacts": [Path(path).name for path in release1_artifacts],
        "tool_version": TOOL_VERSION,
        "highest_severity": max(
            (finding.get("severity", "informational") for finding in findings),
            key=lambda value: {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0),
            default="informational",
        ),
    }
    report_payload = {
        "summary": summary,
        "findings": findings,
        "timeline": timeline,
        "sections": {key: value for key, value in data.items() if key not in {"timestamp", "hostname", "requested_scope", "collected_sections"}},
        "metadata": {
            "timestamp": data.get("timestamp"),
            "software_inventory": software_inventory,
            "hostname": data.get("hostname"),
            "requested_scope": data.get("requested_scope"),
            "agent_id": agent_id,
            "request_id": request_id,
            "tool_version": TOOL_VERSION,
            "release1_artifacts": [Path(path).name for path in release1_artifacts],
        },
    }
    json_file = export_json(report_payload, str(OUTPUT_DIR / "evidence.json"))
    html_file = export_html(report_payload, str(OUTPUT_DIR / "report.html"))
    bundle = export_bundle(
        [json_file, html_file, *release1_artifacts],
        str(OUTPUT_DIR / "evidence_bundle.enc"),
        metadata={
            "agent_id": agent_id,
            "hostname": data.get("hostname") or hostname,
            "request_id": request_id,
            "selected_scope": scope,
            "tool_version": TOOL_VERSION,
        },
    )
    upload_evidence(agent_id, bundle)
    result_payload = {
        "request_id": request_id or f"LOCAL-{agent_id}",
        "status": "complete",
        "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summary,
        "findings": findings,
        "timeline": timeline,
        "software_inventory": software_inventory,
        "report_path": str(html_file),
        "bundle_path": bundle,
    }
    submit_result(agent_id, result_payload)
    logging.info("Investigation evidence uploaded: %s", bundle)


def main():
    print("Starting Sentinel endpoint agent...")
    logging.info("Starting Sentinel endpoint agent")
    agent_id = get_or_register_agent()
    print(f"Agent identity: {agent_id}")
    logging.info("Agent identity: %s", agent_id)

    while True:
        try:
            posture = collect(agent_id)
            send_posture(posture)
            logging.info("Posture sent successfully")
            task = fetch_task(agent_id)
            if task.get("status") in ("in-progress", "assigned") and task.get("instruction"):
                logging.info("Received instruction: %s", task.get("instruction"))
                run_investigation(agent_id, task.get("instruction"))
        except Exception as exc:
            logging.exception("Agent cycle failed: %s", exc)
            print(f"Agent cycle failed: {exc}")
        time.sleep(interval)


if __name__ == "__main__":
    main()
