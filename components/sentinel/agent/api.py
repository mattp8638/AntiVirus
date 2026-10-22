import requests
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"

with open(CONFIG_FILE) as f:
    CONFIG = json.load(f)

API = CONFIG["api_url"]


def register(hostname, os, existing_agent_id=None):
    res = requests.post(f"{API}/api/endpoint/agent/register", json={
        "hostname": hostname,
        "operating_system": os,
        "existing_agent_id": existing_agent_id
    })
    return res.json()


def send_posture(data):
    requests.post(f"{API}/api/endpoint/agent/posture", json=data)


def fetch_task(agent_id):
    res = requests.get(f"{API}/api/endpoint/agent/{agent_id}/task")
    try:
        return res.json()
    except Exception:
        return {"status": "idle"}


def upload_evidence(agent_id, filepath):
    with open(filepath, "rb") as f:
        requests.post(
            f"{API}/api/endpoint/agent/{agent_id}/evidence",
            files={"file": f}
        )


def submit_result(agent_id, payload):
    res = requests.post(f"{API}/api/endpoint/agent/{agent_id}/result", json=payload)
    res.raise_for_status()
    return res.json()
