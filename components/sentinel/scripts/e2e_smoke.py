import time
import requests
import platform
import json
from pathlib import Path

BASE = "http://127.0.0.1:8000"

def register_agent(hostname=None, os_name=None):
    hostname = hostname or platform.node()
    os_name = os_name or platform.platform()
    res = requests.post(f"{BASE}/api/endpoint/agent/register", json={"hostname": hostname, "operating_system": os_name})
    res.raise_for_status()
    return res.json()

def send_posture(posture):
    res = requests.post(f"{BASE}/api/endpoint/agent/posture", json=posture)
    res.raise_for_status()
    return res.json()

def trigger_investigation(agent_id, scope=None):
    scope = scope or {"processes": True, "network": True}
    res = requests.post(f"{BASE}/api/endpoint/agent/{agent_id}/investigate", json={"scope": scope})
    res.raise_for_status()
    return res.json()

def run_local_agent_upload(agent_id, task=None):
    # import agent runner from the repo's agent package
    import sys
    from pathlib import Path as _P
    # Ensure agent folder is on sys.path so agent's internal top-level imports work
    agent_dir = str((_P(__file__).resolve().parent.parent / "agent").resolve())
    if agent_dir not in sys.path:
        sys.path.insert(0, agent_dir)
    import main as agent_main
    agent_main.run_investigation(agent_id, task)

def check_agent(agent_id):
    res = requests.get(f"{BASE}/api/endpoint/agent/{agent_id}")
    res.raise_for_status()
    return res.json()

def main():
    print("E2E smoke: registering agent")
    ag = register_agent()
    agent_id = ag.get("agent_id") or ag.get("agent_id")
    print("Agent id:", agent_id)

    print("Sending posture")
    # lightweight posture; backend scoring will accept the fields used in Endpoint model
    posture = {
        "agent_id": agent_id,
        "hostname": ag.get("hostname"),
        "operating_system": ag.get("operating_system"),
        "defender_enabled": True,
        "defender_realtime_enabled": True,
        "firewall_enabled": True,
        "bitlocker_enabled": False,
        "rdp_enabled": False,
        "smb_v1_enabled": False,
        "local_admin_count": 1,
        "powershell_logging_enabled": False,
        "audit_policy_enabled": True,
        "risky_services": 0,
    }
    send_posture(posture)

    print("Triggering investigation")
    instr = trigger_investigation(agent_id)
    print("Instruction created:", instr.get("request_id"))

    print("Running local agent collection and upload (this may take a few seconds)")
    try:
        run_local_agent_upload(agent_id, instr.get("instruction"))
    except Exception as exc:
        print("Agent run failed:", exc)
        return

    time.sleep(1)
    print("Checking agent state")
    info = check_agent(agent_id)
    print(json.dumps(info, indent=2))

if __name__ == '__main__':
    main()
