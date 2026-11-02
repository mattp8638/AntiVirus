import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = ROOT / "agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.append(str(AGENT_DIR))

from investigation import RELEASE1_ARTIFACT_FILES, build_release1_artifacts, write_release1_artifacts


def _sample_collection():
    return {
        "timestamp": "2026-04-28T10:00:00Z",
        "hostname": "HOST-1",
        "requested_scope": {"collectors": ["processes", "network", "eventlogs"]},
        "endpoint_snapshot": {
            "collected_at": "2026-04-28T10:00:00Z",
            "hostname": "HOST-1",
            "os_version": "Windows 11",
            "logged_in_user": "analyst",
        },
        "processes": [
            {
                "pid": 101,
                "ppid": 1,
                "parent_pid": 1,
                "name": "powershell.exe",
                "cmdline": ["powershell.exe", "-NoProfile"],
                "cmdline_text": "powershell.exe -NoProfile",
            }
        ],
        "network": [{"pid": 101, "remote_address": "203.0.113.10:443", "process_name": "powershell.exe"}],
        "services": [{"Name": "WinDefend", "State": "Running"}],
        "scheduled_tasks": [{"TaskName": "OneDrive Standalone Update Task"}],
        "startup": {
            "folders": [{"path": "C:\\Users\\analyst\\Startup", "entries": []}],
            "registry_autoruns": [{"path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "OneDrive"}],
        },
        "local_users": {"users": ["analyst"], "administrators": ["Administrator"]},
        "recent_files": [{"path": "C:\\Users\\analyst\\Downloads\\invoice.docm"}],
        "defender_events": [{"Id": 1116, "Message": "Threat detected"}],
        "powershell_events": [{"Id": 4104, "Message": "Script block logged"}],
        "security_events": [{"Id": 4624, "Message": "Logon"}],
        "system_events": [{"Id": 7036, "Message": "Service state changed"}],
    }


def test_release1_artifacts_have_expected_names_and_sections():
    artifacts = build_release1_artifacts(_sample_collection())

    assert list(artifacts) == RELEASE1_ARTIFACT_FILES
    assert artifacts["endpoint_snapshot.json"]["local_users"] == ["analyst"]
    assert artifacts["endpoint_snapshot.json"]["local_administrators"] == ["Administrator"]
    assert artifacts["processes.json"]["processes"][0]["parent_pid"] == 1
    assert artifacts["network_connections.json"]["connections"][0]["remote_address"] == "203.0.113.10:443"
    assert artifacts["persistence.json"]["registry_autoruns"][0]["name"] == "OneDrive"
    assert artifacts["event_logs.json"]["event_counts"]["system_events"] == 1
    assert artifacts["powershell_activity.json"]["powershell_processes"][0]["name"] == "powershell.exe"


def test_write_release1_artifacts_creates_json_files(tmp_path):
    written = write_release1_artifacts(_sample_collection(), tmp_path)

    assert [Path(path).name for path in written] == RELEASE1_ARTIFACT_FILES
    for filename in RELEASE1_ARTIFACT_FILES:
        assert (tmp_path / filename).exists()
