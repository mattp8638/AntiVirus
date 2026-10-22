from modules.investigator.router import (
    analyse_commands,
    analyse_network,
    analyse_process_tree,
    highest_severity,
    make_timeline,
)


def test_suspicious_command_line_analyser_flags_encoded_powershell():
    processes = [
        {
            "pid": 100,
            "ppid": 50,
            "name": "powershell.exe",
            "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "cmdline_text": "powershell.exe -EncodedCommand SQBFAFgA",
        }
    ]

    findings = analyse_commands(processes)

    assert findings
    assert findings[0]["module"] == "Suspicious Command Line Analyser"
    assert findings[0]["severity"] == "critical"
    assert "Encoded PowerShell" in findings[0]["title"]
    assert findings[0]["recommended_action"]


def test_process_tree_viewer_flags_office_to_powershell_chain():
    processes = [
        {"pid": 10, "ppid": 1, "name": "winword.exe", "cmdline_text": "winword.exe invoice.docm"},
        {"pid": 11, "ppid": 10, "name": "powershell.exe", "cmdline_text": "powershell.exe -nop"},
    ]

    findings = analyse_process_tree(processes)

    assert findings
    assert findings[0]["module"] == "Process Tree Viewer"
    assert findings[0]["severity"] == "critical"
    assert findings[0]["evidence"]["parent_name"] == "winword.exe"
    assert findings[0]["evidence"]["child_name"] == "powershell.exe"


def test_network_monitor_flags_script_tool_external_connection():
    connections = [
        {
            "remote_ip": "203.0.113.10",
            "remote_address": "203.0.113.10:443",
            "process_name": "powershell.exe",
            "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "pid": 222,
        }
    ]

    findings = analyse_network(connections)

    assert findings
    assert findings[0]["module"] == "Network Connection Monitor"
    assert findings[0]["severity"] == "high"
    assert "external connection" in findings[0]["title"].lower()


def test_highest_severity_and_timeline_are_normalised():
    findings = [
        {"finding_id": "FND-1", "module": "A", "title": "Low item", "severity": "low", "created_at": "2026-01-01T00:00:00Z"},
        {"finding_id": "FND-2", "module": "B", "title": "Critical item", "severity": "critical", "created_at": "2026-01-01T00:01:00Z"},
    ]

    assert highest_severity(findings) == "critical"
    timeline = make_timeline(findings)
    assert len(timeline) == 2
    assert timeline[0]["evidence_ref"] == "FND-1"
    assert timeline[1]["evidence_ref"] == "FND-2"
