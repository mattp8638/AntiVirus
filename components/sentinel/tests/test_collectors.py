import platform
import pytest

from modules.investigator import collectors


def test_host_collector_returns_dict():
    from modules.investigator.collectors.host import collect_host_summary
    s = collect_host_summary()
    assert isinstance(s, dict)
    assert "hostname" in s


def test_processes_collector_smoke():
    try:
        from modules.investigator.collectors.processes import collect_processes
    except Exception:
        pytest.skip("processes collector import failed")
    procs = collect_processes()
    assert isinstance(procs, list)


def test_network_collector_smoke():
    try:
        from modules.investigator.collectors.network import collect_network_connections
    except Exception:
        pytest.skip("network collector import failed")
    conns = collect_network_connections()
    assert isinstance(conns, list)


def test_services_collector_on_windows():
    from modules.investigator.collectors.services import collect_services
    if platform.system().lower() != "windows":
        pytest.skip("services collector only applicable on Windows")
    services = collect_services()
    assert isinstance(services, list)


def test_eventlogs_collector_on_windows():
    from modules.investigator.collectors.eventlogs import collect_eventlog_summary
    if platform.system().lower() != "windows":
        pytest.skip("eventlog collector only applicable on Windows")
    summary = collect_eventlog_summary(1)
    assert isinstance(summary, dict)


def test_analysis_and_timeline_smoke():
    from modules.investigator.analysis.commands import analyse_commands
    from modules.investigator.timeline import make_timeline, highest_severity
    findings = analyse_commands([])
    assert isinstance(findings, list)
    timeline = make_timeline(findings)
    assert isinstance(timeline, list)
    assert highest_severity(findings) in {"informational", "low", "medium", "high", "critical"}
