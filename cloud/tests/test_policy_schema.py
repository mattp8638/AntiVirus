

def test_scan_schedules_reach_agents_as_plans():
    from fenrir_cloud import policy_schema as ps

    settings = ps.defaults()
    settings["antimalware"]["quickScanSchedule"] = "weekdays 09:00"
    settings["antimalware"]["fullScanSchedule"] = "off"
    doc = ps.to_agent_policy("p1", "Test", settings)
    assert doc["modules"]["antimalware"]["quickScanPlan"] == {"off": False, "days": [0, 1, 2, 3, 4], "minuteOfDay": 540}
    assert doc["modules"]["antimalware"]["fullScanPlan"]["off"] is True
    assert ps.parse_scan_schedule("weekly sun 02:00") == {"off": False, "days": [6], "minuteOfDay": 120}
    import pytest
    with pytest.raises(ps.PolicyError):
        ps.validate_partial({"antimalware": {"quickScanSchedule": "every so often"}})
    fields = {f["path"]: f for s in ps.schema_document()["sections"] for f in s["fields"]}
    assert fields["antimalware.quickScanSchedule"]["enforcedOn"] == ["windows", "linux", "macos"]
    assert fields["experience.trayIcon"]["enforcedOn"] == []
