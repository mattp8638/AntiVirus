

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
    assert fields["experience.trayIcon"]["enforcedOn"] == ["windows"]
    assert fields["experience.allowUserPause"]["enforcedOn"] == []


def test_firewall_rules_are_validated_and_parsed_for_agents():
    import pytest
    from fenrir_cloud import policy_schema as ps

    assert ps.parse_firewall_rule("allow in tcp 3389 from 10.0.0.0/8") == {
        "action": "allow", "direction": "in", "protocol": "tcp", "ports": [[3389, 3389]], "remote": ["10.0.0.0/8"]}
    assert ps.parse_firewall_rule("BLOCK out udp any to 203.0.113.9,2001:db8::/32") == {
        "action": "block", "direction": "out", "protocol": "udp", "ports": [], "remote": ["203.0.113.9", "2001:db8::/32"]}
    assert ps.parse_firewall_rule("allow in tcp 80,443,8000-8100")["ports"] == [[80, 80], [443, 443], [8000, 8100]]
    assert ps.parse_firewall_rule("block in any from 198.51.100.0/24")["protocol"] == "any"
    for bad in ("allow in tcp 0", "allow in tcp 70000", "allow in tcp 90-80", "allow sideways tcp 1", "allow in any 80",
                "allow in tcp 80 from evil.example", "allow in tcp 80 from 10.0.0.1; rm -rf /", "allow in tcp 80 via 1.2.3.4", "deny in tcp"):
        assert ps.parse_firewall_rule(bad) is None, bad
    with pytest.raises(ps.PolicyError):
        ps.validate_partial({"firewall": {"rules": ["allow in tcp 3389 from somewhere"]}})
    cleaned = ps.validate_partial({"firewall": {"rules": ["# office VPN", "allow in tcp 3389 from 10.0.0.0/8"]}})
    settings = ps.defaults()
    settings["firewall"].update(cleaned["firewall"])
    doc = ps.to_agent_policy("p1", "Test", settings)
    assert doc["modules"]["firewall"]["parsedRules"] == [ps.parse_firewall_rule("allow in tcp 3389 from 10.0.0.0/8")]
    assert doc["modules"]["firewall"]["rules"] == ["# office VPN", "allow in tcp 3389 from 10.0.0.0/8"]
    fields = {f["path"]: f for s in ps.schema_document()["sections"] for f in s["fields"]}
    assert fields["firewall.defaultOutbound"]["enforcedOn"] == ["windows", "linux", "macos"]
    assert fields["firewall.blockSmbV1"]["enforcedOn"] == ["windows"]
