import dataclasses
import json
from datetime import datetime, timezone

from fenrir_cloud import config, detection


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _image_load(i: int) -> dict:
    return {"eventId": f"img-{i}", "eventType": "image.loaded", "source": "etw", "occurredAt": _now(),
            "summary": f"Image module{i}.dll loaded", "payloadJson": json.dumps({"imagePath": f"C:\\Windows\\System32\\m{i}.dll",
                                                                                "processImagePath": "C:\\Windows\\explorer.exe"})}


def _post(client, device, events):
    response = client.post(f"/api/v1/devices/{device['deviceId']}/telemetry", json={"events": events}, headers=device["headers"])
    assert response.status_code == 200, response.text
    return response.json()


def _cap(monkeypatch, per_minute: int):
    monkeypatch.setattr(config, "_active", dataclasses.replace(config.get_settings(), routine_events_per_device_minute=per_minute))
    monkeypatch.setattr(detection, "ROUTINE_BUDGET", detection._RoutineBudget())


def test_routine_events_over_the_cap_are_checked_but_not_stored(client, admin, device, monkeypatch):
    _cap(monkeypatch, 5)
    finding = {"eventId": "finding-1", "eventType": "scan.finding", "source": "agent-service", "occurredAt": _now(),
               "summary": "EICAR", "payloadJson": json.dumps({"path": "C:\\x\\eicar.com", "disposition": "quarantine",
                                                              "remediationStatus": "quarantined", "heuristicScore": 99,
                                                              "quarantineRecordId": "q-1"})}
    result = _post(client, device, [_image_load(i) for i in range(20)] + [finding])
    assert result["accepted"] == 21 and result["notStored"] == 15 and "totalStored" not in result
    stored = client.get("/api/console/events", params={"device_id": device["deviceId"], "hours": 1}, headers=admin).json()["events"]
    assert sum(e["eventType"] == "image.loaded" for e in stored) == 5
    assert any(e["eventType"] == "scan.finding" for e in stored)  # security events are never capped
    volume = client.get("/api/console/platform/telemetry-volume", params={"device_id": device["deviceId"], "minutes": 10},
                        headers=admin).json()
    assert volume["events"] == 6 and volume["notStored"] == 15
    assert volume["byType"][0] == {"eventType": "image.loaded", "events": 5}
    assert volume["byDevice"][0]["hostname"] == device.get("hostname", "ACME-WS-01")


def test_a_capped_routine_event_that_matches_a_rule_is_still_stored_and_alerts(client, admin, device, monkeypatch):
    _cap(monkeypatch, 1)

    def process(event_id: str, image: str, command_line: str, parent: str = "C:\\Windows\\explorer.exe") -> dict:
        return {"eventId": event_id, "eventType": "process.start", "source": "etw", "occurredAt": _now(),
                "payloadJson": json.dumps({"processImagePath": image, "commandLine": command_line,
                                           "parentProcessImagePath": parent, "pid": 4242})}

    quiet = [process(f"p-{i}", "C:\\Windows\\System32\\notepad.exe", "notepad.exe") for i in range(5)]
    ransomware = process("p-vss", "C:\\Windows\\System32\\vssadmin.exe", "vssadmin delete shadows /all /quiet",
                         "C:\\Users\\bob\\AppData\\Local\\Temp\\locker.exe")
    result = _post(client, device, quiet + [ransomware])
    assert result["notStored"] == 4 and result["alerts"] >= 1  # over the cap, yet the detection still fires
    stored = client.get("/api/console/events", params={"device_id": device["deviceId"], "hours": 1}, headers=admin).json()["events"]
    assert "p-vss" in {e["eventId"] for e in stored}


def test_no_cap_when_it_is_set_to_zero(client, device, monkeypatch):
    _cap(monkeypatch, 0)
    assert _post(client, device, [_image_load(i) for i in range(30)])["notStored"] == 0


def test_telemetry_volume_needs_configure_and_is_scoped(client, admin, tenant, device):
    other = client.post("/api/console/tenants", json={"name": "Other Customer"}, headers=admin).json()
    assert client.get("/api/console/platform/telemetry-volume", params={"tenant_id": other["id"]}, headers=admin).json()["events"] == 0
    assert client.get("/api/console/platform/telemetry-volume").status_code == 401
