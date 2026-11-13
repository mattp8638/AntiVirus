from fenrir_cloud import db as database
from fenrir_cloud.models import Device


def test_windows_reinstall_reuses_authenticated_record(client, admin, tenant, device):
    token = client.post("/api/console/enrollment-tokens", headers=admin,
                        json={"tenantId": tenant["id"], "label": "reinstall"}).json()["token"]
    proof = "12" * 32
    old_id = device["deviceId"]
    endpoint = f"/api/v1/devices/{old_id}/heartbeat"
    assert client.post(endpoint, headers=device["headers"], json={"reinstallProof": proof}).status_code == 200
    with database.session_factory()() as db:
        db.get(Device, old_id).notes = "Domain controller"
        db.commit()

    def install(serial, identity):
        return client.post("/api/v1/enroll", headers={"X-Fenrir-Token": token},
                           json={"hostname": "ACME-DC", "platform": "windows", "serialNumber": serial,
                                 "reinstallProof": identity})

    assert install("SN-1", "34" * 32).status_code == 409
    separate = install("unrelated-install", "34" * 32)
    assert separate.status_code == 200 and separate.json()["deviceId"] != old_id
    restored = install("fresh-install-guid", proof.upper())
    assert restored.status_code == 200 and restored.json()["deviceId"] == old_id
    assert client.post(endpoint, headers=device["headers"], json={}).status_code in (401, 403)
    assert client.post(endpoint, headers={"X-Device-Api-Key": restored.json()["deviceApiKey"]}, json={}).status_code == 200
    with database.session_factory()() as db:
        assert db.get(Device, old_id).notes == "Domain controller"
