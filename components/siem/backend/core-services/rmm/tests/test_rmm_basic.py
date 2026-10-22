from fastapi.testclient import TestClient
from core_services.rmm.app.main import app

client = TestClient(app)


def test_create_profile():
    r = client.post("/rmm/configuration_profiles", json={"name": "Default", "profile_type": "hardening"})
    assert r.status_code == 200
    j = r.json()
    assert "id" in j
