from fastapi.testclient import TestClient
from core_services.psa.app.main import app


def test_health():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_create_case():
    client = TestClient(app)
    payload = {"organisation_id": "org-1", "case_type": "incident", "source_system": "manual", "severity": 2}
    r = client.post("/psa/cases", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["organisation_id"] == "org-1"
