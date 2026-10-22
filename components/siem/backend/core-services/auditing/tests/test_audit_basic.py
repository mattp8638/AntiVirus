from fastapi.testclient import TestClient
from core_services.auditing.app.main import app


client = TestClient(app)


def test_health_and_create_framework():
    # startup will create sqlite DB
    r = client.post("/auditing/frameworks", json={"name": "ISO27001", "version": "2013", "authority": "ISO"})
    assert r.status_code == 200
    j = r.json()
    assert "id" in j
