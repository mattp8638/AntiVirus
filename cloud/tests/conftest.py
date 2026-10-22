import dataclasses

import pytest
from fastapi.testclient import TestClient

from fenrir_cloud.config import Settings
from fenrir_cloud.main import create_app

ADMIN_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture()
def client():
    settings = dataclasses.replace(Settings(), database_url="sqlite://", bootstrap_admin_password=ADMIN_PASSWORD,
                                   secret_key="test-secret", public_base_url="https://fenrir.test")
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def login(client, email="admin@fenrir.local", password=ADMIN_PASSWORD) -> dict:
    response = client.post("/api/console/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


@pytest.fixture()
def admin(client):
    return login(client)


@pytest.fixture()
def tenant(client, admin):
    response = client.post("/api/console/tenants", json={"name": "Acme Dental", "template": "balanced"}, headers=admin)
    assert response.status_code == 200, response.text
    return response.json()


def enroll(client, admin, tenant, hostname="ACME-WS-01", os_version="Windows 11 Pro 23H2", serial="SN-1") -> dict:
    token = client.post("/api/console/enrollment-tokens", json={"tenantId": tenant["id"], "label": "test"}, headers=admin).json()["token"]
    response = client.post("/api/v1/enroll", json={"hostname": hostname, "osVersion": os_version, "serialNumber": serial},
                           headers={"X-Fenrir-Token": token})
    assert response.status_code == 200, response.text
    data = response.json()
    data["headers"] = {"X-Device-Api-Key": data["deviceApiKey"]}
    return data


@pytest.fixture()
def device(client, admin, tenant):
    return enroll(client, admin, tenant)
