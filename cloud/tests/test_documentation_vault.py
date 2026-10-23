import base64
import json
import pytest
from conftest import ADMIN_PASSWORD, login
from fenrir_cloud import db as database, crypto
from fenrir_cloud.models import VaultCredential, AuditLog

def stepup(client, admin):
    proof = client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    return {**admin, "X-Fenrir-Reauth": proof}

def test_document_revisions_and_restore(client, admin):
    created = client.post("/api/console/psa/kb", headers=admin, json={"title": "Runbook", "body": "Original"}).json()
    route = "/api/console/documentation/" + created["id"]
    first = client.get(route + "/revisions", headers=admin).json()
    assert len(first) == 1 and first[0]["snapshot"]["body"] == "Original"
    changed = client.patch("/api/console/psa/kb/" + created["id"], headers=admin, json={"body": "Updated"})
    assert changed.status_code == 200
    assert len(client.get(route + "/revisions", headers=admin).json()) == 2
    restored = client.post(route + "/restore/" + first[0]["id"], headers=admin)
    assert restored.status_code == 200 and restored.json()["body"] == "Original"
    assert len(client.get(route + "/revisions", headers=admin).json()) == 3
    assert len(client.get("/api/console/documentation/templates", headers=admin).json()) >= 3

def test_vault_encryption_reveal_archive_and_rotation(client, admin, tenant, monkeypatch):
    secret = "must-not-appear-in-metadata-or-audit"
    response = client.post("/api/console/vault/credentials", headers=admin, json={"tenantId": tenant["id"], "name": "Router", "secret": secret})
    assert response.status_code == 200
    row = response.json()
    assert secret not in response.text and "ciphertext" not in row
    route = "/api/console/vault/credentials/" + row["id"]
    assert client.post(route + "/reveal", headers=admin).status_code == 403
    proof = stepup(client, admin)
    reveal = client.post(route + "/reveal", headers=proof)
    assert reveal.json()["secret"] == secret and reveal.headers["Cache-Control"] == "no-store"
    with database.session_factory()() as db:
        stored = db.get(VaultCredential, row["id"])
        assert secret not in json.dumps(stored.ciphertext)
        with pytest.raises(crypto.VaultError):
            crypto.decrypt(stored.ciphertext, "vault:wrong:" + row["id"])
        assert all(secret not in json.dumps(log.details) for log in db.query(AuditLog))
        monkeypatch.setenv("FENRIR_VAULT_KEY", base64.b64encode(b"k" * 32).decode())
        assert crypto.rotate(db)["rewrapped"] == 1
        db.commit()
    assert client.post(route + "/reveal", headers=proof).json()["secret"] == secret
    assert client.patch(route, headers=proof, json={"archived": True}).status_code == 200
    assert client.post(route + "/reveal", headers=proof).status_code == 409

def test_vault_tenant_and_role_boundaries(client, admin, tenant):
    cred = client.post("/api/console/vault/credentials", headers=admin, json={"tenantId": tenant["id"], "name": "Only Acme", "secret": "secret"}).json()
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other"}).json()
    assert client.post("/api/console/users", headers=admin, json={"tenantId": other["id"], "email": "other@test.com", "password": ADMIN_PASSWORD, "role": "technician"}).status_code == 200
    outsider = login(client, "other@test.com")
    assert client.get("/api/console/vault/credentials", headers=outsider).json() == []
    assert client.post("/api/console/vault/credentials/" + cred["id"] + "/reveal", headers=stepup(client, outsider)).status_code == 404
    assert client.post("/api/console/vault/credentials", headers=outsider, json={"tenantId": tenant["id"], "name": "Cross tenant", "secret": "x"}).status_code == 404
