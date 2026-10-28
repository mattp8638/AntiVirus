"""CORE-14: an unsafe production configuration never starts; softer risks are reported to platform administrators."""

import dataclasses

import pytest

from conftest import login
from fenrir_cloud import production
from fenrir_cloud.config import Settings
from fenrir_cloud.main import create_app

STRONG = "9f" * 32


def prod(**overrides):
    base = dict(environment="production", database_url="postgresql+psycopg://u:p@db/fenrir", secret_key=STRONG,
                bootstrap_admin_password="a-long-random-admin-password", public_base_url="https://fenrir.example.net",
                open_enrollment=False)
    return dataclasses.replace(Settings(), **{**base, **overrides})


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("FENRIR_SECRET_KEY", STRONG)
    monkeypatch.setenv("FENRIR_VAULT_ALLOW_DERIVED_LEGACY", "false")
    return monkeypatch


def test_safe_production_settings_pass(env):
    assert production.check(prod(), 0) == ([], [])


@pytest.mark.parametrize("overrides, users, message", [
    ({"secret_key": "change-me-64-hex-chars"}, 1, "FENRIR_SECRET_KEY"),
    ({"secret_key": "short"}, 1, "FENRIR_SECRET_KEY"),
    ({"database_url": "sqlite:///./fenrir.db"}, 1, "SQLite"),
    ({"bootstrap_admin_password": "change-me-at-least-12-chars"}, 0, "FENRIR_ADMIN_PASSWORD"),
    ({"bootstrap_admin_password": "short"}, 0, "FENRIR_ADMIN_PASSWORD"),
])
def test_unsafe_production_settings_are_errors(env, overrides, users, message):
    errors, _ = production.check(prod(**overrides), users)
    assert errors and message in errors[0]


def test_unset_secret_key_is_an_error_and_existing_admin_password_is_not_checked(env):
    env.delenv("FENRIR_SECRET_KEY")
    assert "not set" in production.check(prod(), 1)[0][0]
    env.setenv("FENRIR_SECRET_KEY", STRONG)
    assert production.check(prod(bootstrap_admin_password="x"), 5)[0] == []  # the first admin already exists


def test_soft_risks_are_warnings(env):
    env.setenv("FENRIR_VAULT_ALLOW_DERIVED_LEGACY", "true")
    errors, warnings = production.check(prod(public_base_url="http://fenrir.example.net", open_enrollment=True), 1)
    assert errors == [] and len(warnings) == 3
    assert production.check(prod(public_base_url="http://127.0.0.1:8080"), 1) == ([], ["FENRIR_VAULT_ALLOW_DERIVED_LEGACY is on: vault values encrypted with the old derived key are still readable. Rotate the vault key, then set it to false."])


def test_development_never_blocks(env):
    errors, warnings = production.check(prod(environment="development", secret_key="x", database_url="sqlite://"), 0)
    assert errors == [] and "not enforced" in warnings[0]


def test_create_app_refuses_unsafe_production(env):
    with pytest.raises(RuntimeError, match="will not start in production"):
        create_app(prod(database_url="sqlite://", secret_key="change-me"))


def test_ready_and_readiness(client, admin, tenant):
    assert client.get("/ready").json() == {"ready": True}
    report = client.get("/api/console/platform/readiness", headers=admin).json()
    assert report["environment"] == "development" and report["schemaVersion"] == report["expectedSchemaVersion"]
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "ta@acme.example",
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    assert client.get("/api/console/platform/readiness", headers=login(client, "ta@acme.example", "acme-password-123")).status_code == 403


def test_current_migration_ledger_does_not_hide_missing_device_columns(client):
    from sqlalchemy import text
    from fenrir_cloud import db

    with db.engine().begin() as connection:
        connection.execute(text("ALTER TABLE devices DROP COLUMN agent_build"))
    assert client.get("/health").status_code == 200  # process liveness is insufficient
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"ready": False, "reason": "device schema is incompatible"}
