import base64
import os

import pytest

from conftest import ADMIN_PASSWORD, login
from fenrir_cloud import crypto, db as database, events
from fenrir_cloud.security import totp_code


def test_envelope_encryption_round_trip_and_binding(client):
    env = crypto.encrypt("hunter2-secret", "vault:ten_a:sec_1")
    assert "hunter2" not in str(env)
    assert crypto.decrypt(env, "vault:ten_a:sec_1") == "hunter2-secret"
    # A ciphertext moved to another tenant/record does not decrypt.
    with pytest.raises(crypto.VaultError):
        crypto.decrypt(env, "vault:ten_b:sec_1")
    tampered = dict(env, ct=base64.b64encode(b"x" * 30).decode())
    with pytest.raises(crypto.VaultError):
        crypto.decrypt(tampered, "vault:ten_a:sec_1")
    # Two encryptions of the same value differ (fresh data key and nonce).
    assert crypto.encrypt("same", "a")["ct"] != crypto.encrypt("same", "a")["ct"]
    assert crypto.key_status()["source"] == "derived" and not crypto.key_status()["productionReady"]


def test_key_rotation_with_old_keys(client, monkeypatch):
    old = base64.b64encode(os.urandom(32)).decode()
    new = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("FENRIR_VAULT_KEY", old)
    env = crypto.encrypt("value", "aad")
    monkeypatch.setenv("FENRIR_VAULT_KEY", new)
    with pytest.raises(crypto.VaultError):
        crypto.decrypt(env, "aad")
    monkeypatch.setenv("FENRIR_VAULT_OLD_KEYS", old)
    assert crypto.decrypt(env, "aad") == "value" and crypto.needs_rewrap(env)
    rotated = crypto.rewrap(env, "aad")
    assert not crypto.needs_rewrap(rotated) and crypto.decrypt(rotated, "aad") == "value"
    assert crypto.key_status()["productionReady"] and crypto.key_status()["decryptOnlyKeys"] == 1
    monkeypatch.setenv("FENRIR_VAULT_KEY", "too-short")
    with pytest.raises(ValueError):
        crypto.encrypt("x", "y")


def test_events_are_idempotent_retried_and_dead_lettered(client):
    calls = {"ok": 0, "flaky": 0}

    @events.handler("test.thing", name="test.ok")
    def ok_handler(db, event):
        calls["ok"] += 1

    @events.handler("test.thing", name="test.flaky")
    def flaky(db, event):
        calls["flaky"] += 1
        if event.payload.get("fail"):
            raise RuntimeError("downstream unavailable")

    db = database.session_factory()()
    try:
        first = events.publish(db, "test.thing", {"fail": True}, key="thing-1")
        again = events.publish(db, "test.thing", {"fail": True}, key="thing-1")
        assert first.id == again.id
        db.commit()
        assert events.process(db) == 1
        db.commit()
        db.refresh(first)
        assert first.status == "pending" and first.attempts == 1 and "downstream unavailable" in first.last_error
        assert first.results["test.ok"] == "ok"
        # Not due yet (back-off), so nothing runs.
        assert events.process(db) == 0
        for _ in range(events.MAX_ATTEMPTS):
            first.next_attempt_at = first.created_at
            events.process(db)
            db.commit()
            db.refresh(first)
        assert first.status == "dead"
        # The handler that succeeded never ran again.
        assert calls["ok"] == 1 and calls["flaky"] == events.MAX_ATTEMPTS
        # Fixed downstream: an administrator retries it.
        first.payload = {"fail": False}
        events.retry(db, first)
        db.commit()
        events.process(db)
        db.commit()
        db.refresh(first)
        assert first.status == "done" and first.processed_at is not None
    finally:
        db.close()
        events._handlers.pop("test.thing", None)


def test_mfa_enrolment_login_and_reset(client, admin):
    setup = client.post("/api/console/auth/mfa/setup", headers=admin).json()
    assert setup["otpauthUri"].startswith("otpauth://totp/")
    assert client.post("/api/console/auth/mfa/enable", headers=admin, json={"code": "000000"}).status_code == 400
    assert client.post("/api/console/auth/mfa/enable", headers=admin, json={"code": totp_code(setup["secret"])}).json()["mfaEnabled"]
    me = client.get("/api/console/auth/me", headers=admin).json()
    assert me["user"]["mfaEnabled"] is True and "mfaSecret" not in me["user"]
    no_code = client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD})
    assert no_code.status_code == 428
    bad = client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD, "code": "123456"})
    assert bad.status_code == 401
    good = client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD,
                                                        "code": totp_code(setup["secret"])})
    assert good.status_code == 200
    # The seed is stored encrypted, never as plain text.
    db = database.session_factory()()
    from fenrir_cloud.models import User

    user = db.query(User).filter_by(email="admin@fenrir.local").one()
    assert setup["secret"] not in str(user.mfa_secret)
    db.close()
    reset_url = f"/api/console/users/{user.id}/mfa/reset"
    assert client.post(reset_url, headers=admin).status_code == 403
    proof = client.post("/api/console/auth/reauth", headers=admin,
                        json={"password": ADMIN_PASSWORD, "code": totp_code(setup["secret"])}).json()["reauthToken"]
    assert client.post(reset_url, headers={**admin, "X-Fenrir-Reauth": proof}).json()["mfaEnabled"] is False
    # Resetting the authentication state signs that account out everywhere (FIX-03), so the old session and its
    # proof are both dead.
    assert client.post(reset_url, headers={**admin, "X-Fenrir-Reauth": proof}).status_code == 401
    assert client.get("/api/console/auth/me", headers=admin).status_code == 401
    admin = login(client)
    assert client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD}).status_code == 200


def test_reauth_tokens_are_short_lived_and_not_sessions(client, admin):
    assert client.post("/api/console/auth/reauth", headers=admin, json={"password": "wrong"}).status_code == 401
    token = client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    # A re-auth token cannot be used to sign in.
    assert client.get("/api/console/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_login_rate_limit(client):
    for _ in range(10):
        client.post("/api/console/auth/login", json={"email": "nobody@example.com", "password": "x"})
    blocked = client.post("/api/console/auth/login", json={"email": "nobody@example.com", "password": "x"})
    assert blocked.status_code == 429 and blocked.headers.get("Retry-After")


def test_platform_status_and_event_admin(client, admin):
    status = client.get("/api/console/platform/status", headers=admin).json()
    assert status["vault"]["algorithm"].startswith("AES-256-GCM") and "pending" in status["events"]
    db = database.session_factory()()
    events.publish(db, "test.nohandler", {}, key="nohandler-1")
    db.commit()
    db.close()
    rows = client.get("/api/console/platform/events", headers=admin).json()
    assert any(r["key"] == "nohandler-1" for r in rows)
    event_id = next(r["id"] for r in rows if r["key"] == "nohandler-1")
    assert client.post(f"/api/console/platform/events/{event_id}/retry", headers=admin).json()["status"] == "pending"


def test_vault_rotation_from_derived_key(client, admin, monkeypatch):
    setup = client.post("/api/console/auth/mfa/setup", headers=admin).json()
    client.post("/api/console/auth/mfa/enable", headers=admin, json={"code": totp_code(setup["secret"])})
    monkeypatch.setenv("FENRIR_VAULT_KEY", base64.b64encode(os.urandom(32)).decode())
    # Rotation is a sensitive action: it needs a fresh password + MFA confirmation.
    assert client.post("/api/console/platform/vault/rotate", headers=admin).status_code == 403
    reauth = client.post("/api/console/auth/reauth", headers=admin, json={"password": ADMIN_PASSWORD, "code": totp_code(setup["secret"])}).json()
    result = client.post("/api/console/platform/vault/rotate", headers={**admin, "X-Fenrir-Reauth": reauth["reauthToken"]}).json()
    assert result["rewrapped"] == 1 and result["failed"] == 0
    # MFA still works with the seed now under the new key.
    ok = client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD, "code": totp_code(setup["secret"])})
    assert ok.status_code == 200


def test_reauth_proof_is_bound_to_session_and_password(client, admin):
    proof = client.post("/api/console/auth/reauth", headers=admin,
                        json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    other_session = login(client)
    assert other_session != admin
    rotate_url = "/api/console/platform/vault/rotate"
    assert client.post(rotate_url, headers={**other_session, "X-Fenrir-Reauth": proof}).status_code == 403
    assert client.post(rotate_url, headers={**admin, "X-Fenrir-Reauth": proof}).status_code == 200
    changed = client.post("/api/console/auth/password", headers=admin,
                          json={"currentPassword": ADMIN_PASSWORD, "newPassword": "a-new-long-password"})
    assert changed.status_code == 200
    # The old session (and the other one) ended with the password; the client gets a fresh session.
    assert client.post(rotate_url, headers={**admin, "X-Fenrir-Reauth": proof}).status_code == 401
    assert client.get("/api/console/auth/me", headers=other_session).status_code == 401
    fresh = {"Authorization": "Bearer " + changed.json()["token"]}
    assert client.get("/api/console/auth/me", headers=fresh).status_code == 200
    assert client.post(rotate_url, headers={**fresh, "X-Fenrir-Reauth": proof}).status_code == 403  # proof bound to the old session


@pytest.mark.parametrize("claims", [{"exp": "invalid"}, {"exp": None}, {"exp": True}, {"exp": float("inf")}])
def test_malformed_signed_expiry_is_rejected(claims):
    from fenrir_cloud.security import issue_token, read_token
    token = issue_token("secret", "user", 5, **claims)
    assert read_token("secret", token) is None


@pytest.mark.parametrize("token", ["a.é", "x" * 20000, "", "no-dot"])
def test_malformed_bearer_tokens_are_rejected(token):
    from fenrir_cloud.security import read_token
    assert read_token("secret", token) is None
