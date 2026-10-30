import base64
import json
import time
import urllib.parse

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from fenrir_cloud import db as database, platform_security, sso

from conftest import ADMIN_PASSWORD

TENANT = "11111111-2222-3333-4444-555555555555"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeEntra:
    """Discovery, signing keys and a token endpoint, like login.microsoftonline.com."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.nonce = ""
        self.claims: dict = {}
        self.sign_with = self.key

    def id_token(self) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "exp": now + 600, "nbf": now - 5, "nonce": self.nonce,
                  "preferred_username": "admin@fenrir.local", "tid": TENANT, **self.claims}
        header = _b64(json.dumps({"alg": "RS256", "kid": "k1", "typ": "JWT"}).encode())
        body = _b64(json.dumps(claims).encode())
        signature = self.sign_with.sign(f"{header}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{body}.{_b64(signature)}"

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                                             "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/keys"})
        if url.endswith("/keys"):
            numbers = self.key.public_key().public_numbers()
            return httpx.Response(200, json={"keys": [{"kty": "RSA", "kid": "k1", "n": _b64(numbers.n.to_bytes(256, "big")),
                                                       "e": _b64(numbers.e.to_bytes(3, "big"))}]})
        if url.endswith("/token"):
            form = urllib.parse.parse_qs(request.content.decode())
            assert form["code_verifier"][0] and form["client_secret"] == ["s3cret"]
            return httpx.Response(200, json={"id_token": self.id_token(), "token_type": "Bearer"})
        return httpx.Response(404)


@pytest.fixture()
def entra(monkeypatch):
    fake = FakeEntra()
    monkeypatch.setattr(sso, "_client", lambda: httpx.Client(transport=httpx.MockTransport(fake.handler)))
    monkeypatch.setattr(sso, "_metadata_cache", {})
    monkeypatch.setattr(sso, "_jwks_cache", {})
    return fake


def _stepup(client, headers):
    proof = client.post("/api/console/auth/reauth", headers=headers, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    return {**headers, "X-Fenrir-Reauth": proof}


def _configure(client, admin, **extra):
    response = client.put("/api/console/platform/security/sso", headers=_stepup(client, admin),
                          json={"enabled": True, "tenant": TENANT, "clientId": CLIENT_ID, "clientSecret": "s3cret", **extra})
    assert response.status_code == 200, response.text
    return response.json()


def _sign_in(client, entra, cookie: str | None = None) -> httpx.Response:
    start = client.get("/api/console/auth/sso/start", params={"returnTo": "/alerts"}, follow_redirects=False)
    assert start.status_code == 302
    location = urllib.parse.urlparse(start.headers["location"])
    query = urllib.parse.parse_qs(location.query)
    assert location.netloc == "login.microsoftonline.com" and query["code_challenge_method"] == ["S256"]
    entra.nonce = query["nonce"][0]
    binding = start.cookies.get(sso.COOKIE) if cookie is None else cookie
    return client.get("/api/console/auth/sso/callback", params={"code": "auth-code", "state": query["state"][0]},
                      headers={"Cookie": f"{sso.COOKIE}={binding}"}, follow_redirects=False)


def _error(response: httpx.Response) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(response.headers["location"]).query).get("sso_error", [""])[0]


def test_microsoft_sign_in_hands_the_console_a_session_once(client, admin, entra):
    view = _configure(client, admin)
    assert view["secretSet"] and view["redirectUri"] == "https://fenrir.test/api/console/auth/sso/callback"
    assert "s3cret" not in json.dumps(client.get("/api/console/platform/security", headers=admin).json())
    assert client.get("/api/console/auth/sso/info").json() == {"enabled": True, "required": False}

    callback = _sign_in(client, entra)
    assert callback.status_code == 302, callback.text
    landed = urllib.parse.urlparse(callback.headers["location"])
    assert landed.path == "/alerts"
    handoff = urllib.parse.parse_qs(landed.query)["sso"][0]
    done = client.post("/api/console/auth/sso/complete", json={"handoff": handoff})
    assert done.status_code == 200
    me = client.get("/api/console/auth/me", headers={"Authorization": f"Bearer {done.json()['token']}"})
    assert me.status_code == 200 and me.json()["user"]["email"] == "admin@fenrir.local"
    assert client.post("/api/console/auth/sso/complete", json={"handoff": handoff}).status_code == 401  # once only
    # The hand-off code is not a session token.
    assert client.get("/api/console/auth/me", headers={"Authorization": f"Bearer {handoff}"}).status_code == 401


@pytest.mark.parametrize("tamper, message", [
    ("cookie", "same browser"),
    ("audience", "different application"),
    ("issuer", "different Entra tenant"),
    ("signature", "signature is not valid"),
    ("expired", "expired"),
    ("nobody", "no active Fenrir staff account"),
])
def test_microsoft_sign_in_refuses_anything_that_does_not_check_out(client, admin, entra, tamper, message):
    _configure(client, admin)
    if tamper == "audience":
        entra.claims = {"aud": "someone-elses-app"}
    elif tamper == "issuer":
        entra.claims = {"iss": "https://login.microsoftonline.com/another-tenant/v2.0"}
    elif tamper == "signature":
        entra.sign_with = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif tamper == "expired":
        entra.claims = {"exp": int(time.time()) - 3600}
    elif tamper == "nobody":
        entra.claims = {"preferred_username": "stranger@example.com"}
    response = _sign_in(client, entra, cookie="not-the-right-browser" if tamper == "cookie" else None)
    assert response.status_code == 302 and message in _error(response)
    assert "sso=" not in response.headers["location"].split("?", 1)[-1].replace("sso_error=", "")


def test_requiring_microsoft_sign_in_keeps_a_platform_admin_break_glass(client, admin, entra):
    technician = client.post("/api/console/users", headers=admin, json={
        "email": "tech@fenrir.local", "name": "Tech", "password": "a-long-enough-password", "role": "technician"})
    assert technician.status_code in (200, 201), technician.text
    _configure(client, admin, required=True)
    refused = client.post("/api/console/auth/login", json={"email": "tech@fenrir.local", "password": "a-long-enough-password"})
    assert refused.status_code == 403 and "Microsoft" in refused.json()["detail"]
    assert client.post("/api/console/auth/login", json={"email": "admin@fenrir.local", "password": ADMIN_PASSWORD}).status_code == 200


def test_entra_mfa_satisfies_required_mfa_only_when_trusted(client, admin, entra):
    _configure(client, admin)
    with database.session_factory()() as db:
        platform_security.save(db, {"requireMfa": True})
        db.commit()

    def signed_in_headers():
        handoff = urllib.parse.parse_qs(urllib.parse.urlparse(_sign_in(client, entra).headers["location"]).query)["sso"][0]
        return {"Authorization": f"Bearer {client.post('/api/console/auth/sso/complete', json={'handoff': handoff}).json()['token']}"}

    untrusted = signed_in_headers()
    assert client.get("/api/console/devices", headers=untrusted).status_code == 403  # still needs Fenrir MFA
    with database.session_factory()() as db:
        platform_security.save(db, {"sso": {**sso.settings(db), "trustMfa": True}})
        db.commit()
    assert client.get("/api/console/devices", headers=signed_in_headers()).status_code == 200


def test_sso_settings_validation(client, admin):
    bad = client.put("/api/console/platform/security/sso", headers=_stepup(client, admin),
                     json={"enabled": True, "tenant": "common", "clientId": CLIENT_ID, "clientSecret": "x"})
    assert bad.status_code == 400 and "own Entra tenant" in bad.json()["detail"]
    assert client.put("/api/console/platform/security/sso", headers=_stepup(client, admin),
                      json={"enabled": False, "required": True}).status_code == 400
    assert client.get("/api/console/auth/sso/start", follow_redirects=False).headers["location"].startswith("/?sso_error=")
