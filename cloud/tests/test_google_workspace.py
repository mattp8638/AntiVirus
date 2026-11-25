"""VULN-12: Google Workspace posture assessment and safe remediation against a fake Google API."""
import base64
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from test_documentation_vault import stepup
from fenrir_cloud import db as database, google_workspace as gw, m365_tools
from fenrir_cloud.models import AuditLog, GoogleWorkspaceConnection

REAL = httpx.Client
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
OLD = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
RECENT = datetime.now(timezone.utc).isoformat()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@pytest.fixture
def google(monkeypatch):
    state = {"users": {
        "boss@acme.example": {"primaryEmail": "boss@acme.example", "isAdmin": True, "isEnrolledIn2Sv": False, "isEnforcedIn2Sv": False, "lastLoginTime": RECENT},
        "it@acme.example": {"primaryEmail": "it@acme.example", "isDelegatedAdmin": True, "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": True, "lastLoginTime": RECENT},
        "old@acme.example": {"primaryEmail": "old@acme.example", "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": True, "lastLoginTime": OLD},
        "gone@acme.example": {"primaryEmail": "gone@acme.example", "suspended": True, "lastLoginTime": OLD}},
        "tokens": {"boss@acme.example": [{"clientId": "123", "displayText": "Mail merge pro"}]}, "assertions": [], "writes": []}

    def handler(request: httpx.Request):
        url = str(request.url)
        if url.startswith(gw.TOKEN_URL):
            assertion = parse_qs(request.content.decode())["assertion"][0]
            header, claims, sig = assertion.split(".")
            KEY.public_key().verify(b64d(sig), f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
            state["assertions"].append(json.loads(b64d(claims)))
            return httpx.Response(200, json={"access_token": "ya29.token"})
        path = request.url.path.removeprefix("/admin/directory/v1")
        if path == "/users":
            return httpx.Response(200, json={"users": list(state["users"].values())})
        if path.endswith("/tokens"):
            return httpx.Response(200, json={"items": state["tokens"].get(path.split("/")[2], [])})
        if path == "/customer/my_customer/domains":
            return httpx.Response(200, json={"domains": [{"domainName": "acme.example", "verified": True}]})
        if path.startswith("/users/"):
            email = path.split("/")[2]
            user = state["users"][email]
            if request.method in ("PUT", "POST"):
                state["writes"].append((request.method, path, request.content.decode()))
                if request.method == "PUT":
                    user.update(json.loads(request.content))
                return httpx.Response(200 if request.method == "PUT" else 204, json=user if request.method == "PUT" else None)
            return httpx.Response(200, json=user)
        return httpx.Response(404)

    def dns(client, name, rtype):
        return {"acme.example": ["v=spf1 include:_spf.google.com ~all"], "_dmarc.acme.example": ["v=DMARC1; p=reject"]}.get(name, []) \
            if rtype == "TXT" else []

    monkeypatch.setattr(gw, "_client", lambda: REAL(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(m365_tools, "_dns", dns)
    monkeypatch.setattr(m365_tools, "_client", lambda: REAL(transport=httpx.MockTransport(lambda r: httpx.Response(404))))
    return state


def connect(client, admin, tenant, allow=False):
    key = json.dumps({"type": "service_account", "client_email": "fenrir@proj.iam.gserviceaccount.com", "private_key": PEM})
    r = client.post("/api/console/google-workspace/connections", headers=stepup(client, admin),
                    json={"tenantId": tenant["id"], "domain": "acme.example", "adminEmail": "boss@acme.example", "serviceAccountKey": key,
                          "allowChanges": allow})
    assert r.status_code == 200, r.text
    return r.json()


def test_posture_checks_and_explicit_scopes(client, admin, tenant, google):
    conn = connect(client, admin, tenant)
    assert conn["scopes"] == gw.READ_SCOPES and "credentialsEnvelope" not in conn and PEM not in json.dumps(conn)
    out = client.post(f"/api/console/google-workspace/connections/{conn['id']}/assess", headers=admin).json()
    claims = google["assertions"][0]
    assert claims["sub"] == "boss@acme.example" and claims["scope"] == " ".join(gw.READ_SCOPES)
    c = {x["check"]: x for x in out["checks"]}
    assert c["2sv-admins"]["status"] == "fail" and c["2sv-admins"]["evidence"] == ["boss@acme.example"]
    assert c["super-admins"]["status"] == "warn" and c["stale-accounts"]["evidence"] == ["old@acme.example"]
    assert c["admin-oauth"]["evidence"] == ["boss@acme.example: Mail merge pro"]
    assert c["spf:acme.example"]["status"] == "pass" and c["dmarc:acme.example"]["status"] == "pass"
    assert c["dkim:acme.example"]["status"] == "fail"
    assert out["checks"][0]["status"] == "fail" and out["summary"]["fail"] == 2
    with database.session_factory()() as db:
        assert PEM[40:80] not in json.dumps(db.get(GoogleWorkspaceConnection, conn["id"]).credentials_envelope)


def test_remediation_is_opt_in_confirmed_verified_and_spares_super_admins(client, admin, tenant, google):
    url = lambda c: f"/api/console/google-workspace/connections/{c['id']}/remediate"  # noqa: E731
    readonly = connect(client, admin, tenant)
    proof = stepup(client, admin)
    body = {"action": "suspend", "email": "old@acme.example", "confirmEmail": "old@acme.example"}
    r = client.post(url(readonly), headers=proof, json=body)
    assert r.status_code == 409 and "read-only" in r.json()["detail"] and google["writes"] == []
    rw = connect(client, admin, tenant, allow=True)
    assert client.post(url(rw), headers=admin, json=body).status_code == 403  # step-up
    proof = stepup(client, admin)
    assert client.post(url(rw), headers=proof, json={**body, "confirmEmail": "x@acme.example"}).status_code == 409
    out = client.post(url(rw), headers=proof, json=body).json()
    assert out["verified"] is True and google["users"]["old@acme.example"]["suspended"] is True
    assert " ".join(gw.READ_SCOPES + gw.WRITE_SCOPES) == google["assertions"][-1]["scope"]
    r = client.post(url(rw), headers=proof, json={"action": "suspend", "email": "boss@acme.example", "confirmEmail": "boss@acme.example"})
    assert r.status_code == 409 and "super administrators" in r.json()["detail"]
    with database.session_factory()() as db:
        assert db.query(AuditLog).filter_by(action="google_workspace.remediated").count() == 1
        assert db.query(AuditLog).filter_by(action="google_workspace.remediation_refused").count() == 2


def test_bad_key_is_refused(client, admin, tenant):
    r = client.post("/api/console/google-workspace/connections", headers=stepup(client, admin),
                    json={"tenantId": tenant["id"], "domain": "acme.example", "adminEmail": "a@acme.example", "serviceAccountKey": "{}"})
    assert r.status_code == 400 and "service account" in r.json()["detail"]
