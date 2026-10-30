import base64
import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from fenrir_cloud import db as database, platform_security

from conftest import ADMIN_PASSWORD

RP_ID, ORIGIN = "fenrir.test", "https://fenrir.test"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def cbor(value) -> bytes:
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)

    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        return head(3, len(value.encode())) + value.encode()
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(value)


class Authenticator:
    """A software passkey: what a phone or security key does, with the knobs to make it misbehave."""

    def __init__(self, alg: str = "es256", counts: bool = False) -> None:
        self.alg, self.counts, self.count = alg, counts, 0
        self.key = {"es256": lambda: ec.generate_private_key(ec.SECP256R1()), "eddsa": ed25519.Ed25519PrivateKey.generate,
                    "rs256": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)}[alg]()
        self.credential_id = os.urandom(32)
        self.user_handle = b""
        self.origin, self.rp_id, self.flags = ORIGIN, RP_ID, 0x05

    def _cose(self) -> dict:
        public = self.key.public_key()
        if self.alg == "es256":
            n = public.public_numbers()
            return {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        if self.alg == "eddsa":
            from cryptography.hazmat.primitives import serialization
            return {1: 1, 3: -8, -1: 6, -2: public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)}
        n = public.public_numbers()
        return {1: 3, 3: -257, -1: n.n.to_bytes(256, "big"), -2: n.e.to_bytes(3, "big")}

    def _sign(self, data: bytes) -> bytes:
        if self.alg == "es256":
            return self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        if self.alg == "eddsa":
            return self.key.sign(data)
        return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    def create(self, options: dict) -> dict:
        public_key = options["publicKey"]
        assert public_key["authenticatorSelection"]["userVerification"] == "required" and public_key["rp"]["id"] == RP_ID
        self.user_handle = _unb64(public_key["user"]["id"])
        client_data = json.dumps({"type": "webauthn.create", "challenge": public_key["challenge"], "origin": self.origin}).encode()
        auth_data = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([self.flags | 0x40]) + self.count.to_bytes(4, "big")
                     + bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cbor(self._cose()))
        return {"id": _b64(self.credential_id), "rawId": _b64(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": _b64(client_data), "transports": ["internal"],
                             "attestationObject": _b64(cbor({"fmt": "none", "attStmt": {}, "authData": auth_data}))}}

    def get(self, options: dict) -> dict:
        if self.counts:
            self.count += 1
        client_data = json.dumps({"type": "webauthn.get", "challenge": options["publicKey"]["challenge"],
                                  "origin": self.origin}).encode()
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([self.flags]) + self.count.to_bytes(4, "big")
        return {"id": _b64(self.credential_id), "rawId": _b64(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": _b64(client_data), "authenticatorData": _b64(auth_data),
                             "signature": _b64(self._sign(auth_data + hashlib.sha256(client_data).digest())),
                             "userHandle": _b64(self.user_handle)}}


def _stepup(client, headers):
    proof = client.post("/api/console/auth/reauth", headers=headers, json={"password": ADMIN_PASSWORD}).json()["reauthToken"]
    return {**headers, "X-Fenrir-Reauth": proof}


def _register(client, headers, authenticator: Authenticator, name: str = "Laptop") -> dict:
    stepped = _stepup(client, headers)
    options = client.post("/api/console/auth/passkeys/options", headers=stepped)
    assert options.status_code == 200, options.text
    added = client.post("/api/console/auth/passkeys", headers=stepped,
                        json={"token": options.json()["token"], "credential": authenticator.create(options.json()), "name": name})
    assert added.status_code == 200, added.text
    return added.json()


def _sign_in(client, authenticator: Authenticator):
    options = client.post("/api/console/auth/passkey/options").json()
    return client.post("/api/console/auth/passkey/login", json={"token": options["token"], "credential": authenticator.get(options)})


@pytest.mark.parametrize("alg", ["es256", "eddsa", "rs256"])
def test_passkey_sign_in_is_multi_factor(client, admin, alg):
    authenticator = Authenticator(alg)
    assert client.post("/api/console/auth/passkeys/options", headers=admin).status_code == 403  # needs a fresh check
    added = _register(client, admin, authenticator)
    assert added["name"] == "Laptop" and [p["id"] for p in client.get("/api/console/auth/passkeys", headers=admin).json()] == [added["id"]]

    with database.session_factory()() as db:
        platform_security.save(db, {"requireMfa": True})
        db.commit()
    signed_in = _sign_in(client, authenticator)
    assert signed_in.status_code == 200, signed_in.text
    headers = {"Authorization": f"Bearer {signed_in.json()['token']}"}
    # The admin has no authenticator app, but a passkey sign-in already proved two factors.
    assert client.get("/api/console/devices", headers=headers).status_code == 200
    assert client.get("/api/console/auth/me", headers=headers).json()["mfaSetupRequired"] is False
    assert client.get("/api/console/devices", headers=admin).status_code == 403  # the password session still is not
    assert client.get("/api/console/auth/passkeys", headers=headers).json()[0]["lastUsedAt"]
    logins = [e for e in client.get("/api/console/audit", headers=headers).json() if e["action"] == "auth.login"]
    assert any(e["details"].get("method") == "passkey" for e in logins)


def test_a_passkey_response_is_accepted_once(client, admin):
    authenticator = Authenticator()
    _register(client, admin, authenticator)
    options = client.post("/api/console/auth/passkey/options").json()
    body = {"token": options["token"], "credential": authenticator.get(options)}
    assert client.post("/api/console/auth/passkey/login", json=body).status_code == 200
    replay = client.post("/api/console/auth/passkey/login", json=body)
    assert replay.status_code == 401 and "already been used" in replay.json()["detail"]


@pytest.mark.parametrize("tamper, message", [
    ("origin", "not https://fenrir.test"),
    ("rp", "different site"),
    ("no_verification", "PIN, fingerprint or face"),
    ("other_key", "signature is not valid"),
    ("unknown", "not registered"),
])
def test_passkey_sign_in_refuses_what_does_not_check_out(client, admin, tamper, message):
    authenticator = Authenticator()
    _register(client, admin, authenticator)
    if tamper == "origin":
        authenticator.origin = "https://fenrir.test.phish.example"
    elif tamper == "rp":
        authenticator.rp_id = "phish.example"
    elif tamper == "no_verification":
        authenticator.flags = 0x01
    elif tamper == "other_key":
        authenticator.key = ec.generate_private_key(ec.SECP256R1())
    elif tamper == "unknown":
        authenticator.credential_id = os.urandom(32)
    refused = _sign_in(client, authenticator)
    assert refused.status_code == 401 and message in refused.json()["detail"]
    assert "token" not in refused.json()


def test_a_copied_security_key_is_caught_by_its_counter(client, admin):
    authenticator = Authenticator(counts=True)
    _register(client, admin, authenticator)
    assert _sign_in(client, authenticator).status_code == 200
    assert _sign_in(client, authenticator).status_code == 200
    authenticator.count = 0  # a clone still at an earlier count
    refused = _sign_in(client, authenticator)
    assert refused.status_code == 401 and "copied" in refused.json()["detail"]


def test_passkey_confirms_identity_for_sensitive_actions(client, admin):
    authenticator = Authenticator()
    _register(client, admin, authenticator)
    options = client.post("/api/console/auth/passkey/options").json()
    proof = client.post("/api/console/auth/reauth", headers=admin,
                        json={"passkey": {"token": options["token"], "credential": authenticator.get(options)}})
    assert proof.status_code == 200, proof.text
    saved = client.put("/api/console/platform/security", headers={**admin, "X-Fenrir-Reauth": proof.json()["reauthToken"]},
                       json={"consoleAllowedNetworks": []})
    assert saved.status_code == 200


def test_another_persons_passkey_does_not_confirm_your_identity(client, admin):
    created = client.post("/api/console/users", headers=admin, json={
        "email": "tech@fenrir.local", "name": "Tech", "password": "a-long-enough-password", "role": "technician"})
    assert created.status_code in (200, 201), created.text
    login = client.post("/api/console/auth/login", json={"email": "tech@fenrir.local", "password": "a-long-enough-password"})
    tech = {"Authorization": f"Bearer {login.json()['token']}"}
    tech_key = Authenticator()
    stepped = {**tech, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=tech,
                                                      json={"password": "a-long-enough-password"}).json()["reauthToken"]}
    options = client.post("/api/console/auth/passkeys/options", headers=stepped).json()
    assert client.post("/api/console/auth/passkeys", headers=stepped,
                       json={"token": options["token"], "credential": tech_key.create(options)}).status_code == 200
    options = client.post("/api/console/auth/passkey/options").json()
    refused = client.post("/api/console/auth/reauth", headers=admin,
                          json={"passkey": {"token": options["token"], "credential": tech_key.get(options)}})
    assert refused.status_code == 401 and "different account" in refused.json()["detail"]


def test_removing_a_passkey_or_resetting_mfa_takes_it_away(client, admin):
    laptop, phone = Authenticator(), Authenticator()
    first = _register(client, admin, laptop, "Laptop")
    _register(client, admin, phone, "Phone")
    other_session = {"Authorization": f"Bearer {_sign_in(client, phone).json()['token']}"}
    assert client.delete(f"/api/console/auth/passkeys/{first['id']}", headers=admin).status_code == 403
    removed = client.delete(f"/api/console/auth/passkeys/{first['id']}", headers=_stepup(client, admin))
    assert removed.status_code == 200 and removed.json()["sessionsRevoked"] >= 1
    assert client.get("/api/console/auth/me", headers=other_session).status_code == 401
    assert "not registered" in _sign_in(client, laptop).json()["detail"]
    assert _sign_in(client, phone).status_code == 200

    # A lost phone: an administrator's MFA reset removes the person's passkeys too.
    created = client.post("/api/console/users", headers=admin, json={
        "email": "tech@fenrir.local", "name": "Tech", "password": "a-long-enough-password", "role": "technician"}).json()
    tech = {"Authorization": "Bearer " + client.post("/api/console/auth/login", json={
        "email": "tech@fenrir.local", "password": "a-long-enough-password"}).json()["token"]}
    tech_key = Authenticator()
    stepped = {**tech, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=tech,
                                                      json={"password": "a-long-enough-password"}).json()["reauthToken"]}
    options = client.post("/api/console/auth/passkeys/options", headers=stepped).json()
    client.post("/api/console/auth/passkeys", headers=stepped, json={"token": options["token"], "credential": tech_key.create(options)})
    user_id = created["id"]
    reset = client.post(f"/api/console/users/{user_id}/mfa/reset", headers=_stepup(client, admin))
    assert reset.status_code == 200, reset.text
    assert "not registered" in _sign_in(client, tech_key).json()["detail"]


def test_a_staff_member_can_enrol_a_passkey_to_meet_required_mfa(client, admin):
    with database.session_factory()() as db:
        platform_security.save(db, {"requireMfa": True})
        db.commit()
    assert client.get("/api/console/devices", headers=admin).status_code == 403
    authenticator = Authenticator()
    _register(client, admin, authenticator)  # reauth and passkey enrolment stay open behind the MFA gate
    upgraded = {"Authorization": f"Bearer {_sign_in(client, authenticator).json()['token']}"}
    assert client.get("/api/console/devices", headers=upgraded).status_code == 200


def test_passkeys_follow_required_microsoft_sign_in_and_disabled_accounts(client, admin):
    created = client.post("/api/console/users", headers=admin, json={
        "email": "tech@fenrir.local", "name": "Tech", "password": "a-long-enough-password", "role": "technician"}).json()
    tech = {"Authorization": "Bearer " + client.post("/api/console/auth/login", json={
        "email": "tech@fenrir.local", "password": "a-long-enough-password"}).json()["token"]}
    tech_key = Authenticator()
    stepped = {**tech, "X-Fenrir-Reauth": client.post("/api/console/auth/reauth", headers=tech,
                                                      json={"password": "a-long-enough-password"}).json()["reauthToken"]}
    options = client.post("/api/console/auth/passkeys/options", headers=stepped).json()
    client.post("/api/console/auth/passkeys", headers=stepped, json={"token": options["token"], "credential": tech_key.create(options)})
    assert _sign_in(client, tech_key).status_code == 200

    with database.session_factory()() as db:
        platform_security.save(db, {"sso": {"enabled": True, "required": True, "tenant": "contoso.example", "clientId": "x"}})
        db.commit()
    refused = _sign_in(client, tech_key)
    assert refused.status_code == 403 and "Microsoft" in refused.json()["detail"]

    with database.session_factory()() as db:
        platform_security.save(db, {"sso": {"enabled": False}})
        db.commit()
    user_id = created["id"]
    assert client.patch(f"/api/console/users/{user_id}", headers=admin, json={"active": False}).status_code == 200
    assert "cannot sign in" in _sign_in(client, tech_key).json()["detail"]
