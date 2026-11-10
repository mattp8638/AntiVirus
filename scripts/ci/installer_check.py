"""CI check after deploy/install.sh: sign in as the new admin (enrolling MFA, which production mode requires), then
confirm the MSP is named and signed Windows installers are ready. Usage: installer_check.py URL EMAIL PASSWORD MSP"""

import base64
import hashlib
import hmac
import json
import struct
import sys
import time
import urllib.request


def call(base, path, token=None, body=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                 method="POST" if body is not None else "GET", headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def totp(secret, at=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int((at or time.time()) // 30)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def main(base, email, password, msp):
    login = call(base, "/api/console/auth/login", body={"email": email, "password": password})
    token = login["token"]
    if login.get("mfaSetupRequired"):
        secret = call(base, "/api/console/auth/mfa/setup", token, {})["secret"]
        call(base, "/api/console/auth/mfa/enable", token, {"code": totp(secret)})
        print("MFA enrolled (production mode requires it for staff)")
    tenants = call(base, "/api/console/tenants", token)
    items = tenants.get("items", tenants) if isinstance(tenants, dict) else tenants
    assert any(t.get("name") == msp for t in items), f"MSP {msp!r} not found"
    status = call(base, "/api/console/enrollment-installers/status", token)
    print(json.dumps(status["windows"]))
    assert status["windows"]["ready"] and status["windows"]["mode"] == "signed", status["windows"]
    print("OK: signed in, MSP named, signed Windows installer ready")


if __name__ == "__main__":
    main(*sys.argv[1:5])
