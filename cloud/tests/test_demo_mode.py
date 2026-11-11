"""Read-only demo (demo_mode.DemoGuard): look at everything, change nothing, download no agents."""

import asyncio
import json

from fenrir_cloud.demo_mode import DemoGuard


def call(path, method="GET", client="203.0.113.5", headers=None, kind="http", token="seed-secret"):
    reached, sent = [], []

    async def app(scope, receive, send):
        reached.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": kind, "path": path, "method": method, "client": (client, 5000),
             "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]}
    asyncio.run(DemoGuard(app, seed_token=token)(scope, receive, send))
    status = next((m.get("status") for m in sent if m["type"] == "http.response.start"), None)
    return status, bool(reached), sent


def test_reading_and_signing_in_work():
    assert call("/api/console/devices")[:2] == (200, True)
    assert call("/")[:2] == (200, True)
    assert call("/api/console/auth/login", "POST")[:2] == (200, True)
    assert call("/api/console/auth/logout", "POST")[:2] == (200, True)


def test_every_change_is_refused():
    for method, path in [("POST", "/api/console/rmm/scripts"), ("PATCH", "/api/console/rmm/scripts/x"),
                         ("DELETE", "/api/console/tenants/t"), ("PUT", "/api/console/branding"),
                         ("POST", "/api/console/remote/sessions"), ("POST", "/api/console/enrollment-installers"),
                         ("POST", "/api/console/deploy-scripts"), ("POST", "/api/console/auth/mfa/setup")]:
        status, reached, sent = call(path, method)
        assert (status, reached) == (403, False), (method, path)
    body = json.loads(sent[-1]["body"])
    assert body["demo"] is True and "read-only demo" in body["detail"]


def test_no_agent_downloads_enrolment_or_agent_api():
    for path in ["/downloads/fenrir-agent-linux-amd64", "/downloads/fenrir-android.apk", "/install/linux.sh",
                 "/api/v1/install/windows.exe", "/api/v1/agent/update/windows", "/api/v1/devices/d/commands/pending"]:
        assert call(path)[:2] == (403, False), path
    assert call("/api/v1/enroll", "POST")[:2] == (403, False)


def test_remote_sessions_cannot_connect():
    status, reached, sent = call("/api/remote/relay", kind="websocket")
    assert not reached and sent == [{"type": "websocket.close", "code": 1008}]


def test_only_the_loader_inside_the_container_can_write():
    seed = {"X-Fenrir-Demo-Seed": "seed-secret"}
    assert call("/api/console/tenants", "POST", client="127.0.0.1", headers=seed)[:2] == (200, True)
    assert call("/api/v1/enroll", "POST", client="127.0.0.1", headers=seed)[:2] == (200, True)
    assert call("/api/console/tenants", "POST", client="203.0.113.5", headers=seed)[:2] == (403, False)  # not from inside
    assert call("/api/console/tenants", "POST", client="127.0.0.1", headers={"X-Fenrir-Demo-Seed": "wrong"})[:2] == (403, False)
    assert call("/api/console/tenants", "POST", client="127.0.0.1", headers=seed, token="")[:2] == (403, False)  # no token set


def test_public_branding_says_it_is_a_demo(client):
    import dataclasses

    from fenrir_cloud import config

    original = config.get_settings()
    config.set_settings(dataclasses.replace(original, demo_mode=True, demo_login="demo@fenrir.demo / Demo-Password-1"))
    try:
        data = client.get("/api/console/auth/branding").json()
        assert data["demo"]["login"] == "demo@fenrir.demo / Demo-Password-1"
    finally:
        config.set_settings(original)
    assert "demo" not in client.get("/api/console/auth/branding").json()


def test_demo_shows_every_module(client, admin):
    import dataclasses

    from fenrir_cloud import config, modules

    client.put("/api/console/modules", json={"enabled": list(modules.ESSENTIALS)}, headers=admin)
    assert client.get("/api/console/modules", headers=admin).json()["enabled"] == list(modules.ESSENTIALS)
    original = config.get_settings()
    config.set_settings(dataclasses.replace(original, demo_mode=True))
    try:
        assert client.get("/api/console/modules", headers=admin).json()["enabled"] == list(modules.MODULES)
    finally:
        config.set_settings(original)
