"""Security hardening: the real client address behind a trusted proxy only, security headers, idle sessions ending."""
import asyncio
from datetime import timedelta

from fenrir_cloud import proxies, sessions
from fenrir_cloud import db as database
from fenrir_cloud.models import UserSession, utcnow

NETWORKS = proxies.parse("172.16.0.0/12, 127.0.0.1")


def test_client_comes_from_the_proxy_header_only_when_the_proxy_is_trusted():
    assert proxies.client_from("172.18.0.5", "203.0.113.9", NETWORKS) == "203.0.113.9"
    # Not from a trusted proxy: the header is the client's own claim and is ignored.
    assert proxies.client_from("198.51.100.4", "203.0.113.9", NETWORKS) == "198.51.100.4"
    # A client cannot hide behind a forged first hop: the right-most untrusted address wins.
    assert proxies.client_from("172.18.0.5", "10.9.9.9, 203.0.113.9", NETWORKS) == "203.0.113.9"
    assert proxies.client_from("172.18.0.5", "203.0.113.9, 172.18.0.7", NETWORKS) == "203.0.113.9"
    assert proxies.client_from("172.18.0.5", "[2001:db8::1]:443", NETWORKS) == "2001:db8::1"
    assert proxies.client_from("172.18.0.5", "not-an-address", NETWORKS) == "172.18.0.5"
    assert proxies.client_from("172.18.0.5", "203.0.113.9", []) == "172.18.0.5"


def test_middleware_rewrites_the_client_and_scheme():
    seen = {}

    async def app(scope, receive, send):
        seen.update(client=scope["client"], scheme=scope["scheme"])

    middleware = proxies.TrustedProxyMiddleware(app, NETWORKS)
    scope = {"type": "http", "client": ("172.18.0.5", 4000), "scheme": "http",
             "headers": [(b"x-forwarded-for", b"203.0.113.9"), (b"x-forwarded-proto", b"https")]}
    asyncio.run(middleware(scope, None, None))
    assert seen == {"client": ("203.0.113.9", 4000), "scheme": "https"}


def test_security_headers(client):
    response = client.get("/health")
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["strict-transport-security"].startswith("max-age=")  # the test server's URL is https


def test_idle_sessions_end(client, admin, monkeypatch):
    assert client.get("/api/console/auth/me", headers=admin).json()["sessionIdleMinutes"] == 60
    with database.session_factory()() as db:
        row = db.query(UserSession).filter(UserSession.revoked_at.is_(None)).first()
        row.last_seen_at = utcnow() - timedelta(minutes=62)
        db.commit()
    assert client.get("/api/console/auth/me", headers=admin).status_code == 401
    with database.session_factory()() as db:
        assert db.query(UserSession).filter(UserSession.revoked_reason == "idle").count() == 1


def test_security_txt_only_when_a_contact_is_set(client, monkeypatch):
    assert client.get("/.well-known/security.txt").status_code == 404
    monkeypatch.setenv("FENRIR_SECURITY_CONTACT", "mailto:security@msp.example")
    text = client.get("/.well-known/security.txt").text
    assert "Contact: mailto:security@msp.example" in text and "Expires: " in text
