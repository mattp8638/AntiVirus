"""VULN-08: safe web application assessment of an attested external asset."""
import httpx
import pytest

from test_documentation_vault import stepup
from fenrir_cloud import db as database, web_assessment as wa
from fenrir_cloud.models import AuditLog, ExternalAsset, WebAssessment

REAL = httpx.Client
HOST = "app.customer-site.test"


def site(seen):
    def handler(request: httpx.Request):
        seen.append((request.method, str(request.url), dict(request.headers)))
        path = request.url.path
        if request.url.scheme == "http":
            return httpx.Response(200, headers={"content-type": "text/html"}, text="<form action='/login'><input type='password'></form>")
        if path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /private\n")
        if path == "/":
            origin = request.headers.get("origin")
            headers = {"content-type": "text/html", "server": "nginx/1.18.0",
                       "set-cookie": "sessionid=abc; Path=/"}
            if origin:
                headers.update({"access-control-allow-origin": origin, "access-control-allow-credentials": "true"})
            q = request.url.params.get("fenrir_probe", "")
            return httpx.Response(200, headers=headers, text=(
                "<html><head><script src='https://cdn.example.net/jquery-1.12.4.min.js'></script></head><body>"
                "<a href='/about'>About</a><a href='/private/admin'>Admin</a><a href='https://elsewhere.test/'>x</a>"
                f"<p>{q}</p></body></html>"))
        if path == "/about":
            return httpx.Response(200, headers={"content-type": "text/html"}, text="<title>Index of /about</title>")
        if path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n")
        if path == "/secure":
            ok = request.headers.get("authorization") == "Bearer app-token"
            return httpx.Response(200 if ok else 401, text="members")
        return httpx.Response(404, text="not found")
    return handler


@pytest.fixture
def web(monkeypatch):
    seen = []
    monkeypatch.setattr(wa, "_client", lambda: REAL(transport=httpx.MockTransport(site(seen)), follow_redirects=False))
    monkeypatch.setattr(wa.time, "sleep", lambda s: None)
    return seen


def asset(tenant_id, target=HOST):
    with database.session_factory()() as db:
        row = ExternalAsset(tenant_id=tenant_id, target=target, ownership_attested_by="owner@example.test")
        db.add(row)
        db.commit()
        return row.id


def run_queued():
    with database.session_factory()() as db:
        wa.tick(db)


def test_standard_assessment_findings_limits_and_evidence(client, admin, tenant, web):
    aid = asset(tenant["id"])
    r = client.post("/api/console/web-assessments", headers=admin, json={"tenantId": tenant["id"], "assetId": aid,
                                                                       "url": f"https://{HOST}/", "profile": "standard"})
    assert r.status_code == 200, r.text
    run_queued()
    out = client.get(f"/api/console/web-assessments/{r.json()['id']}", headers=admin).json()
    assert out["status"] == "completed", out["error"]
    by = {f["key"]: f for f in out["findings"]}
    assert by["missing-headers"]["status"] == "confirmed" and by["no-hsts"]["owasp"] == "A02"
    assert by["version-banner"]["evidence"] == "server: nginx/1.18.0"
    assert "Secure" in by["cookie-flags:sessionid"]["title"] and by["cookie-flags:sessionid"]["owasp"] == "A07"
    assert by["directory-listing"]["url"].endswith("/about")
    assert by["exposed:/.git/HEAD"]["status"] == "confirmed" and by["exposed:/.git/HEAD"]["severity"] == "high"
    assert any(k.startswith("old-library") and by[k]["status"] == "suspected" for k in by)
    assert by["reflection"]["status"] == "suspected" and by["cors-any-origin"]["status"] == "confirmed"
    assert all(f["request"].startswith("GET ") and f["responseStatus"] for f in out["findings"])
    # Only GET requests, only the attested host, robots.txt respected.
    assert {m for m, _, _ in web} == {"GET"}
    assert all(HOST in u for _, u, _ in web)
    assert not any("/private" in u for _, u, _ in web) and any(p.get("skipped") == "robots.txt" for p in out["pages"])
    assert {u["owasp"] for u in out["untested"]} >= {"A04", "A09", "A10", "A01"}
    assert out["summary"]["confirmed"] >= 6 and out["summary"]["limits"]["max_pages"] == 50


def test_passive_profile_sends_no_probes_and_auth_is_not_kept(client, admin, tenant, web):
    aid = asset(tenant["id"])
    body = {"tenantId": tenant["id"], "assetId": aid, "url": f"https://{HOST}/secure", "authHeader": "Authorization",
            "authValue": "Bearer app-token", "maxPages": 3}
    assert client.post("/api/console/web-assessments", headers=admin, json=body).status_code == 403  # step-up for credentials
    row = client.post("/api/console/web-assessments", headers=stepup(client, admin), json=body).json()
    assert "authValue" not in row and "authEnvelope" not in row and row["config"]["authenticated"] is True
    run_queued()
    out = client.get(f"/api/console/web-assessments/{row['id']}", headers=admin).json()
    assert out["status"] == "completed"
    assert not any("fenrir_probe" in u for _, u, _ in web) and not any("origin" in h for _, _, h in web)
    assert any(h.get("authorization") == "Bearer app-token" for _, _, h in web)
    assert len([p for p in out["pages"] if "status" in p]) <= 3
    with database.session_factory()() as db:
        assert db.get(WebAssessment, row["id"]).auth_envelope is None
        assert "app-token" not in str([a.details for a in db.query(AuditLog).all()])


def test_targets_must_be_attested_assets(client, admin, tenant, web):
    aid = asset(tenant["id"])
    bad = client.post("/api/console/web-assessments", headers=admin, json={"tenantId": tenant["id"], "assetId": aid,
                                                                         "url": "https://someone-else.test/"})
    assert bad.status_code == 400 and "attested" in bad.json()["detail"]
    meta = asset(tenant["id"], "169.254.169.254")
    blocked = client.post("/api/console/web-assessments", headers=admin, json={"tenantId": tenant["id"], "assetId": meta,
                                                                             "url": "http://169.254.169.254/"})
    assert blocked.status_code == 400
    plain = client.post("/api/console/web-assessments", headers=admin, json={"tenantId": tenant["id"], "assetId": aid, "url": f"http://{HOST}/"})
    run_queued()
    out = client.get(f"/api/console/web-assessments/{plain.json()['id']}", headers=admin).json()
    keys = {f["key"] for f in out["findings"]}
    assert {"no-https-redirect", "password-over-http"} <= keys
