"""M365-32: domain/email diagnostics and the gated, read-only Graph explorer."""
import httpx
import pytest

from conftest import login
from test_msp_modules import connection
from fenrir_cloud import db as database, m365, m365_tools as tools
from fenrir_cloud.models import AuditLog

REAL = httpx.Client
DNS = {
    ("contoso.example", "MX"): ["0 contoso-example.mail.protection.outlook.com."],
    ("contoso.example", "TXT"): ["v=spf1 include:spf.protection.outlook.com include:a.example include:b.example ~all", "other=1"],
    ("_dmarc.contoso.example", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@contoso.example"],
    ("selector1._domainkey.contoso.example", "CNAME"): ["selector1-contoso._domainkey.contoso.onmicrosoft.com."],
    ("autodiscover.contoso.example", "CNAME"): ["autodiscover.outlook.com."],
}
CODES = {"MX": 15, "TXT": 16, "CNAME": 5}


@pytest.fixture
def net(monkeypatch):
    calls = []

    def handler(request: httpx.Request):
        calls.append(request)
        if request.url.host == "cloudflare-dns.com":
            name, rtype = request.url.params["name"], request.url.params["type"]
            return httpx.Response(200, json={"Answer": [{"type": CODES[rtype], "data": d} for d in DNS.get((name, rtype), [])]})
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"issuer": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"})
        if request.url.host == "graph.microsoft.com":
            return httpx.Response(200, json={"value": [{"displayName": "Ann"}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skip=1"})
        return httpx.Response(404)

    monkeypatch.setattr(tools, "_client", lambda: REAL(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(tools.httpx, "Client", lambda **kw: REAL(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(m365, "access_token", lambda client, conn, *a, **k: "token")
    return calls


def test_domain_diagnostics(client, admin, net):
    out = client.post("/api/console/m365/tools/domain", headers=admin, json={"domain": "Contoso.example"}).json()
    c = {x["check"]: x for x in out["checks"]}
    assert c["mx"]["status"] == "pass" and "Microsoft 365" in c["mx"]["detail"]
    assert c["spf"]["status"] == "pass" and c["spf"]["detail"].startswith("3 DNS lookups")
    assert c["dmarc"]["status"] == "warn" and "p=none" in c["dmarc"]["detail"]
    assert c["dkim"]["status"] == "warn" and c["autodiscover"]["status"] == "pass" and c["mta-sts"]["status"] == "info"
    assert "11111111-2222-3333-4444-555555555555" in c["tenant"]["detail"]
    assert client.post("/api/console/m365/tools/domain", headers=admin, json={"domain": "localhost"}).status_code == 400
    assert client.post("/api/console/m365/tools/domain", headers=admin, json={"domain": "169.254.169.254"}).status_code == 400


@pytest.mark.parametrize("path", ["/me/messages", "/users/ann@x.example/messages", "/users/1/drive/root/children", "/$batch",
                                  "/sites/root", "/users?$skiptoken=x", "/users?$top=500", "https://evil.example/v1.0/users",
                                  "/users/../me/messages", "/chats", "/users/1/mailFolders/inbox"])
def test_explorer_refuses_content_writes_and_unapproved_paths(path):
    with pytest.raises(tools.ToolError):
        tools.validate_path(path)


def test_explorer_reads_with_audit_and_role_gate(client, admin, tenant, net):
    conn = connection(client, admin, tenant)
    url = "/api/console/m365/tools/graph"
    out = client.post(url, headers=admin, json={"connectionId": conn["id"], "path": "/users?$select=displayName&$top=5"}).json()
    assert out["status"] == 200 and out["json"]["value"][0]["displayName"] == "Ann" and out["nextPage"] is True
    graph_calls = [r for r in net if r.url.host == "graph.microsoft.com"]
    assert len(graph_calls) == 1 and graph_calls[0].method == "GET"  # one page, GET only
    r = client.post(url, headers=admin, json={"connectionId": conn["id"], "path": "/me/messages"})
    assert r.status_code == 400 and len([x for x in net if x.url.host == "graph.microsoft.com"]) == 1
    created = client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "viewer@acme.example",
                                                                     "password": "viewer-password-123", "role": "viewer"})
    assert created.status_code == 200, created.text
    viewer = login(client, "viewer@acme.example", "viewer-password-123")
    assert client.post(url, headers=viewer, json={"connectionId": conn["id"], "path": "/users"}).status_code == 403
    with database.session_factory()() as db:
        ok = db.query(AuditLog).filter_by(action="m365.graph_explorer").one()
        assert ok.details["path"].startswith("/users?") and "Ann" not in str(ok.details)
        assert db.query(AuditLog).filter_by(action="m365.graph_explorer_refused").count() == 1
