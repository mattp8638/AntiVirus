"""MSP branding (sign-in page, reports, agent window) and customer reports as branded HTML and PDF, kept and scheduled."""

import base64
import io
import json
from datetime import timedelta

from conftest import enroll, login
from fenrir_cloud import branding, db as database, mailer, reports, services
from fenrir_cloud.models import ClientReport, Device, Tenant, Vulnerability, utcnow


def _png(width=900, height=300, colour=(20, 60, 160)) -> str:
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (width, height), colour).save(out, format="PNG")
    return base64.b64encode(out.getvalue()).decode()


def _brand(client, admin, **values):
    body = {"companyName": "Northwind IT", "primaryColour": "#0F766E", "supportEmail": "help@northwind.example",
            "supportPhone": "0161 496 0000", "website": "https://northwind.example", "reportFooter": "Confidential.", **values}
    response = client.put("/api/console/branding", headers=admin, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _customer_admin(client, admin, tenant, email="ops@acme.example"):
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": email,
                                                           "password": "acme-password-123", "role": "tenant_admin"})
    return login(client, email, "acme-password-123")


# --------------------------------------------------------------------------- branding


def test_brand_defaults_then_customised_and_public(client, admin):
    public = client.get("/api/console/auth/branding").json()
    assert public["logoUrl"] is None and public["primaryColour"] == "#3b82f6" and "supportEmail" not in public
    assert public["companyName"] == "Fenrir"  # the MSP's tenant name is not shown to anonymous visitors until branded
    saved = _brand(client, admin)
    assert saved["companyName"] == "Northwind IT" and saved["primaryColour"] == "#0f766e" and saved["editable"] is True
    assert saved["onPrimary"] == "#ffffff"
    public = client.get("/api/console/auth/branding").json()
    assert public["companyName"] == "Northwind IT" and "supportEmail" not in public and "reportFooter" not in public
    assert _brand(client, admin, primaryColour="#fde68a")["onPrimary"] == "#111827"  # dark text on a light colour
    # Clearing a value falls back to the default.
    assert _brand(client, admin, primaryColour="")["primaryColour"] == "#3b82f6"


def test_brand_input_is_validated(client, admin):
    for bad in ({"primaryColour": "blue"}, {"primaryColour": "#12345"}, {"website": "http://northwind.example"},
                {"supportEmail": "not-an-email"}, {"companyName": "x" * 81}, {"tagline": 12}):
        assert client.put("/api/console/branding", headers=admin, json=bad).status_code == 400, bad
    # Control characters are stripped rather than stored.
    assert _brand(client, admin, companyName="North\nwind\x00 IT")["companyName"] == "North wind  IT"


def test_logo_is_reencoded_and_unsafe_files_are_refused(client, admin):
    saved = client.put("/api/console/branding/logo", headers=admin, json={"data": "data:image/png;base64," + _png()}).json()
    assert saved["logoUrl"].startswith("/api/console/branding/logo?v=") and saved["logoDataUrl"].startswith("data:image/png;base64,")
    logo = client.get("/api/console/auth/branding/logo")
    assert logo.status_code == 200 and logo.headers["content-type"] == "image/png" and logo.content.startswith(b"\x89PNG")
    from PIL import Image

    assert Image.open(io.BytesIO(logo.content)).size == (600, 200)  # scaled into the logo box
    svg = base64.b64encode(b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>').decode()
    for bad in (svg, base64.b64encode(b"\x89PNG\r\n\x1a\nnot really a png").decode(), "!!not base64!!", ""):
        response = client.put("/api/console/branding/logo", headers=admin, json={"data": bad})
        assert response.status_code == 400, bad
    assert client.delete("/api/console/branding/logo", headers=admin).json()["logoUrl"] is None
    assert client.get("/api/console/auth/branding/logo").status_code == 404


def test_oversized_logo_dimensions_are_refused(client, admin, monkeypatch):
    monkeypatch.setattr(branding, "MAX_PIXELS", 100 * 100)
    response = client.put("/api/console/branding/logo", headers=admin, json={"data": _png(200, 200)})
    assert response.status_code == 400 and "too large" in response.json()["detail"]


def test_customers_inherit_the_brand_but_cannot_change_it(client, admin, tenant):
    _brand(client, admin)
    ops = _customer_admin(client, admin, tenant)
    mine = client.get("/api/console/branding", headers=ops).json()
    assert mine["companyName"] == "Northwind IT" and mine["supportEmail"] == "help@northwind.example" and mine["editable"] is False
    assert client.put("/api/console/branding", headers=ops, json={"companyName": "Hijack"}).status_code == 403
    assert client.put("/api/console/branding/logo", headers=ops, json={"data": _png()}).status_code == 403


def test_agent_window_shows_the_msp_brand_unless_the_policy_names_one(client, admin, tenant):
    device = enroll(client, admin, tenant)
    with database.session_factory()() as session:
        resolution, doc = services.effective_policy(session, session.get(Device, device["deviceId"]))
        assert resolution["settings"]["experience"]["brandName"] == "Fenrir"  # not customised: unchanged
    _brand(client, admin)
    with database.session_factory()() as session:
        resolution, doc = services.effective_policy(session, session.get(Device, device["deviceId"]))
        assert resolution["settings"]["experience"]["brandName"] == "Northwind IT"
        assert "Northwind IT" in json.dumps(doc)


# --------------------------------------------------------------------------- reports


def _vulns(tenant_id, device_id):
    now = utcnow()
    with database.session_factory()() as session:
        session.add_all([
            Vulnerability(tenant_id=tenant_id, device_id=device_id, vuln_id="CVE-2024-1111", package="OpenSSL", severity="medium",
                          cvss=5.0, first_seen=now - timedelta(days=10)),
            Vulnerability(tenant_id=tenant_id, device_id=device_id, vuln_id="CVE-2024-2222", package="Chrome", severity="high",
                          cvss=8.8, known_exploited=True, epss=0.42, first_seen=now - timedelta(days=120), due_at=now - timedelta(days=3)),
            Vulnerability(tenant_id=tenant_id, device_id=device_id, vuln_id="CVE-2024-3333", package="7-Zip", severity="critical",
                          cvss=9.8, first_seen=now - timedelta(days=40)),
            Vulnerability(tenant_id=tenant_id, device_id=device_id, vuln_id="CVE-2023-4444", package="Java", severity="high",
                          status="accepted", exception_reason="Vendor app needs Java 8", exception_approved_by="cfo@acme.example",
                          exception_expires_at=now + timedelta(days=60)),
        ])
        session.commit()


def test_every_report_kind_is_a_branded_pdf_and_html(client, admin, tenant):
    _brand(client, admin)
    client.put("/api/console/branding/logo", headers=admin, json={"data": _png()})
    device = enroll(client, admin, tenant)
    _vulns(tenant["id"], device["deviceId"])
    for kind in reports.KINDS:
        pdf = client.get(f"/api/console/reports/{kind}.pdf", headers=admin, params={"tenant_id": tenant["id"]})
        assert pdf.status_code == 200, (kind, pdf.text)
        assert pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF")
        assert f'filename="Acme-Dental-{kind}-' in pdf.headers["content-disposition"]
        page = client.get(f"/api/console/reports/{kind}.html", headers=admin, params={"tenant_id": tenant["id"]})
        assert page.status_code == 200 and "Northwind IT" in page.text and "data:image/png;base64," in page.text, kind
        assert "help@northwind.example" in page.text and "Confidential." in page.text and "#0f766e" in page.text


def test_executive_report_recommends_next_steps(client, admin, tenant):
    device = enroll(client, admin, tenant)
    _vulns(tenant["id"], device["deviceId"])
    page = client.get("/api/console/reports/executive.html", headers=admin, params={"tenant_id": tenant["id"], "days": 7}).text
    assert "Security report: Acme Dental" in page and "Last 7 days" in page and "Recommended next steps" in page
    assert "Fix the 1 vulnerability known to be exploited by attackers first." in page
    assert "Remediate 1 critical and 1 high-severity vulnerabilities." in page  # the accepted risk is not counted
    assert "By priority" in page and "Engineer time" in page
    assert client.get("/api/console/reports/executive.pdf", headers=admin,
                      params={"tenant_id": tenant["id"], "days": 45}).status_code == 400


def test_vulnerability_report_ranks_known_exploited_first_and_lists_accepted_risks(client, admin, tenant):
    device = enroll(client, admin, tenant)
    _vulns(tenant["id"], device["deviceId"])
    with database.session_factory()() as session:
        _, doc = reports.vulnerability_doc(session, session.get(Tenant, tenant["id"]))
    kpis = {k["label"]: k["value"] for k in doc["blocks"][0]["items"]}
    assert kpis["open vulnerabilities"] == 3 and kpis["past their fix-by date"] == 1 and kpis["risks accepted"] == 1
    ranked = next(b for b in doc["blocks"] if b.get("type") == "table" and "CVSS" in b["columns"])
    assert [row[0] for row in ranked["rows"]] == ["CVE-2024-2222 (KEV)", "CVE-2024-3333", "CVE-2024-1111"]
    assert ranked["rows"][0][1] == "ACME-WS-01" and ranked["rows"][0][5] == "42%" and ranked["rows"][0][6]["status"] == "bad"
    accepted = next(b for b in doc["blocks"] if b.get("type") == "table" and "Reason" in b["columns"])
    assert accepted["rows"][0][2] == "Vendor app needs Java 8"
    ageing = next(b for b in doc["blocks"] if b.get("type") == "table" and "over 90 days" in b["columns"])
    assert ageing["rows"][1][3]["text"] == "1" and ageing["rows"][1][3]["status"] == "bad"  # an old high


def test_reports_are_scoped_to_the_callers_customers(client, admin, tenant):
    other = client.post("/api/console/tenants", headers=admin, json={"name": "Other Ltd", "template": "balanced"}).json()
    ops = _customer_admin(client, admin, tenant)
    assert client.get("/api/console/reports/vulnerability.pdf", headers=ops, params={"tenant_id": other["id"]}).status_code == 404
    assert client.get("/api/console/reports/executive.html", headers=ops, params={"tenant_id": other["id"]}).status_code == 404
    assert client.get("/api/console/reports/vulnerability.pdf", headers=ops, params={"tenant_id": tenant["id"]}).status_code == 200
    assert client.get("/api/console/reports/nonsense.pdf", headers=admin, params={"tenant_id": tenant["id"]}).status_code == 404
    assert client.get("/api/console/reports/schedules", headers=ops, params={"tenant_id": other["id"]}).status_code == 404


def test_kept_reports_download_as_pdf(client, admin, tenant):
    kept = client.post(f"/api/console/clients/{tenant['id']}/reports", headers=admin, json={"kind": "quarterly", "period": "2026-Q3"}).json()
    listed = client.get(f"/api/console/clients/{tenant['id']}/reports", headers=admin).json()
    assert listed[0]["hasPdf"] is True
    pdf = client.get(f"/api/console/clients/{tenant['id']}/reports/{kept['id']}.pdf", headers=admin)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and "quarterly-2026-Q3" in pdf.headers["content-disposition"]
    with database.session_factory()() as session:  # a report kept before PDF copies existed
        old = ClientReport(tenant_id=tenant["id"], kind="monthly", period="2026-01", html="<p>old</p>")
        session.add(old)
        session.commit()
        old_id = old.id
    assert client.get(f"/api/console/clients/{tenant['id']}/reports/{old_id}.pdf", headers=admin).status_code == 409


# --------------------------------------------------------------------------- schedules


def test_schedules_are_validated_and_send_once_per_period(client, admin, tenant):
    url = "/api/console/reports/schedules"
    params = {"tenant_id": tenant["id"]}
    for bad in ([{"kind": "nope", "every": "monthly", "to": ["a@b.example"]}],
                [{"kind": "executive", "every": "daily", "to": ["a@b.example"]}],
                [{"kind": "executive", "every": "monthly", "to": []}],
                [{"kind": "executive", "every": "monthly", "to": ["not an email"]}], "not a list"):
        assert client.put(url, headers=admin, params=params, json={"schedules": bad}).status_code == 400, bad
    saved = client.put(url, headers=admin, params=params, json={"schedules": [
        {"kind": "executive", "every": "monthly", "to": ["CEO@acme.example", "ceo@acme.example"], "lastPeriod": "forged"},
        {"kind": "vulnerability", "every": "weekly", "to": ["it@acme.example"]}]}).json()["schedules"]
    assert saved[0]["to"] == ["ceo@acme.example"] and saved[0]["lastPeriod"] is None and len(saved[0]["id"]) >= 8
    mailer.OUTBOX.clear()
    with database.session_factory()() as session:
        assert reports.send_schedules(session) == 2
        assert reports.send_schedules(session) == 0  # already sent this period
    sent = [m for m in mailer.OUTBOX if m["to"] in ("ceo@acme.example", "it@acme.example")]
    assert len(sent) == 2 and all(m["attachments"][0].endswith(".pdf") for m in sent)
    assert any(m["subject"].startswith("Security report: Acme Dental") for m in sent)
    stored = client.get(url, headers=admin, params=params).json()["schedules"]
    assert all(s["lastSentAt"] and s["lastError"] is None for s in stored)
    # Saving the same schedules again keeps their delivery state; changing one resets it.
    resaved = client.put(url, headers=admin, params=params, json={"schedules": [
        stored[0], {**stored[1], "every": "monthly"}]}).json()["schedules"]
    assert resaved[0]["lastPeriod"] == stored[0]["lastPeriod"] and resaved[1]["lastPeriod"] is None


def test_a_failing_report_is_recorded_and_does_not_stop_the_others(client, admin, tenant, monkeypatch):
    params = {"tenant_id": tenant["id"]}
    client.put("/api/console/reports/schedules", headers=admin, params=params, json={"schedules": [
        {"kind": "vulnerability", "every": "monthly", "to": ["it@acme.example"]},
        {"kind": "executive", "every": "monthly", "to": ["ceo@acme.example"]}]})
    real = reports.vulnerability_doc

    def broken(db, tenant):
        raise RuntimeError("scanner database unavailable")

    monkeypatch.setattr(reports, "vulnerability_doc", broken)
    with database.session_factory()() as session:
        assert reports.send_schedules(session) == 1
    stored = client.get("/api/console/reports/schedules", headers=admin, params=params).json()["schedules"]
    assert "scanner database unavailable" in stored[0]["lastError"] and stored[1]["lastError"] is None
    monkeypatch.setattr(reports, "vulnerability_doc", real)
    mailer.OUTBOX.clear()
    sent = client.post(f"/api/console/reports/schedules/{stored[0]['id']}/send", headers=admin, params=params)
    assert sent.status_code == 200 and sent.json()["sent"] == 1 and mailer.OUTBOX[-1]["to"] == "it@acme.example"


def test_only_configurers_change_schedules(client, admin, tenant):
    client.post("/api/console/users", headers=admin, json={"tenantId": tenant["id"], "email": "view@acme.example",
                                                           "password": "acme-password-123", "role": "viewer"})
    viewer = login(client, "view@acme.example", "acme-password-123")
    params = {"tenant_id": tenant["id"]}
    assert client.get("/api/console/reports/schedules", headers=viewer, params=params).status_code == 200
    assert client.put("/api/console/reports/schedules", headers=viewer, params=params, json={"schedules": [
        {"kind": "executive", "every": "monthly", "to": ["x@y.example"]}]}).status_code == 403


# --------------------------------------------------------------------------- modules (Essentials layout)


def test_new_installs_start_with_essentials_and_admins_choose_modules(client, admin, tenant):
    from fenrir_cloud import modules

    shown = client.get("/api/console/modules", headers=admin).json()
    assert shown["enabled"] == modules.ESSENTIALS and shown["editable"] is True
    assert {m["key"] for m in shown["modules"]} == set(modules.MODULES)
    saved = client.put("/api/console/modules", headers=admin, json={"enabled": ["identity", "service"]}).json()
    assert saved["enabled"] == ["service", "identity"]  # kept in the catalogue's order
    assert client.put("/api/console/modules", headers=admin, json={"enabled": ["nonsense"]}).status_code == 400
    assert client.put("/api/console/modules", headers=admin, json={"enabled": "service"}).status_code == 400
    ops = _customer_admin(client, admin, tenant)
    mine = client.get("/api/console/modules", headers=ops).json()
    assert mine["enabled"] == ["service", "identity"] and mine["editable"] is False
    assert client.put("/api/console/modules", headers=ops, json={"enabled": []}).status_code == 403


def test_existing_installs_keep_every_module(client, admin):
    from fenrir_cloud import modules

    with database.session_factory()() as session:
        msp = branding.default_msp(session)
        msp.settings = {k: v for k, v in (msp.settings or {}).items() if k != "modules"}  # an install from before modules
        session.commit()
    assert client.get("/api/console/modules", headers=admin).json()["enabled"] == list(modules.MODULES)
