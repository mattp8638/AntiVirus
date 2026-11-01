"""Usage-based billing from Microsoft 365, reconciliation, and Xero invoice sync (billing_sync.py)."""

import json
import uuid
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from conftest import enroll
from test_documentation_vault import stepup
from fenrir_cloud import billing_sync
from fenrir_cloud.db import session_factory
from fenrir_cloud.models import AccountingConnection, Invoice, M365Connection

SNAPSHOT = {"licenses": [{"skuPartNumber": "O365_BUSINESS_PREMIUM", "consumedUnits": 12},
                         {"skuPartNumber": "EXCHANGESTANDARD", "consumedUnits": 3}],
            "users": [{"userPrincipalName": f"u{i}@acme.test", "accountEnabled": i != 0, "assignedLicenses": [{"skuId": "x"}]}
                      for i in range(5)]}


def add_m365(tenant_id):
    with session_factory()() as db:
        db.add(M365Connection(tenant_id=tenant_id, name="Acme", directory_id=str(uuid.uuid4()), client_id=str(uuid.uuid4()),
                              credentials_envelope={}, snapshot=SNAPSHOT))
        db.commit()


def test_m365_licence_counts_bill_and_reconcile(client, admin, tenant):
    enroll(client, admin, tenant, hostname="ACME-1", serial="B1")
    add_m365(tenant["id"])
    contract = client.post("/api/console/billing/contracts", headers=admin, json={
        "accountTenantId": tenant["id"], "name": "Acme managed", "pricePerDevice": 10,
        "additions": [{"product": "Microsoft 365 Business Premium", "unitPrice": 18, "autoCount": "m365:O365_BUSINESS_PREMIUM"},
                      {"product": "Security awareness per user", "unitPrice": 2, "autoCount": "m365-users"}]}).json()
    invoice = next(i for i in client.post("/api/console/billing/invoices/generate", json={"period": "2026-10"}, headers=admin).json()["created"]
                   if i["contractId"] == contract["id"])
    lines = {l["description"]: l["quantity"] for l in invoice["lines"]}
    assert lines["Microsoft 365 Business Premium"] == 12 and lines["Security awareness per user"] == 4

    # The customer grows: two more managed devices and a new SKU assigned since invoicing.
    enroll(client, admin, tenant, hostname="ACME-2", serial="B2")
    enroll(client, admin, tenant, hostname="ACME-3", serial="B3")
    report = client.get("/api/console/billing/reconciliation", params={"period": "2026-10"}, headers=admin).json()
    row = next(r for r in report if r["contractId"] == contract["id"])
    devices = next(i for i in row["items"] if i["item"] == "Managed devices")
    assert devices["billed"] == 1 and devices["actual"] == 3 and devices["revenueGap"] == 20
    assert row["unbilledM365"] == [{"sku": "EXCHANGESTANDARD", "assigned": 3}] and row["drift"]


class FakeXero:
    def __init__(self):
        self.invoices, self.refresh_tokens, self.requests = {}, [], []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "identity.xero.com":
            form = parse_qs(request.content.decode())
            assert request.headers["authorization"].startswith("Basic ")
            if form["grant_type"] == ["authorization_code"]:
                return httpx.Response(200, json={"access_token": "at-1", "refresh_token": "rt-1"})
            self.refresh_tokens.append(form["refresh_token"][0])
            return httpx.Response(200, json={"access_token": "at-2", "refresh_token": f"rt-{len(self.refresh_tokens) + 1}"})
        if request.url.path == "/connections":
            return httpx.Response(200, json=[{"tenantId": "xero-org-1", "tenantName": "Palmertech Ltd", "tenantType": "ORGANISATION"}])
        assert request.headers["xero-tenant-id"] == "xero-org-1"
        if request.method == "POST":
            body = json.loads(request.content)["Invoices"][0]
            invoice_id = body.get("InvoiceID") or str(uuid.uuid4())
            self.invoices[invoice_id] = {**body, "InvoiceID": invoice_id, "Status": "DRAFT"}
            return httpx.Response(200, json={"Invoices": [self.invoices[invoice_id]]})
        ids = request.url.params["IDs"].split(",")
        return httpx.Response(200, json={"Invoices": [self.invoices[i] for i in ids if i in self.invoices]})


@pytest.fixture
def xero(monkeypatch):
    fake = FakeXero()
    monkeypatch.setattr(billing_sync, "http_client", lambda: httpx.Client(transport=httpx.MockTransport(fake)))
    return fake


def test_xero_connect_push_and_pull(client, admin, tenant, xero):
    proof = stepup(client, admin)
    configured = client.put("/api/console/billing/accounting", headers=proof, json={"clientId": "xero-client", "clientSecret": "xero-secret"})
    assert configured.status_code == 200, configured.text
    state = parse_qs(urlparse(configured.json()["authorizeUrl"]).query)["state"][0]
    assert client.get("/api/billing/xero/callback", params={"state": "forged", "code": "c"}, follow_redirects=False).headers["location"] \
        == "/billing?xero=failed"
    done = client.get("/api/billing/xero/callback", params={"state": state, "code": "auth-code"}, follow_redirects=False)
    assert done.headers["location"] == "/billing?xero=connected"
    assert client.get("/api/console/billing/accounting", headers=admin).json()["organisation"] == "Palmertech Ltd"
    # The state is single-use.
    assert client.get("/api/billing/xero/callback", params={"state": state, "code": "again"}, follow_redirects=False).headers["location"] \
        == "/billing?xero=failed"

    enroll(client, admin, tenant, hostname="ACME-X", serial="X1")
    client.post("/api/console/billing/contracts", headers=admin, json={"accountTenantId": tenant["id"], "name": "Acme", "pricePerDevice": 10})
    invoice = client.post("/api/console/billing/invoices/generate", json={"period": "2026-09"}, headers=admin).json()["created"][0]
    assert client.post("/api/console/billing/accounting/push", json={}, headers=admin).json() == []  # drafts are not pushed by default
    client.patch(f"/api/console/billing/invoices/{invoice['id']}", json={"status": "Sent"}, headers=admin)
    pushed = client.post("/api/console/billing/accounting/push", json={}, headers=admin).json()
    assert pushed[0]["status"] == "pushed"
    sent = next(iter(xero.invoices.values()))
    assert sent["Type"] == "ACCREC" and sent["Contact"]["Name"] == "Acme Dental" and sent["InvoiceNumber"] == invoice["number"]
    assert sent["LineItems"][0]["Quantity"] == 1 and sent["LineItems"][0]["UnitAmount"] == 10

    sent["Status"] = "PAID"
    assert client.post("/api/console/billing/accounting/pull", headers=admin).json() == {"updated": 1}
    with session_factory()() as db:
        assert db.get(Invoice, invoice["id"]).status == "Paid"
        row = db.query(AccountingConnection).one()
        assert billing_sync._secrets_of(row)["refreshToken"] == f"rt-{len(xero.refresh_tokens) + 1}"  # rotated tokens kept
    # A paid invoice is never pushed again.
    again = client.post("/api/console/billing/accounting/push", json={"invoiceIds": [invoice["id"]]}, headers=admin).json()
    assert again[0]["status"] == "skipped"
