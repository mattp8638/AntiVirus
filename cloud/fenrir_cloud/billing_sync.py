"""Billing kept in step with what is actually managed, and invoices kept in step with the accounting system.

**Usage-based lines.** A contract addition's ``autoCount`` counts live data when invoices are drafted:

- ``devices`` / ``devices:<platform>`` / ``devices:server`` (managed, approved devices; existing behaviour);
- ``m365:<SKU part number>`` (e.g. ``m365:O365_BUSINESS_PREMIUM``): licences of that SKU assigned in the customer's
  synced Microsoft 365 tenants;
- ``m365-users``: enabled member accounts holding any licence.

**Reconciliation.** For a period, compares what each contract's invoice billed with what is under management now:
devices billed vs managed, each counted addition, and Microsoft 365 licences assigned but billed by no addition.

**Accounting sync (Xero).** Invoices are pushed as drafts (``ACCREC``) to the MSP's Xero organisation with the
customer as contact, and payment status is pulled back (PAID -> Paid, VOIDED/DELETED -> Void). The OAuth refresh
token is stored encrypted and rotated on every use. Draft invoices are never pushed automatically.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets as _secrets
from datetime import timedelta
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, crypto
from .config import get_settings
from .models import AccountingConnection, Contract, Device, Invoice, M365Connection, Tenant, utcnow

XERO_AUTHORIZE = "https://login.xero.com/identity/connect/authorize"
XERO_TOKEN = "https://identity.xero.com/connect/token"
XERO_CONNECTIONS = "https://api.xero.com/connections"
XERO_API = "https://api.xero.com/api.xro/2.0"
DEFAULT_SCOPES = "offline_access accounting.transactions accounting.contacts"
STATUS_FROM_XERO = {"PAID": "Paid", "VOIDED": "Void", "DELETED": "Void", "AUTHORISED": "Sent", "SUBMITTED": "Sent", "DRAFT": "Draft"}


class AccountingError(Exception):
    pass


def http_client() -> httpx.Client:
    return httpx.Client(timeout=30, follow_redirects=False)


# --------------------------------------------------------------------------- usage counts


def _licence_rows(db: Session, tenant_id: str) -> list[dict]:
    rows = []
    for connection in db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant_id)).scalars():
        rows.extend(sku for sku in (connection.snapshot or {}).get("licenses") or [] if isinstance(sku, dict))
    return rows


def m365_assigned(db: Session, tenant_id: str) -> dict[str, int]:
    """SKU part number -> licences assigned across the customer's synced tenants."""
    counts: dict[str, int] = {}
    for sku in _licence_rows(db, tenant_id):
        name = str(sku.get("skuPartNumber") or sku.get("skuId") or "").upper()
        if name:
            counts[name] = counts.get(name, 0) + int(sku.get("consumedUnits") or 0)
    return counts


def m365_licensed_users(db: Session, tenant_id: str) -> int:
    count = 0
    for connection in db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant_id)).scalars():
        for user in (connection.snapshot or {}).get("users") or []:
            if user.get("accountEnabled") is not False and user.get("assignedLicenses") and user.get("userType", "Member") == "Member":
                count += 1
    return count


def auto_quantity(db: Session, contract: Contract, devices: list[Device], auto: str) -> float | None:
    """The live quantity for an addition's autoCount, or None when the rule is not recognised."""
    if auto.startswith("devices"):
        platform = auto.partition(":")[2]
        return float(len([d for d in devices if not platform or d.platform == platform or
                          (platform == "server" and "server" in (d.os_version or "").lower())]))
    if auto.startswith("m365:"):
        return float(m365_assigned(db, contract.account_tenant_id).get(auto.partition(":")[2].upper(), 0))
    if auto == "m365-users":
        return float(m365_licensed_users(db, contract.account_tenant_id))
    return None


def reconciliation(db: Session, owner_ids: list[str], period: str) -> list[dict]:
    out = []
    for contract in db.execute(select(Contract).where(Contract.tenant_id.in_(owner_ids), Contract.active.is_(True))).scalars():
        devices = db.execute(select(Device).where(Device.tenant_id == contract.account_tenant_id, Device.approved.is_(True))).scalars().all()
        invoice = db.execute(select(Invoice).where(Invoice.contract_id == contract.id, Invoice.period == period)).scalar_one_or_none()
        billed = {line.get("description"): float(line.get("quantity") or 0) for line in (invoice.lines if invoice else [])}
        items = []
        if contract.price_per_device:
            description = f"Protected endpoints ({contract.plan})"
            items.append({"item": "Managed devices", "billed": billed.get(description, 0.0), "actual": float(len(devices)),
                          "unitPrice": contract.price_per_device})
        covered_skus = set()
        for addition in contract.additions or []:
            auto = str(addition.get("autoCount") or "")
            if auto.startswith("m365:"):
                covered_skus.add(auto.partition(":")[2].upper())
            actual = auto_quantity(db, contract, devices, auto) if auto else float(addition.get("quantity") or 0)
            items.append({"item": str(addition.get("product") or "Addition"), "billed": billed.get(str(addition.get("product") or "Addition"), 0.0),
                          "actual": actual if actual is not None else float(addition.get("quantity") or 0),
                          "unitPrice": float(addition.get("unitPrice") or 0), "autoCount": auto})
        for item in items:
            item["difference"] = round(item["actual"] - item["billed"], 2)
            item["revenueGap"] = round(item["difference"] * item["unitPrice"], 2)
        unbilled = [{"sku": sku, "assigned": n} for sku, n in sorted(m365_assigned(db, contract.account_tenant_id).items())
                    if n and sku not in covered_skus]
        tenant = db.get(Tenant, contract.account_tenant_id)
        out.append({"contractId": contract.id, "contract": contract.name, "customer": tenant.name if tenant else "",
                    "accountTenantId": contract.account_tenant_id, "invoice": invoice.number if invoice else None, "items": items,
                    "unbilledM365": unbilled, "drift": any(i["difference"] for i in items) or bool(unbilled),
                    "revenueGap": round(sum(i["revenueGap"] for i in items), 2)})
    return out


# --------------------------------------------------------------------------- Xero


def _aad(row: AccountingConnection) -> str:
    return f"accounting:{row.tenant_id}:{row.id}"


crypto.register_encrypted(AccountingConnection, "credentials_envelope", _aad)


def _secrets_of(row: AccountingConnection) -> dict:
    return json.loads(crypto.decrypt(row.credentials_envelope, _aad(row))) if row.credentials_envelope else {}


def _store(row: AccountingConnection, values: dict) -> None:
    row.credentials_envelope = crypto.encrypt(json.dumps(values), _aad(row))


def redirect_uri() -> str:
    return get_settings().public_base_url.rstrip("/") + "/api/billing/xero/callback"


def authorize_url(row: AccountingConnection) -> str:
    state = _secrets.token_urlsafe(24)
    row.pending_state = hashlib.sha256(state.encode()).hexdigest()
    row.pending_until = utcnow() + timedelta(minutes=15)
    return XERO_AUTHORIZE + "?" + urlencode({"response_type": "code", "client_id": row.client_id, "redirect_uri": redirect_uri(),
                                             "scope": row.scopes or DEFAULT_SCOPES, "state": state})


def _basic(row: AccountingConnection) -> str:
    raw = f"{row.client_id}:{_secrets_of(row).get('clientSecret', '')}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def complete_authorization(db: Session, state: str, code: str) -> AccountingConnection:
    digest = hashlib.sha256(state.encode()).hexdigest()
    row = db.execute(select(AccountingConnection).where(AccountingConnection.pending_state == digest)).scalar_one_or_none()
    if row is None or row.pending_until is None or row.pending_until < utcnow():
        raise AccountingError("This authorisation link has expired; start again from Billing")
    with http_client() as client:
        response = client.post(XERO_TOKEN, headers={"Authorization": _basic(row)},
                               data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri()})
        if response.status_code != 200:
            raise AccountingError(f"Xero refused the authorisation (HTTP {response.status_code})")
        tokens = response.json()
        connections = client.get(XERO_CONNECTIONS, headers={"Authorization": "Bearer " + tokens["access_token"]})
        connections.raise_for_status()
    organisations = [c for c in connections.json() if c.get("tenantType", "ORGANISATION") == "ORGANISATION"]
    if not organisations:
        raise AccountingError("No Xero organisation was authorised")
    _store(row, {**_secrets_of(row), "refreshToken": tokens["refresh_token"]})
    row.external_tenant_id = organisations[0]["tenantId"]
    row.external_name = str(organisations[0].get("tenantName") or "")[:200]
    row.status, row.last_error, row.pending_state, row.pending_until = "connected", "", None, None
    return row


def _access_token(row: AccountingConnection, client: httpx.Client) -> str:
    values = _secrets_of(row)
    if not values.get("refreshToken"):
        raise AccountingError("Connect Xero first")
    response = client.post(XERO_TOKEN, headers={"Authorization": _basic(row)},
                           data={"grant_type": "refresh_token", "refresh_token": values["refreshToken"]})
    if response.status_code != 200:
        row.status, row.last_error = "error", f"Xero refused the refresh token (HTTP {response.status_code}); reconnect"
        raise AccountingError(row.last_error)
    tokens = response.json()
    _store(row, {**values, "refreshToken": tokens.get("refresh_token") or values["refreshToken"]})  # Xero rotates it
    return tokens["access_token"]


def _headers(row: AccountingConnection, token: str) -> dict:
    return {"Authorization": "Bearer " + token, "xero-tenant-id": row.external_tenant_id or "", "Accept": "application/json"}


def xero_invoice(db: Session, row: AccountingConnection, invoice: Invoice) -> dict:
    customer = db.get(Tenant, invoice.account_tenant_id)
    created = invoice.created_at.date().isoformat() if invoice.created_at else utcnow().date().isoformat()
    body = {"Type": "ACCREC", "Contact": {"Name": customer.name if customer else invoice.account_tenant_id},
            "Date": created, "DueDate": invoice.due_date or created, "InvoiceNumber": invoice.number, "Reference": invoice.period,
            "CurrencyCode": invoice.currency, "Status": "DRAFT", "LineAmountTypes": "Exclusive",
            "LineItems": [{"Description": str(line.get("description") or "")[:4000], "Quantity": line.get("quantity") or 0,
                           "UnitAmount": line.get("unitPrice") or 0, "AccountCode": row.account_code or "200"}
                          for line in invoice.lines or []]}
    if invoice.external_id:
        body["InvoiceID"] = invoice.external_id  # update in place rather than duplicating
    return body


def push_invoices(db: Session, row: AccountingConnection, invoices: list[Invoice], actor: str) -> list[dict]:
    if row.status != "connected":
        raise AccountingError("Connect Xero first")
    results = []
    with http_client() as client:
        token = _access_token(row, client)
        for invoice in invoices:
            if invoice.external_status in ("PAID", "VOIDED", "DELETED"):
                results.append({"invoice": invoice.number, "status": "skipped", "reason": f"already {invoice.external_status} in Xero"})
                continue
            response = client.post(XERO_API + "/Invoices", headers=_headers(row, token), json={"Invoices": [xero_invoice(db, row, invoice)]})
            invoice.external_synced_at = utcnow()
            if response.status_code != 200:
                invoice.external_error = f"Xero rejected the invoice (HTTP {response.status_code})"
                results.append({"invoice": invoice.number, "status": "failed", "reason": invoice.external_error})
                continue
            created = (response.json().get("Invoices") or [{}])[0]
            invoice.external_id, invoice.external_status, invoice.external_error = created.get("InvoiceID"), created.get("Status"), ""
            results.append({"invoice": invoice.number, "status": "pushed", "externalId": invoice.external_id})
    audit.record(db, actor, "billing.xero.pushed", f"{len(invoices)} invoices", row.tenant_id,
                 pushed=sum(1 for r in results if r["status"] == "pushed"))
    return results


def pull_statuses(db: Session, row: AccountingConnection) -> int:
    """Copy Xero payment state back onto pushed invoices."""
    invoices = db.execute(select(Invoice).where(Invoice.tenant_id == row.tenant_id, Invoice.external_id.is_not(None))).scalars().all()
    if not invoices:
        return 0
    changed = 0
    with http_client() as client:
        token = _access_token(row, client)
        by_id = {i.external_id: i for i in invoices}
        ids = list(by_id)
        for start in range(0, len(ids), 50):
            response = client.get(XERO_API + "/Invoices", headers=_headers(row, token), params={"IDs": ",".join(ids[start:start + 50])})
            if response.status_code != 200:
                raise AccountingError(f"Xero refused the status check (HTTP {response.status_code})")
            for remote in response.json().get("Invoices") or []:
                invoice = by_id.get(remote.get("InvoiceID"))
                if invoice is None:
                    continue
                status = STATUS_FROM_XERO.get(str(remote.get("Status")))
                invoice.external_status = remote.get("Status")
                invoice.external_synced_at = utcnow()
                if status and status != invoice.status and status != "Draft":
                    invoice.status = status
                    changed += 1
    row.last_sync_at = utcnow()
    return changed


def tick(db: Session) -> None:
    for row in db.execute(select(AccountingConnection).where(AccountingConnection.status == "connected")).scalars():
        if row.last_sync_at and utcnow() - row.last_sync_at < timedelta(hours=6):
            continue
        try:
            pull_statuses(db, row)
            db.commit()
        except (AccountingError, httpx.HTTPError, crypto.VaultError):
            db.commit()  # keep the recorded error


def view(row: AccountingConnection) -> dict:
    return {"id": row.id, "provider": row.provider, "clientId": row.client_id, "status": row.status, "organisation": row.external_name,
            "accountCode": row.account_code, "scopes": row.scopes or DEFAULT_SCOPES, "lastError": row.last_error,
            "lastSyncAt": row.last_sync_at.isoformat() + "Z" if row.last_sync_at else None, "redirectUri": redirect_uri()}
