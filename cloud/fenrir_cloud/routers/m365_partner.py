"""Microsoft partner (GDAP), multi-tenant identity standards and Entra ID reconciliation."""

from __future__ import annotations

from uuid import UUID

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, crypto, entra_reconcile, m365_partner as partner_mod, m365_standards as standards
from ..db import get_db
from ..deps import Principal, current_principal, require_reauth
from ..models import M365Connection, M365Partner, M365StandardRun, Tenant

router = APIRouter(prefix="/api/console/m365", tags=["Microsoft partner and standards"])


def _msp(principal: Principal) -> str:
    """Partner connections belong to the MSP: only MSP staff with Microsoft administration manage them."""
    principal.require("m365_admin")
    principal.require("manage_tenants")
    return principal.user.tenant_id


def _partner(db: Session, principal: Principal) -> M365Partner:
    row = db.execute(select(M365Partner).where(M365Partner.tenant_id == _msp(principal))).scalars().first()
    if row is None:
        raise HTTPException(404, "No partner connection")
    return row


def _provider(call):
    try:
        return call()
    except partner_mod.PartnerError as exc:
        raise HTTPException(502, str(exc)) from exc
    except (httpx.HTTPError, crypto.VaultError, ValueError) as exc:
        raise HTTPException(502, "Microsoft request failed: " + str(exc)[:200]) from exc


# --------------------------------------------------------------------------- partner connection


@router.get("/partner")
def get_partner(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = db.execute(select(M365Partner).where(M365Partner.tenant_id == _msp(principal))).scalars().first()
    return {"partner": partner_mod.view(row) if row else None,
            "recommendedRoles": [{"id": k, "name": v} for k, v in partner_mod.RECOMMENDED_ROLES.items()]}


@router.post("/partner")
def create_partner(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    msp = _msp(principal)
    require_reauth(request, principal)
    if db.execute(select(M365Partner).where(M365Partner.tenant_id == msp)).scalars().first():
        raise HTTPException(409, "A partner connection exists; delete it first")
    secret = str(body.get("clientSecret") or "")  # only for apps with public client flows turned off
    try:
        row = partner_mod.create(db, msp, str(UUID(str(body.get("directoryId")))), str(UUID(str(body.get("clientId")))), secret, principal.actor)
    except ValueError as exc:
        raise HTTPException(422, "directoryId and clientId must be GUIDs") from exc
    audit.record(db, principal.actor, "m365.partner.created", row.partner_directory_id, msp)
    db.commit()
    return partner_mod.view(row)


@router.delete("/partner")
def delete_partner(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _partner(db, principal)
    require_reauth(request, principal)
    audit.record(db, principal.actor, "m365.partner.deleted", row.partner_directory_id, row.tenant_id)
    db.delete(row)
    db.commit()
    return {"deleted": True}


@router.post("/partner/signin")
def partner_signin(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Start a device-code sign-in as a partner admin. The device code itself stays on the server."""
    row = _partner(db, principal)
    code = _provider(lambda: partner_mod.start_signin(row))
    partner_mod._store_secrets(row, {**partner_mod._secrets(row), "pendingDeviceCode": code.pop("deviceCode")})
    db.commit()
    return code


@router.post("/partner/signin/poll")
def partner_signin_poll(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _partner(db, principal)
    pending = partner_mod._secrets(row).get("pendingDeviceCode")
    if not pending:
        raise HTTPException(409, "Start a sign-in first")
    status = _provider(lambda: partner_mod.complete_signin(row, pending))
    if status == "ok":
        partner_mod._store_secrets(row, {k: v for k, v in partner_mod._secrets(row).items() if k != "pendingDeviceCode"})
        audit.record(db, principal.actor, "m365.partner.signed_in", row.signed_in_as, row.tenant_id)
    db.commit()
    return {"status": status, "partner": partner_mod.view(row)}


@router.get("/partner/relationships")
def relationships(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _partner(db, principal)
    result = _provider(lambda: partner_mod.list_relationships(row))
    db.commit()
    return result


@router.post("/partner/relationships")
def create_relationship(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _partner(db, principal)
    require_reauth(request, principal)
    name = str(body.get("displayName") or "").strip()
    if not name:
        raise HTTPException(422, "displayName is required")
    rel = _provider(lambda: partner_mod.create_relationship(row, name, body.get("customerTenantId") or None,
                                                            int(body.get("durationDays") or 730), bool(body.get("autoExtend", True))))
    audit.record(db, principal.actor, "m365.gdap.relationship_created", rel["id"], row.tenant_id, displayName=name,
                 roles=len(partner_mod.RECOMMENDED_ROLES))
    db.commit()
    return rel


@router.post("/partner/role-groups")
def role_groups(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _partner(db, principal)
    groups = _provider(lambda: partner_mod.ensure_role_groups(row))
    audit.record(db, principal.actor, "m365.gdap.role_groups", row.partner_directory_id, row.tenant_id, groups=len(groups))
    db.commit()
    return partner_mod.view(row)


@router.post("/partner/relationships/{relationship_id}/assign")
def assign_relationship(relationship_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _partner(db, principal)
    result = _provider(lambda: partner_mod.assign_access(row, relationship_id))
    audit.record(db, principal.actor, "m365.gdap.access_assigned", relationship_id, row.tenant_id, **result)
    db.commit()
    return result


@router.get("/partner/customers")
def gdap_customers(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    row = _partner(db, principal)
    customers = _provider(lambda: partner_mod.list_customers(row))
    mapped = {c.directory_id: c for c in db.execute(select(M365Connection).where(M365Connection.auth_mode == "gdap",
                                                                                 M365Connection.tenant_id.in_(principal.tenant_ids))).scalars()}
    db.commit()
    return [{**c, "connectionId": mapped[c["tenantId"]].id if c["tenantId"] in mapped else None,
             "fenrirTenantId": mapped[c["tenantId"]].tenant_id if c["tenantId"] in mapped else None} for c in customers]


@router.post("/partner/customers/{directory_id}/onboard")
def onboard(directory_id: str, request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal),
            db: Session = Depends(get_db)):
    row = _partner(db, principal)
    tenant_id = str(body.get("tenantId") or "")
    principal.check_tenant(tenant_id)
    require_reauth(request, principal)
    connection = _provider(lambda: partner_mod.onboard_customer(db, row, directory_id, tenant_id, str(body.get("name") or ""), principal.actor))
    db.commit()
    return {"connectionId": connection.id, "tenantId": tenant_id, "directoryId": connection.directory_id}


# --------------------------------------------------------------------------- standards


def _tenant(db: Session, principal: Principal, tenant_id: str) -> Tenant:
    principal.check_tenant(tenant_id)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(404, "Not found")
    return tenant


@router.get("/standards")
def list_standards(tenant_id: str | None = None, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    catalogue = [{"id": k, "title": v["title"], "kind": v["kind"], "permissions": v["permissions"]} for k, v in standards.STANDARDS.items()]
    out = {"standards": catalogue, "modes": list(standards.MODES)}
    if tenant_id:
        tenant = _tenant(db, principal, tenant_id)
        out["assignments"] = standards.assignments(tenant)
        runs = db.execute(select(M365StandardRun).where(M365StandardRun.tenant_id == tenant.id).order_by(M365StandardRun.at.desc()).limit(200)).scalars()
        latest: dict = {}
        for run in runs:
            latest.setdefault(f"{run.standard}:{run.connection_id}:{run.action}", {
                "standard": run.standard, "connectionId": run.connection_id, "action": run.action, "status": run.status,
                "details": run.details, "actor": run.actor, "at": run.at.isoformat() + "Z"})
        out["latest"] = list(latest.values())
    return out


@router.put("/standards/assignments")
def assign_standard(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("m365_admin")
    tenant = _tenant(db, principal, str(body.get("tenantId") or ""))
    standard, mode = str(body.get("standard") or ""), str(body.get("mode") or "")
    if standard not in standards.STANDARDS:
        raise HTTPException(422, "Unknown standard")
    current = standards.assignments(tenant)
    if mode in ("", "off"):
        current.pop(standard, None)
    elif mode not in standards.MODES:
        raise HTTPException(422, f"mode must be one of {', '.join(standards.MODES)} or off")
    else:
        options = body.get("options") or {}
        try:
            standards.desired(standard, options)  # validates break-glass IDs and options
        except (ValueError, standards.StandardError) as exc:
            raise HTTPException(422, f"Invalid options: {exc}") from exc
        current[standard] = {"mode": mode, "options": options}
    tenant.settings = {**(tenant.settings or {}), "m365Standards": current}
    audit.record(db, principal.actor, "m365.standard.assigned", standard, tenant.id, mode=mode or "off")
    db.commit()
    return standards.assignments(tenant)


@router.post("/standards/evaluate")
def evaluate_standards(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    tenant = _tenant(db, principal, str(body.get("tenantId") or ""))
    results = standards.run_for_tenant(db, tenant, principal.actor)
    db.commit()
    return results


@router.post("/standards/deploy")
def deploy_standard(request: Request, body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    """Deploy one standard to many customers at once, with a result per Microsoft tenant."""
    principal.require("m365_admin")
    require_reauth(request, principal)
    standard = str(body.get("standard") or "")
    if standard not in standards.STANDARDS:
        raise HTTPException(422, "Unknown standard")
    options = body.get("options") or {}
    try:
        standards.desired(standard, options)
    except (ValueError, standards.StandardError) as exc:
        raise HTTPException(422, f"Invalid options: {exc}") from exc
    tenant_ids = [str(t) for t in body.get("tenantIds") or []][:200]
    if not tenant_ids:
        raise HTTPException(422, "Choose at least one customer")
    results = []
    for tenant_id in tenant_ids:
        if tenant_id not in principal.tenant_ids:
            results.append({"tenantId": tenant_id, "status": "skipped", "error": "not found"})
            continue
        connections = db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant_id)).scalars().all()
        if not connections:
            results.append({"tenantId": tenant_id, "status": "skipped", "error": "no Microsoft 365 connection"})
        for connection in connections:
            try:
                outcome = standards.deploy(connection, standard, options)
                standards.record(db, connection, standard, "deploy", "deployed", outcome, principal.actor)
                results.append({"tenantId": tenant_id, "connectionId": connection.id, "status": "deployed", **outcome})
            except (standards.StandardError, httpx.HTTPError, ValueError, crypto.VaultError) as exc:
                standards.record(db, connection, standard, "deploy", "failed", {"error": str(exc)[:300]}, principal.actor)
                results.append({"tenantId": tenant_id, "connectionId": connection.id, "status": "failed", "error": str(exc)[:300]})
            db.commit()  # each tenant's outcome is kept even if a later one fails
    return {"standard": standard, "results": results}


# --------------------------------------------------------------------------- Entra ID reconciliation


@router.get("/reconcile")
def reconcile(tenant_id: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("read")
    return entra_reconcile.report(db, _tenant(db, principal, tenant_id))


@router.post("/reconcile/apply")
def reconcile_apply(body: dict = Body(...), principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    principal.require("crm")
    tenant = _tenant(db, principal, str(body.get("tenantId") or ""))
    result = entra_reconcile.apply(db, tenant, principal.actor, [str(x) for x in body.get("addContacts") or []],
                                   [str(x) for x in body.get("retireContacts") or []])
    db.commit()
    return result
