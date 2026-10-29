"""Microsoft 365 identity and device standards across customers: evaluate, alert on drift, deploy.

Each standard knows how to read the tenant's current state and how to bring it into line:

``mfa.all-users``        Conditional Access "Require MFA for all users" (break-glass accounts excluded), or
                         Microsoft security defaults, which also enforce MFA.
``mfa.admins``           Conditional Access requiring MFA for the privileged directory roles.
``legacy-auth.block``    Conditional Access blocking legacy authentication (EAS and other basic-auth clients).
``intune.windows-compliance``  An Intune Windows compliance policy: BitLocker, Secure Boot, Defender, firewall,
                         code integrity, TPM; assigned to all devices.

Deployment follows Microsoft's own advice: Conditional Access policies are created **report-only** unless
``enforce`` is chosen, so their impact can be reviewed in sign-in logs first. A tenant with security defaults
on cannot have Conditional Access policies; that is reported rather than switched off silently. Policies
Fenrir creates are named ``Fenrir: ...`` and matched by name, so redeploying updates rather than duplicates.

Per-customer assignment lives in ``Tenant.settings["m365Standards"]`` as ``{standard: {"mode": "report" |
"alert" | "remediate", "options": {...}}}``. The daily check records every evaluation; ``alert`` opens a ticket
on drift; ``remediate`` redeploys (never escalating report-only to enforced on its own).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, m365, services
from .models import M365Connection, M365StandardRun, Tenant, utcnow

log = logging.getLogger("fenrir.m365.standards")

# Privileged roles for "MFA for admins" (built-in role template IDs).
ADMIN_ROLES = [
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "3a2c62db-5318-420d-8d74-23affee5d9d5",  # Intune Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
]

STANDARDS: dict[str, dict] = {
    "mfa.all-users": {"title": "Require MFA for all users", "kind": "ca",
                      "permissions": ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All"]},
    "mfa.admins": {"title": "Require MFA for administrators", "kind": "ca",
                   "permissions": ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"]},
    "legacy-auth.block": {"title": "Block legacy authentication", "kind": "ca",
                          "permissions": ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"]},
    "intune.windows-compliance": {"title": "Windows device compliance baseline", "kind": "intune",
                                  "permissions": ["DeviceManagementConfiguration.ReadWrite.All"]},
}
MODES = ("report", "alert", "remediate")
CA_PATH = "/identity/conditionalAccess/policies"
COMPLIANCE_PATH = "/deviceManagement/deviceCompliancePolicies"


class StandardError(Exception):
    pass


def http_client() -> httpx.Client:
    return httpx.Client(timeout=20, follow_redirects=False)


def display_name(standard: str) -> str:
    return "Fenrir: " + STANDARDS[standard]["title"]


def _excluded(options: dict) -> list[str]:
    out = []
    for value in options.get("excludeUserIds") or []:
        out.append(str(UUID(str(value))))
    return out


def desired(standard: str, options: dict) -> dict:
    """The Graph object Fenrir would create for a standard."""
    if standard == "intune.windows-compliance":
        return {"@odata.type": "#microsoft.graph.windows10CompliancePolicy", "displayName": display_name(standard),
                "description": "Managed by Fenrir. BitLocker, Secure Boot, Defender, firewall, code integrity and TPM required.",
                "bitLockerEnabled": True, "secureBootEnabled": True, "codeIntegrityEnabled": True, "tpmRequired": True,
                "defenderEnabled": True, "antivirusRequired": True, "antiSpywareRequired": True, "activeFirewallRequired": True,
                "rtpEnabled": True, "osMinimumVersion": str(options.get("osMinimumVersion") or "10.0.19045"),
                "scheduledActionsForRule": [{"ruleName": "PasswordRequired", "scheduledActionConfigurations": [
                    {"actionType": "block", "gracePeriodHours": int(options.get("gracePeriodHours") or 24),
                     "notificationTemplateId": "", "notificationMessageCCList": []}]}]}
    state = "enabled" if options.get("enforce") else "enabledForReportingButNotEnforced"
    excluded = _excluded(options)
    if standard == "mfa.all-users":
        conditions = {"users": {"includeUsers": ["All"], "excludeUsers": excluded}, "applications": {"includeApplications": ["All"]},
                      "clientAppTypes": ["all"]}
        grant = {"operator": "OR", "builtInControls": ["mfa"]}
    elif standard == "mfa.admins":
        conditions = {"users": {"includeRoles": ADMIN_ROLES, "excludeUsers": excluded}, "applications": {"includeApplications": ["All"]},
                      "clientAppTypes": ["all"]}
        grant = {"operator": "OR", "builtInControls": ["mfa"]}
    elif standard == "legacy-auth.block":
        conditions = {"users": {"includeUsers": ["All"], "excludeUsers": excluded}, "applications": {"includeApplications": ["All"]},
                      "clientAppTypes": ["exchangeActiveSync", "other"]}
        grant = {"operator": "OR", "builtInControls": ["block"]}
    else:
        raise StandardError(f"Unknown standard '{standard}'")
    return {"displayName": display_name(standard), "state": state, "conditions": conditions, "grantControls": grant}


def _graph(client: httpx.Client, token: str, method: str, path: str, body: dict | None = None) -> dict:
    response = client.request(method, m365.GRAPH + path, headers={"Authorization": "Bearer " + token},
                              **({"json": body} if body is not None else {}))
    if response.status_code in (401, 403):
        raise StandardError("Microsoft denied access: grant the standard's permissions (and, for GDAP, the matching role)")
    if response.status_code >= 400:
        raise StandardError(f"Microsoft rejected {method} {path.split('?')[0]} (HTTP {response.status_code})")
    return response.json() if response.content else {}


def _security_defaults(client, token) -> bool:
    return bool(_graph(client, token, "GET", "/policies/identitySecurityDefaultsEnforcementPolicy").get("isEnabled"))


def _find(client, token, path: str, name: str) -> dict | None:
    rows = m365.collect(client, m365.GRAPH + path, token)
    return next((r for r in rows if r.get("displayName") == name), None)


def _ca_covers(policy: dict, want: dict) -> bool:
    """Does an existing policy enforce what we want (any state but disabled counts as present)?"""
    controls = set(((policy.get("grantControls") or {}).get("builtInControls")) or [])
    wanted = set(want["grantControls"]["builtInControls"])
    apps = ((policy.get("conditions") or {}).get("applications") or {}).get("includeApplications") or []
    return policy.get("state") != "disabled" and wanted <= controls and "All" in apps


def evaluate(connection: M365Connection, standard: str, options: dict | None = None) -> dict:
    """{"status": compliant | drifted, "detail": str, "state": ...} from the tenant's live configuration."""
    options = options or {}
    if standard not in STANDARDS:
        raise StandardError(f"Unknown standard '{standard}'")
    want = desired(standard, options)
    with http_client() as client:
        token = m365.access_token(client, connection)
        if STANDARDS[standard]["kind"] == "intune":
            existing = _find(client, token, COMPLIANCE_PATH, want["displayName"])
            if existing is None:
                return {"status": "drifted", "detail": "No Fenrir Windows compliance policy exists"}
            weaker = [k for k in ("bitLockerEnabled", "secureBootEnabled", "codeIntegrityEnabled", "tpmRequired", "defenderEnabled",
                                  "activeFirewallRequired") if existing.get(k) is not True]
            return {"status": "drifted" if weaker else "compliant", "detail": ("Requirements turned off: " + ", ".join(weaker)) if weaker
                    else "Compliance policy in place", "policyId": existing.get("id")}
        if _security_defaults(client, token):
            if standard in ("mfa.all-users", "mfa.admins", "legacy-auth.block"):
                return {"status": "compliant", "detail": "Microsoft security defaults are on (MFA required, legacy authentication blocked)",
                        "securityDefaults": True}
        policies = m365.collect(client, m365.GRAPH + CA_PATH, token)
        ours = next((p for p in policies if p.get("displayName") == want["displayName"]), None)
        matching = [p for p in policies if _ca_covers(p, want) and (standard != "legacy-auth.block" or set(
            ((p.get("conditions") or {}).get("clientAppTypes")) or []) >= {"exchangeActiveSync", "other"})]
        if standard == "mfa.admins":
            matching = [p for p in matching if (((p.get("conditions") or {}).get("users") or {}).get("includeRoles"))
                        or "All" in (((p.get("conditions") or {}).get("users") or {}).get("includeUsers") or [])]
        enforced = [p for p in matching if p.get("state") == "enabled"]
        if enforced:
            return {"status": "compliant", "detail": f"Enforced by '{enforced[0].get('displayName')}'", "policyId": enforced[0].get("id")}
        if matching:
            return {"status": "drifted", "detail": f"'{matching[0].get('displayName')}' is report-only: not yet enforced",
                    "policyId": matching[0].get("id"), "reportOnly": True}
        return {"status": "drifted", "detail": "No Conditional Access policy enforces this", "policyId": ours.get("id") if ours else None}


def deploy(connection: M365Connection, standard: str, options: dict | None = None) -> dict:
    """Create or update the Fenrir policy for a standard. Conditional Access is report-only unless enforce is set."""
    options = options or {}
    want = desired(standard, options)
    with http_client() as client:
        token = m365.access_token(client, connection)
        if STANDARDS[standard]["kind"] == "intune":
            existing = _find(client, token, COMPLIANCE_PATH, want["displayName"])
            if existing is None:
                created = _graph(client, token, "POST", COMPLIANCE_PATH, want)
                _graph(client, token, "POST", f"{COMPLIANCE_PATH}/{created['id']}/assign",
                       {"assignments": [{"target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}]})
                return {"action": "created", "policyId": created["id"], "assigned": "all devices"}
            body = {k: v for k, v in want.items() if k != "scheduledActionsForRule"}
            _graph(client, token, "PATCH", f"{COMPLIANCE_PATH}/{existing['id']}", body)
            return {"action": "updated", "policyId": existing["id"]}
        if _security_defaults(client, token):
            raise StandardError("Security defaults are on in this tenant. They already enforce MFA; Conditional Access policies "
                                "cannot be created until an administrator turns security defaults off.")
        existing = _find(client, token, CA_PATH, want["displayName"])
        if existing is None:
            created = _graph(client, token, "POST", CA_PATH, want)
            return {"action": "created", "policyId": created.get("id"), "state": want["state"]}
        _graph(client, token, "PATCH", f"{CA_PATH}/{existing['id']}", want)
        return {"action": "updated", "policyId": existing["id"], "state": want["state"]}


# --------------------------------------------------------------------------- per-customer assignment and the daily check


def assignments(tenant: Tenant) -> dict:
    return dict((tenant.settings or {}).get("m365Standards") or {})


def record(db: Session, connection: M365Connection, standard: str, action: str, status: str, details: dict, actor: str) -> M365StandardRun:
    run = M365StandardRun(tenant_id=connection.tenant_id, connection_id=connection.id, standard=standard, action=action,
                          status=status, details=details, actor=actor)
    db.add(run)
    audit.record(db, actor, f"m365.standard.{action}", f"{standard}@{connection.directory_id}", connection.tenant_id,
                 status=status, detail=str(details.get("detail") or details.get("action") or details.get("error") or "")[:200])
    return run


def run_for_tenant(db: Session, tenant: Tenant, actor: str = "system:m365-standards") -> list[dict]:
    results = []
    connections = db.execute(select(M365Connection).where(M365Connection.tenant_id == tenant.id)).scalars().all()
    for standard, assignment in assignments(tenant).items():
        if standard not in STANDARDS:
            continue
        mode, options = assignment.get("mode", "report"), assignment.get("options") or {}
        for connection in connections:
            try:
                outcome = evaluate(connection, standard, options)
            except (StandardError, httpx.HTTPError, ValueError) as exc:
                record(db, connection, standard, "evaluate", "unknown", {"error": str(exc)[:300]}, actor)
                results.append({"standard": standard, "connectionId": connection.id, "status": "unknown"})
                continue
            record(db, connection, standard, "evaluate", outcome["status"], outcome, actor)
            if outcome["status"] == "drifted" and mode == "alert":
                _alert(db, tenant, connection, standard, outcome)
            elif outcome["status"] == "drifted" and mode == "remediate" and not outcome.get("reportOnly"):
                try:
                    deployed = deploy(connection, standard, options)
                    record(db, connection, standard, "deploy", "deployed", deployed, actor)
                except (StandardError, httpx.HTTPError, ValueError) as exc:
                    record(db, connection, standard, "deploy", "failed", {"error": str(exc)[:300]}, actor)
            results.append({"standard": standard, "connectionId": connection.id, "status": outcome["status"]})
    return results


def _alert(db: Session, tenant: Tenant, connection: M365Connection, standard: str, outcome: dict) -> None:
    from . import psa
    from .models import Ticket

    subject = f"Microsoft 365 drift: {STANDARDS[standard]['title']} ({connection.tenant_name or connection.name})"
    existing = db.execute(select(Ticket).where(Ticket.account_tenant_id == tenant.id, Ticket.subject == subject)).scalars().all()
    if not any(not psa.is_closed(db, t) for t in existing):
        services.open_ticket(db, tenant.id, subject, outcome.get("detail", ""), priority="P3", source="m365-standards",
                             queue="Security Operations")


def tick(db: Session) -> None:
    """Daily: evaluate every assigned standard (called hourly; runs a customer once a day)."""
    for tenant in db.execute(select(Tenant)).scalars():
        if not assignments(tenant):
            continue
        last = db.execute(select(M365StandardRun.at).where(M365StandardRun.tenant_id == tenant.id, M365StandardRun.action == "evaluate")
                          .order_by(M365StandardRun.at.desc()).limit(1)).scalar_one_or_none()
        if last and utcnow() - last < timedelta(hours=23):
            continue
        try:
            run_for_tenant(db, tenant)
            db.commit()
        except Exception as exc:  # noqa: BLE001 - one customer must not stop the others
            db.rollback()
            log.warning("M365 standards for %s failed: %s", tenant.name, exc)
