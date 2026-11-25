"""ISMS roles and permissions, with record-level owner overrides. Pure: no database or FastAPI imports.

These are the standalone app's per-organization roles. How a Fenrir user gets one (from their Fenrir role, or from a
separate ISMS role per customer) is decision R7 in ``docs/ISMS_REWRITE_PLAN.md``; this module only says what each
ISMS role may do.
"""

from __future__ import annotations

TENANT_ROLES = ("tenant_admin", "isms_manager", "control_owner", "approver", "staff", "auditor", "executive_viewer")

PERMISSIONS = (
    "tenant.settings.manage",
    "tenant.users.manage",
    "tenant.security.manage",  # MFA enforcement, session timeout, SSO
    "tenant.modules.manage",
    "audit_log.view",
    "programme.manage",  # risks, controls, Statement of Applicability, documents, audits
    "controls.view",
    "controls.edit",
    "risks.view",
    "risks.edit",
    "risks.accept",
    "documents.view",
    "documents.edit",
    "documents.approve",
    "documents.acknowledge",
    "evidence.upload",
    "evidence.view",
    "tasks.complete",
    "dashboard.executive",
    "findings.log",
)

_READ_ONLY = ("controls.view", "risks.view", "documents.view", "evidence.view")

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "tenant_admin": frozenset(PERMISSIONS),
    "isms_manager": frozenset(p for p in PERMISSIONS if not p.startswith("tenant.")),
    "control_owner": frozenset((*_READ_ONLY, "evidence.upload", "tasks.complete", "documents.acknowledge")),
    "approver": frozenset((*_READ_ONLY, "documents.approve", "risks.accept", "documents.acknowledge")),
    "staff": frozenset(("documents.view", "documents.acknowledge", "tasks.complete")),
    "auditor": frozenset((*_READ_ONLY, "audit_log.view", "findings.log")),
    "executive_viewer": frozenset((*_READ_ONLY, "dashboard.executive")),
}

# An owner may edit their own controls, risks and documents without broader rights, if their role can view them.
_OWNER_OVERRIDES = {"controls.edit": "controls.view", "risks.edit": "risks.view", "documents.edit": "documents.view"}


class IsmsForbidden(PermissionError):
    def __init__(self, permission: str):
        super().__init__(f"You do not have permission to do this ({permission}).")
        self.permission = permission


def can(role: str | None, permission: str) -> bool:
    return bool(role) and permission in ROLE_PERMISSIONS.get(role, frozenset())


def can_on_record(role: str | None, user_id: str, permission: str, owner_id: str | None) -> bool:
    """A permission on one record: the role allows it, or the user owns the record and the override applies."""
    if can(role, permission):
        return True
    needs = _OWNER_OVERRIDES.get(permission)
    return bool(needs) and bool(owner_id) and owner_id == user_id and can(role, needs)


def assert_can(role: str | None, permission: str) -> None:
    if not can(role, permission):
        raise IsmsForbidden(permission)
