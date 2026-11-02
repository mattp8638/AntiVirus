"""What each Microsoft 365 feature needs, and what a connection actually has.

Each feature lists the Microsoft Graph permissions it needs in each connection mode:

- ``app``: application permissions (roles), for connections made by an admin sign-in, the platform app or a manual app.
- ``delegated``: delegated permissions (scopes), for GDAP connections through the partner tenant. What a technician can
  then do is also limited by the GDAP roles of the groups they are in, which a token does not show.

``None`` means Microsoft Graph cannot do it in that mode (for example another user's out-of-office message with a
delegated token): the feature then shows as not available there, with the reason.

What a connection has comes from its own access token (``roles`` for app tokens, ``scp`` for delegated ones), so the
check costs no extra calls and shows exactly what Microsoft will allow.
"""
from __future__ import annotations

import base64
import json

# A higher permission that includes a lower one (Microsoft's documented "higher privileged" alternatives).
SUPERSETS: dict[str, tuple[str, ...]] = {
    "User.Read.All": ("User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"),
    "User.RevokeSessions.All": ("User.ReadWrite.All", "Directory.ReadWrite.All"),
    "User.EnableDisableAccount.All": ("User.ReadWrite.All", "Directory.ReadWrite.All"),
    "User-PasswordProfile.ReadWrite.All": ("User.ReadWrite.All", "Directory.ReadWrite.All", "Directory.AccessAsUser.All"),
    "LicenseAssignment.ReadWrite.All": ("User.ReadWrite.All", "Directory.ReadWrite.All"),
    "GroupMember.ReadWrite.All": ("Group.ReadWrite.All", "Directory.ReadWrite.All"),
    "Group.Read.All": ("Group.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All"),
    "Domain.Read.All": ("Directory.Read.All", "Directory.ReadWrite.All", "Domain.ReadWrite.All"),
    "Organization.Read.All": ("Directory.Read.All", "Directory.ReadWrite.All", "Organization.ReadWrite.All"),
    "RoleManagement.Read.Directory": ("RoleManagement.ReadWrite.Directory", "Directory.Read.All", "Directory.ReadWrite.All"),
    "Policy.Read.All": ("Policy.ReadWrite.ConditionalAccess",),
}

# key: title, area, app permissions, delegated permissions, note
FEATURES: dict[str, dict] = {
    # --- Tenant workspace (reading) ---
    "sync.directory": {"title": "Users and licences", "area": "Workspace",
                       "app": ["User.Read.All", "Organization.Read.All"], "delegated": ["User.Read.All", "Organization.Read.All"]},
    "sync.securescore": {"title": "Secure Score", "area": "Workspace",
                         "app": ["SecurityEvents.Read.All"], "delegated": ["SecurityEvents.Read.All"]},
    "sync.domains": {"title": "Domains", "area": "Workspace", "app": ["Domain.Read.All"], "delegated": ["Domain.Read.All"]},
    "sync.admins": {"title": "Administrators and their roles", "area": "Workspace",
                    "app": ["RoleManagement.Read.Directory"], "delegated": ["RoleManagement.Read.Directory"]},
    "sync.servicehealth": {"title": "Microsoft service health", "area": "Workspace",
                           "app": ["ServiceHealth.Read.All"], "delegated": ["ServiceHealth.Read.All"]},
    "sync.mfa": {"title": "MFA registration", "area": "Workspace", "app": ["AuditLog.Read.All"], "delegated": ["AuditLog.Read.All"],
                 "note": "Needs Entra ID P1 or P2 in the customer's tenant."},
    "sync.signinactivity": {"title": "Last sign-in per user (inactive accounts)", "area": "Workspace",
                            "app": ["AuditLog.Read.All", "User.Read.All"], "delegated": ["AuditLog.Read.All", "User.Read.All"],
                            "note": "Needs Entra ID P1 or P2 in the customer's tenant."},
    "sync.intune": {"title": "Intune devices", "area": "Workspace",
                    "app": ["DeviceManagementManagedDevices.Read.All"], "delegated": ["DeviceManagementManagedDevices.Read.All"]},
    "sync.defender": {"title": "Defender alerts", "area": "Workspace",
                      "app": ["SecurityAlert.Read.All"], "delegated": ["SecurityAlert.Read.All"]},
    "logs.signins": {"title": "Sign-in log", "area": "Logs", "app": ["AuditLog.Read.All", "Directory.Read.All"],
                     "delegated": ["AuditLog.Read.All", "Directory.Read.All"],
                     "note": "Needs Entra ID P1 or P2 in the customer's tenant."},
    "logs.audit": {"title": "Directory audit log", "area": "Logs", "app": ["AuditLog.Read.All", "Directory.Read.All"],
                   "delegated": ["AuditLog.Read.All", "Directory.Read.All"]},
    # --- Identity ---
    "user.create": {"title": "Create users", "area": "Identity", "app": ["User.ReadWrite.All", "Domain.Read.All"],
                    "delegated": ["User.ReadWrite.All", "Domain.Read.All"]},
    "user.update": {"title": "Edit user profiles and managers", "area": "Identity", "app": ["User.ReadWrite.All"],
                    "delegated": ["User.ReadWrite.All"]},
    "user.signin": {"title": "Block or allow sign-in", "area": "Identity", "app": ["User.EnableDisableAccount.All", "User.Read.All"],
                    "delegated": ["User.EnableDisableAccount.All", "User.Read.All"]},
    "user.revoke_sessions": {"title": "Sign a user out everywhere", "area": "Identity",
                             "app": ["User.RevokeSessions.All", "User.Read.All"], "delegated": ["User.RevokeSessions.All", "User.Read.All"]},
    "user.reset_password": {"title": "Reset passwords", "area": "Identity", "app": ["User-PasswordProfile.ReadWrite.All"],
                            "delegated": ["User-PasswordProfile.ReadWrite.All"],
                            "note": "Microsoft only lets an app reset an administrator's password if the app itself holds a "
                                    "suitable admin role. Through GDAP, the technician needs the Helpdesk, User or Privileged "
                                    "Authentication Administrator role."},
    "user.reset_mfa": {"title": "Reset MFA (remove sign-in methods)", "area": "Identity",
                       "app": ["UserAuthenticationMethod.ReadWrite.All"], "delegated": ["UserAuthenticationMethod.ReadWrite.All"]},
    "user.tap": {"title": "Temporary Access Pass", "area": "Identity", "app": ["UserAuthenticationMethod.ReadWrite.All"],
                 "delegated": ["UserAuthenticationMethod.ReadWrite.All"],
                 "note": "Temporary Access Pass must be turned on in the tenant's Authentication methods policy."},
    "user.temp_admin": {"title": "Temporary admin roles", "area": "Identity", "app": ["RoleManagement.ReadWrite.Directory"],
                        "delegated": ["RoleManagement.ReadWrite.Directory"],
                        "note": "The most powerful permission Fenrir asks for. Remove it from the app if you never want "
                                "Fenrir to grant admin roles."},
    "user.out_of_office": {"title": "Set out-of-office replies", "area": "Identity", "app": ["MailboxSettings.ReadWrite"], "delegated": None,
                           "note": "Microsoft Graph can only set another user's automatic replies with an app connection. "
                                   "GDAP connections get this with the Exchange batch."},
    "license.assign": {"title": "Assign and remove licences", "area": "Identity",
                       "app": ["LicenseAssignment.ReadWrite.All", "User.Read.All"], "delegated": ["LicenseAssignment.ReadWrite.All", "User.Read.All"]},
    "group.members": {"title": "Change group membership", "area": "Identity", "app": ["GroupMember.ReadWrite.All", "User.Read.All"],
                      "delegated": ["GroupMember.ReadWrite.All", "User.Read.All"]},
    "group.create": {"title": "Create groups", "area": "Identity", "app": ["Group.ReadWrite.All"], "delegated": ["Group.ReadWrite.All"]},
    "guest.invite": {"title": "Invite guests", "area": "Identity", "app": ["User.Invite.All"], "delegated": ["User.Invite.All"]},
    # --- Standards (already built) ---
    "standards.ca": {"title": "Conditional Access standards", "area": "Standards",
                     "app": ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All"],
                     "delegated": ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All"]},
    "standards.intune": {"title": "Intune compliance standard", "area": "Standards",
                         "app": ["DeviceManagementConfiguration.ReadWrite.All"], "delegated": ["DeviceManagementConfiguration.ReadWrite.All"]},
    # --- Intune, directory standards, Teams and SharePoint ---
    "intune.devices": {"title": "Intune devices and actions", "area": "Devices",
                       "app": ["DeviceManagementManagedDevices.ReadWrite.All", "DeviceManagementManagedDevices.PrivilegedOperations.All"],
                       "delegated": ["DeviceManagementManagedDevices.ReadWrite.All", "DeviceManagementManagedDevices.PrivilegedOperations.All"]},
    "intune.keys": {"title": "BitLocker keys and LAPS passwords", "area": "Devices",
                    "app": ["BitlockerKey.Read.All", "DeviceLocalCredential.Read.All"],
                    "delegated": ["BitlockerKey.Read.All", "DeviceLocalCredential.Read.All"]},
    "intune.policies": {"title": "Intune policies, apps and Autopilot", "area": "Devices",
                        "app": ["DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementApps.ReadWrite.All",
                                "DeviceManagementServiceConfig.ReadWrite.All"],
                        "delegated": ["DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementApps.ReadWrite.All",
                                      "DeviceManagementServiceConfig.ReadWrite.All"]},
    "standards.directory": {"title": "Directory security standards", "area": "Security",
                            "app": ["Policy.Read.All", "Policy.ReadWrite.Authorization"],
                            "delegated": ["Policy.Read.All", "Policy.ReadWrite.Authorization"]},
    "collaboration": {"title": "Teams, SharePoint and OneDrive", "area": "Collaboration",
                      "app": ["Sites.Read.All", "SharePointTenantSettings.ReadWrite.All", "Team.ReadBasic.All", "Files.ReadWrite.All"],
                      "delegated": ["Sites.Read.All", "SharePointTenantSettings.ReadWrite.All", "Team.ReadBasic.All", "Files.ReadWrite.All"]},
    "reports.usage": {"title": "Usage and activity reports", "area": "Reports", "app": ["Reports.Read.All", "UserAuthenticationMethod.Read.All"],
                      "delegated": ["Reports.Read.All", "UserAuthenticationMethod.Read.All"]},
}

# Operations of reviewed actions -> the feature that gates them.
OPERATION_FEATURE = {
    "user.create": "user.create", "user.update": "user.update", "user.signin": "user.signin",
    "user.revoke_sessions": "user.revoke_sessions", "user.reset_password": "user.reset_password", "user.reset_mfa": "user.reset_mfa",
    "user.tap": "user.tap", "user.temp_admin": "user.temp_admin", "license.add": "license.assign", "license.remove": "license.assign",
    "group.add_member": "group.members", "group.remove_member": "group.members", "group.create": "group.create",
    "guest.invite": "guest.invite",
}


def _ordered(names) -> list[str]:
    seen: list[str] = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen


# Everything an app connection is set up with (admin sign-in provisioning), and what GDAP customers consent to.
APP_PERMISSIONS = _ordered(["User.Read.All", "Organization.Read.All", "Directory.Read.All", "Domain.Read.All", "SecurityEvents.Read.All",
                            "AuditLog.Read.All", "Reports.Read.All", "User.ReadWrite.All", "User.RevokeSessions.All",
                            "User.EnableDisableAccount.All", "LicenseAssignment.ReadWrite.All", "GroupMember.ReadWrite.All",
                            "SecurityAlert.Read.All"]
                           + [p for f in FEATURES.values() for p in (f["app"] or [])])
DELEGATED_PERMISSIONS = _ordered(["Directory.Read.All", "Organization.Read.All", "Domain.Read.All", "User.ReadWrite.All", "Group.ReadWrite.All",
                                  "AuditLog.Read.All", "Reports.Read.All", "UserAuthenticationMethod.Read.All", "SecurityEvents.Read.All",
                                  "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All",
                                  "DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementManagedDevices.Read.All",
                                  "SecurityAlert.Read.All",
                                  # Added for the workspace and identity batches. Password resets through GDAP use the
                                  # technician's own rights (Directory.AccessAsUser.All), as Microsoft documents.
                                  "UserAuthenticationMethod.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "User.Invite.All",
                                  "ServiceHealth.Read.All", "Directory.AccessAsUser.All"])


def claims(token: str) -> dict:
    """The payload of a Microsoft access token, without verifying it (it came straight from Microsoft over TLS)."""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError, AttributeError):
        return {}


def granted_from_token(token: str) -> tuple[str, list[str]]:
    """("app" | "delegated", permission names) for a Graph access token."""
    data = claims(token)
    if "scp" in data:
        return "delegated", sorted(set(str(data.get("scp") or "").split()))
    return "app", sorted({str(r) for r in data.get("roles") or []})


def has(permission: str, granted: set[str]) -> bool:
    return permission in granted or any(alt in granted for alt in SUPERSETS.get(permission, ()))


def report(mode: str, granted: list[str]) -> list[dict]:
    """Every feature: available, or what is missing and why."""
    have = set(granted)
    out = []
    for key, feature in FEATURES.items():
        needed = feature.get(mode)
        row = {"key": key, "title": feature["title"], "area": feature["area"], "note": feature.get("note", "")}
        if needed is None:
            row.update(available=False, missing=[], unsupported=True)
        else:
            missing = [p for p in needed if not has(p, have)]
            row.update(available=not missing, missing=missing, unsupported=False)
        out.append(row)
    return out


def feature_available(snapshot: dict | None, feature: str) -> bool | None:
    """From a connection's last permission check: True, False, or None when it has not been checked."""
    check = (snapshot or {}).get("permissions") or {}
    for row in check.get("features") or []:
        if row.get("key") == feature:
            return bool(row.get("available"))
    return None
