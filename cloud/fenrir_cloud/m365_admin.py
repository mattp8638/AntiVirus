"""Allowlisted Graph administration. No arbitrary URLs, scripts, or blind write retries.

One-off secrets Microsoft or Fenrir creates for an action (a reset password, a Temporary Access Pass) are returned under
``_secret`` in the result. The router hands them to the technician once and never stores them."""
from contextlib import contextmanager
from datetime import timedelta
from uuid import UUID
from urllib.parse import quote
import secrets
import string
import httpx
from . import m365, m365_permissions
from .models import utcnow

USER_FIELDS = ("id,displayName,userPrincipalName,accountEnabled,department,jobTitle,usageLocation,assignedLicenses,userType,mail,"
               "givenName,surname,onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesUserPrincipalName,onPremisesDomainName")
# What Microsoft refuses to change in the cloud for a user synced from Active Directory (it belongs to AD).
SYNCED_MASTERED = {"user.update", "user.signin", "user.reset_password"}
GROUP_FIELDS = "id,displayName,groupTypes,mailEnabled,securityEnabled,isAssignableToRole,onPremisesSyncEnabled,mailNickname"
# What each operation needs on an app connection (GDAP connections: m365_permissions.FEATURES[...]["delegated"]).
CAPABILITIES = {op: list(m365_permissions.FEATURES[feature]["app"] or []) for op, feature in m365_permissions.OPERATION_FEATURE.items()}
CAPABILITIES["user.manager"] = list(m365_permissions.FEATURES["user.update"]["app"])
# Operations that make something new rather than act on an existing user.
NEW_OBJECT = {"user.create", "group.create", "guest.invite"}

GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def temp_admin_roles() -> dict[str, str]:
    from .m365_partner import RECOMMENDED_ROLES

    return {GLOBAL_ADMIN: "Global Administrator", "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator", **RECOMMENDED_ROLES}


# Authentication method types Fenrir removes for an MFA reset (the password is never removed), in a safe order: the
# phone methods last, because Microsoft will not remove a default method while others remain.
METHOD_COLLECTIONS = {
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod": ("microsoftAuthenticatorMethods", "Microsoft Authenticator"),
    "#microsoft.graph.softwareOathAuthenticationMethod": ("softwareOathMethods", "Authenticator app (code)"),
    "#microsoft.graph.fido2AuthenticationMethod": ("fido2Methods", "Security key or passkey"),
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": ("windowsHelloForBusinessMethods", "Windows Hello for Business"),
    "#microsoft.graph.temporaryAccessPassAuthenticationMethod": ("temporaryAccessPassMethods", "Temporary Access Pass"),
    "#microsoft.graph.emailAuthenticationMethod": ("emailMethods", "Email (password reset only)"),
    "#microsoft.graph.phoneAuthenticationMethod": ("phoneMethods", "Phone"),
}


class ProviderError(Exception):
    def __init__(self, message, uncertain=False):
        super().__init__(message)
        self.uncertain = uncertain


@contextmanager
def session(connection):
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        token = m365.access_token(client, connection)
        yield client, {"Authorization": "Bearer " + token}


def request(client, headers, method, path, body=None):
    response = client.request(method, m365.GRAPH + path, headers=headers, **({"json": body} if body is not None else {}))
    response.raise_for_status()
    return response.json() if response.content else {}


def microsoft_said(response: httpx.Response) -> str:
    """Microsoft's own error code and message (they name the missing permission or role; they hold no secrets)."""
    try:
        error = response.json().get("error") or {}
        text = ": ".join(str(x) for x in (error.get("code"), error.get("message")) if x)
    except (ValueError, AttributeError):
        text = ""
    return f" Microsoft said: {text[:300]}" if text else ""


def unexpected(exc: Exception, service: str):
    """An HTTPException for a failure a Microsoft 365 page did not expect: what went wrong in plain words (never a bare
    500), with the full traceback in the server log."""
    import logging

    from fastapi import HTTPException

    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, httpx.HTTPStatusError):
        if exc.response.status_code in (400, 401) and "login.microsoftonline.com" in str(exc.request.url):
            said = microsoft_said(exc.response) or (": " + exc.response.text[:300] if exc.response.text else "")
            return HTTPException(400, f"Microsoft would not issue a token for {service}; check the connection's consent and "
                                      f"secret (Microsoft 365 > Permissions).{said}")
        if exc.response.status_code in (401, 403):
            return HTTPException(400, f"Microsoft refused access to {service}; the connection needs more permissions "
                                      f"(Microsoft 365 > Permissions > Update permissions)." + microsoft_said(exc.response))
        return HTTPException(502, f"{service} returned HTTP {exc.response.status_code}." + microsoft_said(exc.response))
    if isinstance(exc, httpx.DecodingError):
        return HTTPException(502, f"{service} answered, but Fenrir could not read the reply ({exc}).")
    if isinstance(exc, httpx.TimeoutException):
        return HTTPException(504, f"{service} did not answer in time ({exc.request.url.host}); try again.")
    if isinstance(exc, httpx.HTTPError):
        host = getattr(getattr(exc, "request", None), "url", None)
        return HTTPException(502, f"Fenrir could not reach {service}" + (f" at {host.host}" if host else "")
                                  + f" ({type(exc).__name__}); check the server can connect out to it.")
    logging.getLogger("fenrir.m365").exception("Unexpected %s failure", service)
    return HTTPException(500, f"{service}: unexpected error ({type(exc).__name__}: {str(exc)[:200]}). It is in the server log.")


def user(client, headers, ident):
    return request(client, headers, "GET", f"/users/{UUID(ident)}?$select={USER_FIELDS}")


def group(client, headers, ident):
    row = request(client, headers, "GET", f"/groups/{UUID(ident)}?$select={GROUP_FIELDS}")
    reason = group_restriction(row)
    if reason:
        raise ProviderError(reason)
    return row


def group_restriction(row: dict) -> str:
    """Why Fenrir will not change this group's members through Graph, or ""."""
    if row.get("isAssignableToRole"):
        return "This group can hold admin roles; change its members in Entra with Privileged Role Administrator."
    if row.get("onPremisesSyncEnabled"):
        return "This group is synced from on-premises Active Directory; change it there."
    if "DynamicMembership" in (row.get("groupTypes") or []):
        return "This group's members are set by a rule."
    if row.get("mailEnabled") and "Unified" not in (row.get("groupTypes") or []):
        return "Distribution lists and mail-enabled security groups are managed in Exchange (coming with the Exchange batch)."
    return ""


def _member(current):
    if current.get("userType") != "Member":
        raise ProviderError("This needs a member user of this directory; guests are managed in their home tenant.")


def methods(client, headers, ident) -> list[dict]:
    rows = m365.collect(client, m365.GRAPH + f"/users/{UUID(ident)}/authentication/methods", headers["Authorization"][7:])
    out = []
    for row in rows:
        kind = row.get("@odata.type")
        if kind in METHOD_COLLECTIONS:
            collection, label = METHOD_COLLECTIONS[kind]
            detail = row.get("phoneNumber") or row.get("displayName") or row.get("emailAddress") or row.get("model") or ""
            out.append({"id": row.get("id"), "type": kind, "collection": collection, "label": label, "detail": str(detail)[:80]})
    order = list(METHOD_COLLECTIONS)
    out.sort(key=lambda m: order.index(m["type"]))
    return out


def existing_role(client, headers, ident, role_id) -> str | None:
    rows = request(client, headers, "GET", "/roleManagement/directory/roleAssignments?$filter=" +
                   quote(f"principalId eq '{UUID(ident)}' and roleDefinitionId eq '{UUID(role_id)}'", safe="="))
    found = [r for r in rows.get("value") or [] if r.get("directoryScopeId", "/") == "/"]
    return found[0].get("id") if found else None


def _odata(value: str) -> str:
    return value.replace("'", "''")


def preview(connection, operation, target, parameters):
    required = CAPABILITIES[operation]
    with session(connection) as (client, headers):
        if operation == "user.create":
            validate_new_user(client, headers, parameters)
            return {"user": parameters, "changes": parameters, "requiredPermissions": required}
        if operation == "group.create":
            validate_new_group(client, headers, parameters)
            out = {"group": {"displayName": parameters["displayName"]}, "changes": parameters, "requiredPermissions": required}
            if parameters.get("ownerId"):
                out["owner"] = user(client, headers, parameters["ownerId"])
            return out
        if operation == "guest.invite":
            validate_guest(client, headers, parameters)
            return {"user": {"userPrincipalName": parameters["email"], "displayName": parameters.get("displayName", "")},
                    "changes": parameters, "requiredPermissions": required}
        current = user(client, headers, target)
        validate_license(operation, parameters, current)
        if operation in ("user.revoke_sessions", "user.tap", "user.reset_mfa", "user.reset_password"):
            _member(current)
        if current.get("onPremisesSyncEnabled") and operation in SYNCED_MASTERED:
            raise ProviderError("This user is synced from Active Directory, so Microsoft only accepts this change in AD. Use "
                                "Offboarding (Fenrir makes the AD changes on the domain controller), or change it in Active "
                                "Directory Users and Computers; Entra Connect brings it across within 30 minutes.")
        result = {"user": current, "changes": parameters, "requiredPermissions": required}
        if operation.startswith("group."):
            result["group"] = group(client, headers, parameters["groupId"])
        if operation.startswith("license."):
            skus = m365.collect(client, m365.GRAPH + "/subscribedSkus", headers["Authorization"][7:])
            sku = next((x for x in skus if x.get("skuId") == parameters["skuId"]), None)
            if not sku:
                raise ProviderError("Selected licence is not present in this directory.")
            result["license"] = {"skuId": sku["skuId"], "name": sku.get("skuPartNumber", "")}
        if operation == "user.reset_mfa":
            result["methods"] = methods(client, headers, target)
            if not result["methods"]:
                raise ProviderError("This user has no MFA methods to remove.")
        if operation == "user.temp_admin":
            roles = temp_admin_roles()
            result["role"] = {"id": parameters["roleId"], "name": roles.get(parameters["roleId"], "")}
            if existing_role(client, headers, target, parameters["roleId"]):
                raise ProviderError("This user already holds that role. Fenrir only grants roles it can take away again.")
            result["expiresAt"] = (utcnow() + timedelta(hours=parameters["hours"])).isoformat() + "Z"
        if operation == "user.manager":
            result["manager"] = user(client, headers, parameters["managerId"])
            if parameters["managerId"] == str(UUID(target)):
                raise ProviderError("A user cannot be their own manager.")
        return result


def inventory(connection, collection):
    paths = {
        "users": "/users?$select=" + USER_FIELDS + "&$top=999",
        "groups": "/groups?$select=" + GROUP_FIELDS + "&$top=999",
        "licenses": "/subscribedSkus",
    }
    with session(connection) as (client, headers):
        return m365.collect(client, m365.GRAPH + paths[collection], headers["Authorization"][7:])


def diagnostics(connection):
    checks = []
    with session(connection) as (client, headers):
        for name, path in [("users", "/users?$select=id&$top=1"), ("groups", "/groups?$select=id&$top=1"),
                           ("licenses", "/subscribedSkus")]:
            try:
                request(client, headers, "GET", path)
                checks.append({"resource": name, "status": "available"})
            except httpx.HTTPStatusError as exc:
                checks.append({"resource": name, "status": "denied" if exc.response.status_code == 403 else "unavailable"})
    return {"checks": checks, "operations": CAPABILITIES,
            "note": "Read probes do not verify write consent. Microsoft validates permissions and target restrictions when an action runs."}


def new_password(length: int = 16) -> str:
    """A random password that meets Microsoft's complexity rules (no look-alike characters)."""
    upper, lower, digits, symbols = "ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!#$%&*?@-+="
    chars = [secrets.choice(upper), secrets.choice(lower), secrets.choice(digits), secrets.choice(symbols)]
    chars += [secrets.choice(upper + lower + digits + symbols) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _rejected(exc: httpx.HTTPStatusError, what: str = "the action") -> ProviderError:
    status = exc.response.status_code
    return ProviderError(f"Microsoft rejected {what}." + microsoft_said(exc.response), uncertain=status >= 500 or status == 408)


def execute(connection, operation, target, parameters):
    """Revalidate targets before dispatch; failures after dispatch can have ambiguous outcomes."""
    if operation in ("group.create", "guest.invite"):
        return _create_object(connection, operation, parameters)
    if operation == "user.reset_mfa":
        return reset_mfa(connection, target)
    with session(connection) as (client, headers):
        current = user(client, headers, target)
        validate_license(operation, parameters, current)
        if operation in ("user.revoke_sessions", "user.tap", "user.reset_password"):
            _member(current)
        method, path, body = "PATCH", f"/users/{UUID(target)}", parameters
        secret = None
        if operation == "user.revoke_sessions":
            method, path, body = "POST", path + "/revokeSignInSessions", None
        elif operation == "user.signin":
            body = {"accountEnabled": parameters["accountEnabled"]}
        elif operation == "user.reset_password":
            secret = new_password()
            body = {"passwordProfile": {"password": secret, "forceChangePasswordNextSignIn": parameters.get("forceChange", True)}}
        elif operation == "user.tap":
            method, path = "POST", path + "/authentication/temporaryAccessPassMethods"
            body = {"lifetimeInMinutes": parameters["lifetimeMinutes"], "isUsableOnce": parameters["usableOnce"]}
        elif operation == "user.temp_admin":
            if existing_role(client, headers, target, parameters["roleId"]):
                raise ProviderError("This user already holds that role. Fenrir only grants roles it can take away again.")
            method, path = "POST", "/roleManagement/directory/roleAssignments"
            body = {"principalId": str(UUID(target)), "roleDefinitionId": str(UUID(parameters["roleId"])), "directoryScopeId": "/"}
        elif operation == "user.manager":
            method, path = "PUT", path + "/manager/$ref"
            body = {"@odata.id": m365.GRAPH + "/users/" + str(UUID(parameters["managerId"]))}
        elif operation.startswith("license."):
            body = {"addLicenses": [{"skuId": parameters["skuId"], "disabledPlans": []}] if operation == "license.add" else [],
                    "removeLicenses": [parameters["skuId"]] if operation == "license.remove" else []}
            method, path = "POST", path + "/assignLicense"
        elif operation.startswith("group."):
            group(client, headers, parameters["groupId"])
            path = f"/groups/{UUID(parameters['groupId'])}/members"
            if operation == "group.add_member":
                method, path, body = "POST", path + "/$ref", {"@odata.id": m365.GRAPH + "/directoryObjects/" + str(UUID(target))}
            else:
                method, path, body = "DELETE", path + "/" + str(UUID(target)) + "/$ref", None
        try:
            response = request(client, headers, method, path, body)
            if operation == "user.revoke_sessions" and response.get("value") is False:
                raise ProviderError("Microsoft did not confirm session revocation.", uncertain=True)
        except httpx.HTTPStatusError as exc:
            if operation == "user.tap" and exc.response.status_code == 400:
                raise ProviderError("Microsoft would not issue a Temporary Access Pass. Check that it is turned on in the tenant's "
                                    "Authentication methods policy and that the lifetime is within the policy's limits."
                                    + microsoft_said(exc.response)) from None
            raise _rejected(exc) from None
        except (httpx.RequestError, ValueError, KeyError):
            raise ProviderError("Microsoft's result is unknown. Inspect the tenant before preparing another action.", uncertain=True) from None
        if operation == "user.revoke_sessions":
            return "succeeded", {"message": "Microsoft accepted session revocation. It can take a few minutes to take effect; this does not block future sign-ins."}
        if operation == "user.reset_password":
            return "succeeded", {"_secret": secret, "message": "Password reset. Give the new password to the user securely; Fenrir does not keep it."
                                 + (" They must change it when they next sign in." if parameters.get("forceChange", True) else "")}
        if operation == "user.tap":
            return "succeeded", {"_secret": response.get("temporaryAccessPass") or "", "lifetimeMinutes": response.get("lifetimeInMinutes"),
                                 "usableOnce": response.get("isUsableOnce"), "startDateTime": response.get("startDateTime"),
                                 "message": "Temporary Access Pass issued. Give it to the user securely; Fenrir does not keep it."}
        if operation == "user.temp_admin":
            expires = utcnow() + timedelta(hours=parameters["hours"])
            return "succeeded", {"assignmentId": response.get("id"), "roleId": parameters["roleId"],
                                 "roleName": temp_admin_roles().get(parameters["roleId"], ""), "expiresAt": expires.isoformat() + "Z",
                                 "message": f"Role granted until {expires:%d %b %Y %H:%M} UTC. Fenrir removes it then, or when you end it sooner."}
        # A successful write must not be reclassified as failed if refresh fails.
        try:
            result = {"user": user(client, headers, target)}
            if operation.startswith("group."):
                result["members"] = m365.collect(client, m365.GRAPH + f"/groups/{UUID(parameters['groupId'])}/members?$select=id,displayName", headers["Authorization"][7:])
            return "succeeded", result
        except (httpx.HTTPError, ValueError, KeyError):
            return "succeeded_refresh_pending", {"message": "Microsoft accepted the change; refresh the directory to verify current state."}


def reset_mfa(connection, target):
    """Remove every MFA method (never the password). Returns partial when Microsoft keeps some."""
    with session(connection) as (client, headers):
        _member(user(client, headers, target))
        try:
            found = methods(client, headers, target)
        except httpx.HTTPStatusError as exc:
            raise _rejected(exc, "reading the user's sign-in methods") from None
        removed, failed = [], []
        pending = list(found)
        for _ in range(2):  # a second pass catches a default method Microsoft only releases once the others are gone
            retry = []
            for method in pending:
                try:
                    request(client, headers, "DELETE", f"/users/{UUID(target)}/authentication/{method['collection']}/{quote(str(method['id']), safe='')}")
                    removed.append(method["label"])
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        removed.append(method["label"])
                    else:
                        retry.append({**method, "reason": microsoft_said(exc.response).strip() or f"HTTP {exc.response.status_code}"})
                except httpx.RequestError:
                    retry.append({**method, "reason": "No answer from Microsoft"})
            pending = retry
            if not pending:
                break
        failed = [{"label": m["label"], "detail": m["detail"], "reason": m.get("reason", "")} for m in pending]
    status = "succeeded" if not failed else ("partial" if removed else "failed")
    return status, {"removed": removed, "failed": failed,
                    "message": "MFA methods removed; the user registers again at next sign-in." if not failed
                    else "Some methods could not be removed; see below."}


def end_temp_admin(connection, assignment_id: str) -> str:
    """Remove a role assignment Fenrir made. Returns removed | already_gone."""
    with session(connection) as (client, headers):
        try:
            request(client, headers, "DELETE", "/roleManagement/directory/roleAssignments/" + quote(assignment_id, safe=""))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return "already_gone"
            raise _rejected(exc, "removing the role") from None
    return "removed"


def _create_object(connection, operation, parameters):
    with session(connection) as (client, headers):
        if operation == "group.create":
            validate_new_group(client, headers, parameters)
            unified = parameters["kind"] == "m365"
            body = {"displayName": parameters["displayName"], "mailNickname": parameters["mailNickname"],
                    "mailEnabled": unified, "securityEnabled": not unified, "groupTypes": ["Unified"] if unified else []}
            if parameters.get("description"):
                body["description"] = parameters["description"]
            if unified:
                body["visibility"] = "Private"
            if parameters.get("ownerId"):
                body["owners@odata.bind"] = [m365.GRAPH + "/users/" + str(UUID(parameters["ownerId"]))]
            what, path = "creating the group", "/groups"
        else:
            validate_guest(client, headers, parameters)
            body = {"invitedUserEmailAddress": parameters["email"], "inviteRedirectUrl": parameters.get("redirectUrl") or "https://myapps.microsoft.com",
                    "sendInvitationMessage": parameters.get("sendEmail", True)}
            if parameters.get("displayName"):
                body["invitedUserDisplayName"] = parameters["displayName"]
            if parameters.get("message"):
                body["invitedUserMessageInfo"] = {"customizedMessageBody": parameters["message"]}
            what, path = "the invitation", "/invitations"
        try:
            created = request(client, headers, "POST", path, body)
        except httpx.HTTPStatusError as exc:
            raise _rejected(exc, what) from None
        except (httpx.RequestError, ValueError):
            raise ProviderError("The outcome is unknown. Check the tenant before preparing another action.", uncertain=True) from None
    if operation == "group.create":
        return "succeeded", {"group": {"id": created.get("id"), "displayName": created.get("displayName")},
                             "message": "Group created. Microsoft can take a minute to show it everywhere."}
    invited = created.get("invitedUser") or {}
    return "succeeded", {"user": {"id": invited.get("id"), "userPrincipalName": parameters["email"]},
                         "redeemUrl": created.get("inviteRedeemUrl"),
                         "message": "Invitation sent." if parameters.get("sendEmail", True) else
                         "Guest added. Send them the redeem link yourself."}


def validate_license(operation, parameters, current):
    if operation == "license.add" and any(x.get("skuId") == parameters["skuId"] for x in current.get("assignedLicenses", [])):
        raise ProviderError("User already has this licence. Existing disabled service plans are preserved; use a separate plan-edit workflow.")


def validate_new_group(client, headers, parameters):
    found = request(client, headers, "GET", "/groups?$select=id&$filter=" + quote(f"mailNickname eq '{_odata(parameters['mailNickname'])}'", safe="="))
    if found.get("value"):
        raise ProviderError("A group with this alias already exists.")


def validate_guest(client, headers, parameters):
    email = parameters["email"]
    found = request(client, headers, "GET", "/users?$select=id,userPrincipalName&$filter=" + quote(f"mail eq '{_odata(email)}'", safe="="))
    if found.get("value"):
        raise ProviderError("Someone with this email address is already in the directory.")


def validate_new_user(client, headers, parameters):
    domain = parameters["userPrincipalName"].rsplit("@", 1)[1].lower()
    info = request(client, headers, "GET", "/domains/" + quote(domain, safe=""))
    if info.get("isVerified") is not True or info.get("authenticationType") != "Managed":
        raise ProviderError("Choose a verified managed domain. Federated users require a separate provisioning workflow.")
    try:
        request(client, headers, "GET", "/users/" + quote(parameters["userPrincipalName"], safe="") + "?$select=id")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return
        raise
    raise ProviderError("A user with this sign-in name already exists.")


def create_user(connection, parameters, password):
    with session(connection) as (client, headers):
        validate_new_user(client, headers, parameters)
        body = {**parameters, "accountEnabled": True,
                "passwordProfile": {"password": password, "forceChangePasswordNextSignIn": True}}
        try:
            created = request(client, headers, "POST", "/users", body)
            ident = str(UUID(created["id"]))
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            raise ProviderError("Microsoft rejected user creation. Check domain, password policy, consent and duplicate sign-in names."
                                + microsoft_said(exc.response), uncertain=status >= 500 or status == 408) from None
        except (httpx.RequestError, ValueError, KeyError, TypeError):
            raise ProviderError("User creation outcome is unknown. Check the directory before preparing another action.", uncertain=True) from None
        # Never persist provider passwordProfile data, even if returned by Microsoft.
        return "succeeded", {"user": {"id": ident, "displayName": parameters["displayName"],
            "userPrincipalName": parameters["userPrincipalName"]},
            "message": "User created. A password change is required at first sign-in. Assign licences and groups separately."}
