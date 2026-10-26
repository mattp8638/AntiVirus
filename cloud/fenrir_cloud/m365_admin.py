"""Allowlisted Graph administration. No arbitrary URLs, scripts, or blind write retries."""
from contextlib import contextmanager
from uuid import UUID
from urllib.parse import quote
import httpx
from . import m365

USER_FIELDS = "id,displayName,userPrincipalName,accountEnabled,department,jobTitle,usageLocation,assignedLicenses,userType"
GROUP_FIELDS = "id,displayName,groupTypes,mailEnabled,securityEnabled,isAssignableToRole,onPremisesSyncEnabled"
CAPABILITIES = {
    "user.create": ["User.ReadWrite.All", "Domain.Read.All"],
    "user.revoke_sessions": ["User.RevokeSessions.All", "User.Read.All"],
    "user.update": ["User.ReadWrite.All"],
    "user.signin": ["User.EnableDisableAccount.All", "User.Read.All"],
    "license.add": ["LicenseAssignment.ReadWrite.All", "User.Read.All"],
    "license.remove": ["LicenseAssignment.ReadWrite.All", "User.Read.All"],
    "group.add_member": ["GroupMember.ReadWrite.All", "User.Read.All"],
    "group.remove_member": ["GroupMember.ReadWrite.All", "User.Read.All"],
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

def user(client, headers, ident):
    return request(client, headers, "GET", f"/users/{UUID(ident)}?$select={USER_FIELDS}")

def group(client, headers, ident):
    row = request(client, headers, "GET", f"/groups/{UUID(ident)}?$select={GROUP_FIELDS}")
    # Role-assignable, dynamic, synced, and Exchange-managed groups require other workflows.
    if (row.get("isAssignableToRole") is not False or row.get("onPremisesSyncEnabled")
            or "DynamicMembership" in row.get("groupTypes", [])
            or (row.get("mailEnabled") and "Unified" not in row.get("groupTypes", []))):
        raise ProviderError("This group requires a privileged, dynamic, synced or Exchange management workflow.")
    return row

def preview(connection, operation, target, parameters):
    if operation == "user.create":
        with session(connection) as (client, headers):
            validate_new_user(client, headers, parameters)
        return {"user": parameters, "changes": parameters, "requiredPermissions": CAPABILITIES[operation]}
    with session(connection) as (client, headers):
        current = user(client, headers, target)
        validate_license(operation, parameters, current)
        if operation == "user.revoke_sessions" and current.get("userType") != "Member":
            raise ProviderError("Session revocation requires a member user in this directory; external users must be managed in their home tenant.")
        result = {"user": current, "changes": parameters, "requiredPermissions": CAPABILITIES[operation]}
        if operation.startswith("group."):
            result["group"] = group(client, headers, parameters["groupId"])
        if operation.startswith("license."):
            skus = m365.collect(client, m365.GRAPH + "/subscribedSkus", headers["Authorization"][7:])
            sku = next((x for x in skus if x.get("skuId") == parameters["skuId"]), None)
            if not sku:
                raise ProviderError("Selected licence is not present in this directory.")
            result["license"] = {"skuId": sku["skuId"], "name": sku.get("skuPartNumber", "")}
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

def execute(connection, operation, target, parameters):
    """Revalidate targets before dispatch; failures after dispatch can have ambiguous outcomes."""
    with session(connection) as (client, headers):
        current = user(client, headers, target)
        validate_license(operation, parameters, current)
        if operation == "user.revoke_sessions" and current.get("userType") != "Member":
            raise ProviderError("Session revocation requires a member user in this directory; external users must be managed in their home tenant.")
        method, path, body = "PATCH", f"/users/{UUID(target)}", parameters
        if operation == "user.revoke_sessions":
            method, path, body = "POST", path + "/revokeSignInSessions", None
        elif operation == "user.signin":
            body = {"accountEnabled": parameters["accountEnabled"]}
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
            status = exc.response.status_code
            raise ProviderError("Microsoft rejected the action. Check consent, target restrictions and service availability.",
                                uncertain=status >= 500 or status == 408) from None
        except (httpx.RequestError, ValueError, KeyError):
            raise ProviderError("Microsoft's result is unknown. Inspect the tenant before preparing another action.", uncertain=True) from None
        if operation == "user.revoke_sessions":
            return "succeeded", {"message": "Microsoft accepted session revocation. It can take a few minutes to take effect; this does not block future sign-ins."}
        # A successful write must not be reclassified as failed if refresh fails.
        try:
            result = {"user": user(client, headers, target)}
            if operation.startswith("group."):
                result["members"] = m365.collect(client, m365.GRAPH + f"/groups/{UUID(parameters['groupId'])}/members?$select=id,displayName", headers["Authorization"][7:])
            return "succeeded", result
        except (httpx.HTTPError, ValueError, KeyError):
            return "succeeded_refresh_pending", {"message": "Microsoft accepted the change; refresh the directory to verify current state."}


def validate_license(operation, parameters, current):
    if operation == "license.add" and any(x.get("skuId") == parameters["skuId"] for x in current.get("assignedLicenses", [])):
        raise ProviderError("User already has this licence. Existing disabled service plans are preserved; use a separate plan-edit workflow.")


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
            raise ProviderError("Microsoft rejected user creation. Check domain, password policy, consent and duplicate sign-in names.",
                                uncertain=status >= 500 or status == 408) from None
        except (httpx.RequestError, ValueError, KeyError, TypeError):
            raise ProviderError("User creation outcome is unknown. Check the directory before preparing another action.", uncertain=True) from None
        # Never persist provider passwordProfile data, even if returned by Microsoft.
        return "succeeded", {"user": {"id": ident, "displayName": parameters["displayName"],
            "userPrincipalName": parameters["userPrincipalName"]},
            "message": "User created. A password change is required at first sign-in. Assign licences and groups separately."}
