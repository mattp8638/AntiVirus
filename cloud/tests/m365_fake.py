"""A small in-memory Microsoft tenant behind httpx.MockTransport, for the Microsoft 365 workspace and lifecycle tests.

It answers the Graph calls Fenrir makes with the shapes Microsoft documents, keeps state (users, groups, roles,
methods, logs) and records every request so tests can check exactly what Fenrir sent."""
from __future__ import annotations

import base64
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, unquote, urlparse

import httpx

REAL_CLIENT = httpx.Client
USER = "00000000-0000-0000-0000-000000000010"
MANAGER = "00000000-0000-0000-0000-000000000011"
GROUP = "00000000-0000-0000-0000-000000000020"
DYNAMIC = "00000000-0000-0000-0000-000000000021"
DL = "00000000-0000-0000-0000-000000000022"
SKU = "00000000-0000-0000-0000-000000000030"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
HELPDESK = "729827e3-9c14-49f7-bb1b-9608f156bbb8"


def token(roles=None, scp=None) -> str:
    claims = {"tid": "00000000-0000-0000-0000-000000000001"}
    if scp is not None:
        claims["scp"] = scp
    else:
        claims["roles"] = roles if roles is not None else ["User.ReadWrite.All", "AuditLog.Read.All", "Directory.Read.All"]
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{body}.sig"


def iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "") + "Z"


class FakeTenant:
    def __init__(self):
        now = datetime.now(timezone.utc)
        self.roles = None
        self.requests: list[tuple[str, str, dict | None]] = []
        self.fail: dict[tuple[str, str], int] = {}  # (method, path regex) -> HTTP status to answer instead
        self.users = {
            USER: {"id": USER, "displayName": "Jo Leaver", "userPrincipalName": "jo@acme.example", "mail": "jo@acme.example",
                   "accountEnabled": True, "userType": "Member", "usageLocation": "GB", "assignedLicenses": [{"skuId": SKU}],
                   "licenseAssignmentStates": [{"skuId": SKU, "assignedByGroup": None}], "createdDateTime": iso(now - timedelta(days=400))},
            MANAGER: {"id": MANAGER, "displayName": "Max Manager", "userPrincipalName": "max@acme.example", "accountEnabled": True,
                      "userType": "Member", "assignedLicenses": [], "createdDateTime": iso(now - timedelta(days=400))},
        }
        self.groups = {
            GROUP: {"id": GROUP, "displayName": "Sales", "groupTypes": [], "mailEnabled": False, "securityEnabled": True,
                    "isAssignableToRole": None, "onPremisesSyncEnabled": None, "mailNickname": "sales", "members": {USER}},
            DYNAMIC: {"id": DYNAMIC, "displayName": "All staff", "groupTypes": ["DynamicMembership"], "mailEnabled": False,
                      "securityEnabled": True, "mailNickname": "all", "members": {USER}},
            DL: {"id": DL, "displayName": "Newsletter", "groupTypes": [], "mailEnabled": True, "securityEnabled": False,
                 "mailNickname": "news", "members": {USER}},
        }
        self.assignments = {"ra-1": {"id": "ra-1", "principalId": USER, "roleDefinitionId": HELPDESK, "directoryScopeId": "/"}}
        self.methods = {USER: [
            {"@odata.type": "#microsoft.graph.phoneAuthenticationMethod", "id": "3179e48a-750b-4051-897c-87b9720928f7", "phoneNumber": "+44 7700 900000"},
            {"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod", "id": "auth-1", "displayName": "Jo's phone"},
            {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod", "id": "pw"}]}
        self.signins = [{"id": f"si-{i}", "createdDateTime": iso(now - timedelta(minutes=10 * i)), "userPrincipalName": "jo@acme.example",
                         "appDisplayName": "Office 365", "ipAddress": "198.51.100.7", "location": {"city": "Leeds", "countryOrRegion": "GB"},
                         "status": {"errorCode": 0 if i % 3 else 50126, "failureReason": "" if i % 3 else "Invalid password"},
                         "deviceDetail": {"operatingSystem": "Windows"}} for i in range(1, 8)]
        self.audits = [{"id": f"au-{i}", "activityDateTime": iso(now - timedelta(minutes=15 * i)), "activityDisplayName": "Add member to group",
                        "category": "GroupManagement", "result": "success", "loggedByService": "Core Directory",
                        "initiatedBy": {"user": {"userPrincipalName": "admin@acme.example", "ipAddress": "203.0.113.5"}},
                        "targetResources": [{"type": "User", "userPrincipalName": "jo@acme.example",
                                             "modifiedProperties": [{"displayName": "Group.DisplayName", "newValue": "\"Sales\""}]}]}
                       for i in range(1, 4)]
        self.premium = True
        self.authz = {"id": "authorizationPolicy", "allowInvitesFrom": "everyone", "allowEmailVerifiedUsersToJoinOrganization": True,
                      "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
                      "defaultUserRolePermissions": {"allowedToCreateApps": True, "allowedToCreateTenants": True,
                                                     "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}}
        self.exo_lists = {"Get-DkimSigningConfig": [{"Domain": "acme.example", "Enabled": False, "Selector1CNAME": "selector1-acme-example._domainkey.acme.onmicrosoft.com",
                                                     "Selector2CNAME": "selector2-acme-example._domainkey.acme.onmicrosoft.com"},
                                                    {"Domain": "acme.onmicrosoft.com", "Enabled": True}],
                          "Get-SafeLinksPolicy": [], "Get-SafeAttachmentPolicy": [{"Name": "Built-In Protection Policy", "Enable": True}]}
        self.exo_org = {"Get-AdminAuditLogConfig": {"UnifiedAuditLogIngestionEnabled": False},
                        "Get-AntiPhishPolicy": {"EnableSpoofIntelligence": True, "EnableFirstContactSafetyTips": False, "HonorDmarcPolicy": True},
                        "Get-MalwareFilterPolicy": {"EnableFileFilter": False},
                        "Get-OrganizationConfig": {"AuditDisabled": False, "OAuth2ClientProfileEnabled": True},
                        "Get-HostedOutboundSpamFilterPolicy": {"AutoForwardingMode": "Automatic"},
                        "Get-TransportConfig": {"SmtpClientAuthenticationDisabled": False}}
        # Intune
        self.managed = {
            "11111111-aaaa-4aaa-8aaa-000000000001": {"id": "11111111-aaaa-4aaa-8aaa-000000000001", "deviceName": "JO-LAPTOP",
                "userPrincipalName": "jo@acme.example", "operatingSystem": "Windows", "osVersion": "10.0.26100", "complianceState": "noncompliant",
                "azureADDeviceId": "22222222-bbbb-4bbb-8bbb-000000000001", "isEncrypted": True, "serialNumber": "SN1",
                "totalStorageSpaceInBytes": 100, "freeStorageSpaceInBytes": 40},
            "11111111-aaaa-4aaa-8aaa-000000000002": {"id": "11111111-aaaa-4aaa-8aaa-000000000002", "deviceName": "JO-IPHONE",
                "userPrincipalName": "jo@acme.example", "operatingSystem": "iOS", "osVersion": "18.1", "complianceState": "compliant",
                "azureADDeviceId": None}}
        self.device_actions: list[tuple[str, str]] = []
        self.bitlocker = {"bk-1": {"id": "bk-1", "deviceId": "22222222-bbbb-4bbb-8bbb-000000000001", "volumeType": "operatingSystemVolume",
                                   "key": "111111-222222-333333-444444-555555-666666-777777-888888"}}
        self.laps = {"22222222-bbbb-4bbb-8bbb-000000000001": {"credentials": [
            {"accountName": "LapsAdmin", "passwordBase64": base64.b64encode(b"S3cret-LAPS!").decode(), "backupDateTime": iso(now)}]}}
        self.mobile_apps = {"33333333-cccc-4ccc-8ccc-000000000001": {"@odata.type": "#microsoft.graph.winGetApp", "id": "33333333-cccc-4ccc-8ccc-000000000001",
                                                                     "displayName": "Company Portal", "publisher": "Microsoft",
                                                                     "assignments": [{"intent": "required", "target": {"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"}}]}}
        self.autopilot_imports: list[dict] = []
        self.sharepoint = {"sharingCapability": "externalUserAndGuestSharing", "isResharingByExternalUsersEnabled": True}
        self.onedrive_shares: list = []
        # Exchange Online (adminapi InvokeCommand)
        self.exo_denied = False
        self.exo_calls: list[tuple[str, dict]] = []
        self.mailboxes = {
            "jo@acme.example": {"DisplayName": "Jo Leaver", "PrimarySmtpAddress": "jo@acme.example", "UserPrincipalName": "jo@acme.example",
                                "RecipientTypeDetails": "UserMailbox", "ExternalDirectoryObjectId": USER,
                                "EmailAddresses": ["SMTP:jo@acme.example", "smtp:joanne@acme.example"], "ForwardingSmtpAddress": None,
                                "DeliverToMailboxAndForward": False, "HiddenFromAddressListsEnabled": False},
            "info@acme.example": {"DisplayName": "Info", "PrimarySmtpAddress": "info@acme.example", "UserPrincipalName": "info@acme.example",
                                  "RecipientTypeDetails": "SharedMailbox", "ExternalDirectoryObjectId": "mbx-info",
                                  "EmailAddresses": ["SMTP:info@acme.example"], "ForwardingSmtpAddress": None,
                                  "DeliverToMailboxAndForward": False, "HiddenFromAddressListsEnabled": False},
        }
        self.mailbox_permissions = {"info@acme.example": [{"User": "NT AUTHORITY\\SELF", "AccessRights": ["FullAccess"], "IsInherited": False},
                                                         {"User": "max@acme.example", "AccessRights": ["FullAccess"], "IsInherited": False}]}
        self.inbox_rules = {"jo@acme.example": [{"Identity": "jo@acme.example\\1234", "Name": "Invoices", "Enabled": True,
                                                 "ForwardTo": ["\"x\" [SMTP:attacker@evil.example]"], "DeleteMessage": False}]}
        self.quarantined = [{"Identity": "0b5c6f-abcd-1234\\9a8b7c-ffff", "ReceivedTime": iso(now), "SenderAddress": "boss@supplier.example",
                             "RecipientAddress": ["jo@acme.example"], "Subject": "Invoice", "QuarantineTypes": "HighConfPhish",
                             "ReleaseStatus": "NOTRELEASED"}]

    # --- transport ---
    def client(self, **kwargs):
        return REAL_CLIENT(transport=httpx.MockTransport(self.handle))

    def calls(self, method: str, fragment: str = "") -> list:
        return [r for r in self.requests if r[0] == method and fragment in r[1]]

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": token(self.roles)})
        if request.url.host == "outlook.office365.com":
            return self.exchange(request)
        if request.url.host == "api.partnercenter.microsoft.com":
            self.requests.append((request.method, request.url.path, None))
            return httpx.Response(200, json={})
        path = unquote(request.url.path).removeprefix("/v1.0")
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, path, body))
        for (method, pattern), status in list(self.fail.items()):
            if method == request.method and re.search(pattern, path):
                return httpx.Response(status, json={"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation."}})
        query = {k: v[0] for k, v in parse_qs(urlparse(str(request.url)).query).items()}
        try:
            return self.route(request.method, path, query, body)
        except KeyError:
            return httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound", "message": "Resource not found."}})

    def exchange(self, request: httpx.Request) -> httpx.Response:
        if self.exo_denied:
            return httpx.Response(403, json={"error": {"code": "Forbidden", "message": "The role assigned to application isn't supported in this scenario."}})
        cmd = json.loads(request.content)["CmdletInput"]
        name, p = cmd["CmdletName"], cmd.get("Parameters") or {}
        self.exo_calls.append((name, p))
        mbx = self.mailboxes
        if name in self.exo_lists:
            return httpx.Response(200, json={"value": self.exo_lists[name]})
        if name == "Set-DkimSigningConfig":
            for row in self.exo_lists["Get-DkimSigningConfig"]:
                if row["Domain"] == p["Identity"]:
                    row["Enabled"] = p["Enabled"]
            return httpx.Response(200, json={"value": []})
        if name in self.exo_org:
            return httpx.Response(200, json={"value": [self.exo_org[name]]})
        if name.startswith("Set-") and name.replace("Set-", "Get-", 1) in self.exo_org:
            self.exo_org[name.replace("Set-", "Get-", 1)].update({k: v for k, v in p.items() if k != "Identity"})
            return httpx.Response(200, json={"value": []})
        if name == "Get-Mailbox":
            rows = [mbx[p["Identity"]]] if "Identity" in p else list(mbx.values())
            return httpx.Response(200, json={"value": rows})
        if name == "Get-MailboxPermission":
            return httpx.Response(200, json={"value": self.mailbox_permissions.get(p["Identity"], [])})
        if name == "Get-RecipientPermission":
            return httpx.Response(200, json={"value": [{"Trustee": "max@acme.example", "AccessRights": ["SendAs"]}] if p["Identity"] == "info@acme.example" else []})
        if name == "Get-InboxRule":
            return httpx.Response(200, json={"value": self.inbox_rules.get(p["Mailbox"], [])})
        if name == "Get-QuarantineMessage":
            return httpx.Response(200, json={"value": self.quarantined})
        if name == "Get-MessageTraceV2":
            return httpx.Response(200, json={"value": [{"Received": iso(datetime.now(timezone.utc)), "SenderAddress": p.get("SenderAddress", "a@b.example"),
                                                        "RecipientAddress": p.get("RecipientAddress", "jo@acme.example"), "Subject": "Hello",
                                                        "Status": "Delivered", "Size": 1024, "MessageId": "<m1@x>"}]})
        if name == "Get-DistributionGroup":
            return httpx.Response(200, json={"value": [{"DisplayName": "Newsletter", "PrimarySmtpAddress": "news@acme.example",
                                                        "RecipientTypeDetails": "MailUniversalDistributionGroup", "ExternalDirectoryObjectId": DL}]})
        if name == "Set-Mailbox":
            box = mbx[p["Identity"]]
            if p.get("Type") == "Shared":
                box["RecipientTypeDetails"] = "SharedMailbox"
            if "ForwardingSmtpAddress" in p:
                box["ForwardingSmtpAddress"], box["DeliverToMailboxAndForward"] = p["ForwardingSmtpAddress"], p.get("DeliverToMailboxAndForward")
            if "EmailAddresses" in p:
                for a in p["EmailAddresses"].get("add", []):
                    box["EmailAddresses"].append(a)
            return httpx.Response(200, json={"value": []})
        if name == "Add-MailboxPermission":
            self.mailbox_permissions.setdefault(p["Identity"], []).append({"User": p["User"], "AccessRights": p["AccessRights"], "IsInherited": False})
            return httpx.Response(200, json={"value": []})
        if name == "Release-QuarantineMessage":
            for q in self.quarantined:
                if q["Identity"] == p["Identity"]:
                    q["ReleaseStatus"] = "RELEASED"
            return httpx.Response(200, json={"value": []})
        return httpx.Response(200, json={"value": []})

    def page(self, rows):
        return httpx.Response(200, json={"value": rows})

    def route(self, method, path, query, body):
        m = re.fullmatch
        if path == "/groups" and "resourceProvisioningOptions" in query.get("$filter", ""):
            return self.page([{"id": GROUP, "displayName": "Sales team", "visibility": "Private"},
                              {"id": DL, "displayName": "Orphan team", "visibility": "Public"}])
        if path == "/deviceManagement/managedDevices" and method == "GET":
            return self.page(list(self.managed.values()))
        hit = m(r"/deviceManagement/managedDevices/([0-9a-f-]+)(?:/(\w+))?", path)
        if hit:
            device = self.managed[hit.group(1)]
            if hit.group(2) and method == "POST":
                self.device_actions.append((hit.group(1), hit.group(2)))
                return httpx.Response(204)
            return httpx.Response(200, json=device)
        if path == "/informationProtection/bitlocker/recoveryKeys":
            wanted = re.search(r"deviceId eq '([0-9a-f-]+)'", query.get("$filter", ""))
            return self.page([{k: v for k, v in b.items() if k != "key"} for b in self.bitlocker.values()
                              if not wanted or b["deviceId"] == wanted.group(1)])
        hit = m(r"/informationProtection/bitlocker/recoveryKeys/([\w-]+)", path)
        if hit:
            return httpx.Response(200, json=self.bitlocker[hit.group(1)])
        hit = m(r"/directory/deviceLocalCredentials/([0-9a-f-]+)", path)
        if hit:
            return httpx.Response(200, json=self.laps[hit.group(1)])
        if path in ("/deviceManagement/deviceCompliancePolicies", "/deviceManagement/deviceConfigurations"):
            return self.page([{"@odata.type": "#microsoft.graph.windows10CompliancePolicy", "id": "pol-1", "displayName": "Windows baseline",
                               "assignments": [{}]}] if "Compliance" in path else [])
        if path == "/deviceAppManagement/mobileApps":
            return self.page(list(self.mobile_apps.values()))
        hit = m(r"/deviceAppManagement/mobileApps/([0-9a-f-]+)(/assign)?", path)
        if hit:
            app = self.mobile_apps[hit.group(1)]
            if hit.group(2):
                app["assignments"] = [{"intent": a["intent"], "target": a["target"]} for a in body["mobileAppAssignments"]]
                return httpx.Response(204)
            return httpx.Response(200, json=app)
        if path == "/deviceManagement/windowsAutopilotDeviceIdentities":
            return self.page([{"id": "ap-1", "serialNumber": "SN1", "model": "Surface", "deploymentProfileAssignmentStatus": "assigned"}])
        if path == "/deviceManagement/importedWindowsAutopilotDeviceIdentities" and method == "POST":
            self.autopilot_imports.append(body)
            return httpx.Response(201, json={"id": "imp-1", **body})
        if path == "/policies/authorizationPolicy":
            if method == "PATCH":
                for key, value in body.items():
                    if isinstance(value, dict):
                        self.authz.setdefault(key, {}).update(value)
                    else:
                        self.authz[key] = value
                return httpx.Response(204)
            return httpx.Response(200, json=self.authz)
        if path == "/reports/authenticationMethods/userRegistrationDetails":
            return self.page([{"userPrincipalName": "jo@acme.example", "userDisplayName": "Jo Leaver", "isAdmin": False, "isMfaRegistered": True,
                               "methodsRegistered": ["microsoftAuthenticatorPush"], "userType": "member"},
                              {"userPrincipalName": "max@acme.example", "userDisplayName": "Max Manager", "isAdmin": True, "isMfaRegistered": False,
                               "methodsRegistered": [], "userType": "member"}])
        if path.startswith("/reports/getMailboxUsageDetail"):
            return httpx.Response(200, content=("\ufeffReport Refresh Date,User Principal Name,Display Name,Is Deleted,Item Count,"
                                                "Storage Used (Byte),Issue Warning Quota (Byte),Last Activity Date\n"
                                                "2026-11-01,jo@acme.example,Jo Leaver,False,1200,47000000000,49392123904,2026-10-31\n").encode("utf-8"))
        if path.startswith("/reports/getOneDriveUsageAccountDetail"):
            return httpx.Response(200, content=("Report Refresh Date,Owner Display Name,Owner Principal Name,Is Deleted,File Count,"
                                                "Storage Used (Byte),Last Activity Date\n2026-11-01,Jo Leaver,jo@acme.example,False,300,2147483648,2026-10-30\n").encode())
        if method == "GET" and path == "/users":
            flt = query.get("$filter", "")
            if flt.startswith("userType eq 'Guest'"):
                return self.page([{"displayName": "Gus Guest", "mail": "gus@partner.example", "createdDateTime": "2025-01-01T00:00:00Z",
                                   "externalUserState": "Accepted", "signInActivity": {"lastSignInDateTime": "2025-02-01T00:00:00Z"}}])
            if flt.startswith("mail eq"):
                mail = flt.split("'")[1]
                return self.page([u for u in self.users.values() if u.get("mail") == mail])
            return self.page([{k: v for k, v in u.items()} for u in self.users.values()])
        if method == "POST" and path == "/users":
            ident = str(uuid.uuid4())
            self.users[ident] = {"id": ident, **{k: v for k, v in body.items() if k != "passwordProfile"}, "userType": "Member",
                                 "assignedLicenses": [], "passwordSet": body["passwordProfile"]["password"]}
            return httpx.Response(201, json={"id": ident, "displayName": body["displayName"]})
        if r := m(r"/users/([^/]+)", path):
            user = self._user(r.group(1))
            if method == "GET":
                return httpx.Response(200, json=user)
            if method == "PATCH":
                if "passwordProfile" in body:
                    user["passwordSet"] = body["passwordProfile"]["password"]
                user.update({k: v for k, v in body.items() if k != "passwordProfile"})
                return httpx.Response(204)
        if r := m(r"/users/([^/]+)/revokeSignInSessions", path):
            self._user(r.group(1))
            return httpx.Response(200, json={"value": True})
        if r := m(r"/users/([^/]+)/assignLicense", path):
            user = self._user(r.group(1))
            keep = [l for l in user["assignedLicenses"] if l["skuId"] not in body["removeLicenses"]]
            user["assignedLicenses"] = keep + [{"skuId": a["skuId"]} for a in body["addLicenses"]]
            return httpx.Response(200, json=user)
        if r := m(r"/users/([^/]+)/authentication/methods", path):
            return self.page(self.methods.get(self._user(r.group(1))["id"], []))
        if r := m(r"/users/([^/]+)/authentication/temporaryAccessPassMethods", path):
            self._user(r.group(1))
            return httpx.Response(201, json={"temporaryAccessPass": "TAP-SECRET-4711", "lifetimeInMinutes": body["lifetimeInMinutes"],
                                             "isUsableOnce": body["isUsableOnce"], "startDateTime": iso(datetime.now(timezone.utc))})
        if (r := m(r"/users/([^/]+)/authentication/(\w+)/([^/]+)", path)) and method == "DELETE":
            methods = self.methods.get(r.group(1), [])
            found = [x for x in methods if x["id"] == r.group(3)]
            if not found:
                raise KeyError
            methods.remove(found[0])
            return httpx.Response(204)
        if r := m(r"/users/([^/]+)/manager/\$ref", path):
            self._user(r.group(1))["manager"] = body["@odata.id"].rsplit("/", 1)[-1]
            return httpx.Response(204)
        if r := m(r"/users/([^/]+)/mailboxSettings", path):
            self._user(r.group(1))["automaticReplies"] = body["automaticRepliesSetting"]
            return httpx.Response(200, json=body)
        if r := m(r"/users/([^/]+)/memberOf/microsoft.graph.group", path):
            uid = self._user(r.group(1))["id"]
            return self.page([{k: v for k, v in g.items() if k != "members"} for g in self.groups.values() if uid in g["members"]])
        if method == "GET" and path == "/groups":
            flt = query.get("$filter", "")
            if flt.startswith("mailNickname eq"):
                nick = flt.split("'")[1]
                return self.page([{"id": g["id"]} for g in self.groups.values() if g["mailNickname"] == nick])
            return self.page([{k: v for k, v in g.items() if k != "members"} for g in self.groups.values()])
        if method == "POST" and path == "/groups":
            ident = str(uuid.uuid4())
            self.groups[ident] = {**body, "id": ident, "members": set()}
            return httpx.Response(201, json={"id": ident, "displayName": body["displayName"]})
        if r := m(r"/groups/([^/]+)", path):
            g = self.groups[r.group(1)]
            return httpx.Response(200, json={k: v for k, v in g.items() if k != "members"})
        if r := m(r"/groups/([^/]+)/members/\$ref", path):
            uid = body["@odata.id"].rsplit("/", 1)[-1]
            group = self.groups[r.group(1)]
            if uid in group["members"]:
                return httpx.Response(400, json={"error": {"code": "Request_BadRequest", "message": "One or more added object references already exist"}})
            group["members"].add(uid)
            return httpx.Response(204)
        if r := m(r"/groups/([^/]+)/members/([^/]+)/\$ref", path):
            members = self.groups[r.group(1)]["members"]
            if r.group(2) not in members:
                raise KeyError
            members.discard(r.group(2))
            return httpx.Response(204)
        if r := m(r"/groups/([^/]+)/members", path):
            return self.page([{"id": u} for u in self.groups[r.group(1)]["members"]])
        if path == "/subscribedSkus":
            return self.page([{"skuId": SKU, "skuPartNumber": "O365_BUSINESS_PREMIUM", "prepaidUnits": {"enabled": 10}, "consumedUnits": 1}])
        if r := m(r"/groups/([^/]+)/owners", path):
            return self.page([{"id": MANAGER, "userPrincipalName": "max@acme.example"}] if r.group(1) == GROUP else [])
        if path == "/admin/sharepoint/settings":
            if method == "PATCH":
                self.sharepoint.update(body)
                return httpx.Response(200, json=self.sharepoint)
            return httpx.Response(200, json=self.sharepoint)
        if path.startswith("/reports/getSharePointSiteUsageDetail"):
            return httpx.Response(200, content=("Report Refresh Date,Site Id,Site URL,Owner Display Name,Is Deleted,File Count,Active File Count,"
                                                "Storage Used (Byte),Last Activity Date,Root Web Template\n2026-11-01,s1,https://acme.sharepoint.com/sites/sales,"
                                                "Max Manager,False,500,20,5368709120,2026-10-30,Team Site\n").encode())
        if r := m(r"/users/([^/]+)/drive/root/invite", path):
            self.onedrive_shares.append((r.group(1), body))
            return httpx.Response(200, json={"value": [{"link": {"webUrl": "https://acme-my.sharepoint.com/personal/jo"}}]})
        if path == "/domains" and method == "GET":
            return self.page([{"id": "acme.example", "isVerified": True, "supportedServices": ["Email"]},
                              {"id": "acme.onmicrosoft.com", "isVerified": True, "supportedServices": ["Email"]}])
        if r := m(r"/domains/([^/]+)", path):
            if r.group(1) != "acme.example":
                raise KeyError
            return httpx.Response(200, json={"id": "acme.example", "isVerified": True, "authenticationType": "Managed"})
        if path == "/roleManagement/directory/roleAssignments":
            if method == "POST":
                ident = "ra-" + uuid.uuid4().hex[:8]
                self.assignments[ident] = {"id": ident, **body}
                return httpx.Response(201, json=self.assignments[ident])
            flt = query.get("$filter", "")
            principal = re.search(r"principalId eq '([^']+)'", flt).group(1)
            role = re.search(r"roleDefinitionId eq '([^']+)'", flt)
            rows = [dict(a, roleDefinition={"displayName": "Helpdesk Administrator" if a["roleDefinitionId"] == HELPDESK else "Global Administrator"})
                    for a in self.assignments.values() if a["principalId"] == principal and (not role or a["roleDefinitionId"] == role.group(1))]
            return self.page(rows)
        if (r := m(r"/roleManagement/directory/roleAssignments/([^/]+)", path)) and method == "DELETE":
            del self.assignments[r.group(1)]
            return httpx.Response(204)
        if method == "POST" and path == "/invitations":
            ident = str(uuid.uuid4())
            self.users[ident] = {"id": ident, "mail": body["invitedUserEmailAddress"], "userType": "Guest", "userPrincipalName": "guest#EXT#"}
            return httpx.Response(201, json={"invitedUser": {"id": ident}, "inviteRedeemUrl": "https://invitations.microsoft.com/redeem/x"})
        if path in ("/auditLogs/signIns", "/auditLogs/directoryAudits"):
            if not self.premium and path.endswith("signIns"):
                return httpx.Response(403, json={"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                                                           "message": "Tenant does not have a premium license"}})
            rows, field = (self.signins, "createdDateTime") if path.endswith("signIns") else (self.audits, "activityDateTime")
            flt = query.get("$filter", "")
            start = re.search(r"ge (\S+)", flt).group(1)
            end = re.search(r"lt (\S+)", flt)
            chosen = sorted([x for x in rows if x[field] >= start and (not end or x[field] < end.group(1))], key=lambda x: x[field], reverse=True)
            size = int(query.get("$top", 1000))
            skip = int(query.get("$skiptoken", 0))
            out = {"value": chosen[skip:skip + size]}
            if skip + size < len(chosen):
                out["@odata.nextLink"] = f"https://graph.microsoft.com/v1.0{path}?$filter={flt}&$top={size}&$skiptoken={skip + size}"
            return httpx.Response(200, json=out)
        if path == "/directoryRoles":
            return self.page([{"id": "dr1", "displayName": "Global Administrator", "roleTemplateId": GLOBAL_ADMIN,
                               "members": [{"@odata.type": "#microsoft.graph.user", "id": MANAGER, "displayName": "Max Manager",
                                            "userPrincipalName": "max@acme.example"}]}])
        if path == "/admin/serviceAnnouncement/issues":
            return self.page([{"id": "EX1", "title": "Mail delays", "service": "Exchange Online", "status": "serviceDegradation",
                               "classification": "incident", "secret": "dropped"}])
        if path == "/organization":
            return self.page([{"id": "org", "displayName": "Acme Ltd", "countryLetterCode": "GB"}])
        if method == "GET":
            return self.page([])
        raise KeyError

    def _user(self, ident):
        if ident in self.users:
            return self.users[ident]
        for u in self.users.values():
            if u.get("userPrincipalName") == ident:
                return u
        raise KeyError
