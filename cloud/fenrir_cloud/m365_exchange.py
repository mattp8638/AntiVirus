"""Exchange Online administration (Microsoft 365 batch 3) through Exchange's own admin REST endpoint.

Graph cannot manage most of Exchange: shared mailboxes, mailbox and Send As permissions, forwarding, aliases,
distribution lists, inbox rules, quarantine and message trace. Exchange Online exposes its admin cmdlets over HTTPS
(``/adminapi/beta/{tenant}/InvokeCommand``), the same endpoint CIPP uses. Fenrir calls only the cmdlets listed in
``READS`` and ``WRITES`` below, each with parameters built here from validated input: no cmdlet name or parameter
ever comes from a request.

Access: an app connection needs the "Office 365 Exchange Online" application permission Exchange.ManageAsApp and the
Exchange Administrator role assigned to the app; a partner (GDAP) connection needs the Exchange Administrator role in
the relationship. ``access_error`` turns Microsoft's refusal into those instructions.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from datetime import timedelta

import httpx

from . import m365
from .models import utcnow

EXO_SCOPE = "https://outlook.office365.com/.default"
EXO = "https://outlook.office365.com/adminapi/beta/{tenant}/InvokeCommand"
# Exchange routes admin calls by an anchor mailbox; for app-only access this system mailbox is the documented anchor.
ANCHOR = "APP:SystemMailbox{{bb558c35-97f1-4cb9-8ff7-d53741dc928c}}@{tenant}"
EMAIL = re.compile(r"^[^@\s'\"`;|&$<>(){}]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
MAILBOX_TYPES = {"UserMailbox": "user", "SharedMailbox": "shared", "RoomMailbox": "room", "EquipmentMailbox": "equipment"}
MAX_TRACE_DAYS = 10


class ExchangeError(Exception):
    def __init__(self, message: str, uncertain: bool = False):
        super().__init__(message)
        self.uncertain = uncertain


def address(value: str, what: str = "address") -> str:
    value = str(value or "").strip()
    if not EMAIL.fullmatch(value) or len(value) > 254:
        raise ExchangeError(f"Enter a valid email {what}.")
    return value


def access_error(response: httpx.Response) -> str:
    from .m365_admin import microsoft_said

    said = microsoft_said(response) or f" (HTTP {response.status_code})"
    if response.status_code in (401, 403):
        return ("Exchange refused Fenrir's access. For an app connection, grant the app the 'Office 365 Exchange Online' "
                "application permission Exchange.ManageAsApp (admin consent) and assign the app the Exchange Administrator "
                "role in Entra ID; for a partner connection, include Exchange Administrator in the GDAP relationship."
                + said)
    return "Exchange refused the request." + said


@contextmanager
def session(connection):
    with httpx.Client(timeout=60, follow_redirects=False) as client:
        try:
            token = m365.access_token(client, connection, scope=EXO_SCOPE)
        except httpx.HTTPStatusError as exc:
            raise ExchangeError(access_error(exc.response)) from None
        yield client, token


def invoke(client: httpx.Client, connection, token: str, cmdlet: str, parameters: dict | None = None) -> list[dict]:
    if cmdlet not in READS and cmdlet not in WRITES:
        raise ExchangeError("That Exchange operation is not allowed.")
    tenant = connection.directory_id
    url = EXO.format(tenant=tenant)
    headers = {"Authorization": "Bearer " + token, "X-AnchorMailbox": ANCHOR.format(tenant=tenant),
               "Content-Type": "application/json; charset=utf-8",
               # Exchange's admin endpoint sends compressed replies httpx cannot always decode (DecodingError seen on
               # a live tenant): ask for plain JSON.
               "Accept-Encoding": "identity"}
    body = {"CmdletInput": {"CmdletName": cmdlet, "Parameters": parameters or {}}}
    rows: list[dict] = []
    for _ in range(50):  # pages
        response = client.post(url, headers=headers, json=body)
        if response.status_code >= 400:
            raise ExchangeError(access_error(response), uncertain=cmdlet in WRITES and response.status_code >= 500)
        data = response.json() if response.content else {}
        rows += [r for r in data.get("value") or [] if isinstance(r, dict)]
        url = data.get("@odata.nextLink")
        if not url:
            break
    return rows


# --- reads --------------------------------------------------------------------------------------------------------

READS = {"Get-Mailbox", "Get-MailboxPermission", "Get-RecipientPermission", "Get-InboxRule", "Get-DistributionGroup",
         "Get-DistributionGroupMember", "Get-QuarantineMessage", "Get-MessageTraceV2", "Get-MailboxStatistics",
         # organisation settings read by the standards (m365_standards.py)
         "Get-AdminAuditLogConfig", "Get-OrganizationConfig", "Get-HostedOutboundSpamFilterPolicy", "Get-TransportConfig",
         # email security standards (m365_email_security.py)
         "Get-DkimSigningConfig", "Get-AntiPhishPolicy", "Get-MalwareFilterPolicy", "Get-SafeLinksPolicy", "Get-SafeAttachmentPolicy",
         # Fenrir's mail gateway (mail_gateway.py)
         "Get-InboundConnector"}


def _mailbox(row: dict) -> dict:
    addresses = [str(a) for a in row.get("EmailAddresses") or []]
    return {"id": row.get("ExternalDirectoryObjectId") or row.get("Guid") or row.get("PrimarySmtpAddress"),
            "displayName": row.get("DisplayName"), "address": row.get("PrimarySmtpAddress"),
            "userPrincipalName": row.get("UserPrincipalName"),
            "type": MAILBOX_TYPES.get(str(row.get("RecipientTypeDetails")), str(row.get("RecipientTypeDetails") or "").lower()),
            "aliases": [a[5:] for a in addresses if a.startswith("smtp:")],
            "forwardingTo": (str(row.get("ForwardingSmtpAddress") or "").removeprefix("smtp:") or None),
            "forwardingKeepsCopy": bool(row.get("DeliverToMailboxAndForward")),
            "hiddenFromAddressBook": bool(row.get("HiddenFromAddressListsEnabled")),
            "litigationHold": bool(row.get("LitigationHoldEnabled"))}


def mailboxes(connection) -> list[dict]:
    with session(connection) as (client, token):
        rows = invoke(client, connection, token, "Get-Mailbox", {"ResultSize": "Unlimited"})
    return sorted((_mailbox(r) for r in rows), key=lambda m: (m["type"] != "user", str(m["displayName"]).lower()))


def mailbox_detail(connection, identity: str) -> dict:
    identity = address(identity, "mailbox")
    with session(connection) as (client, token):
        [row] = invoke(client, connection, token, "Get-Mailbox", {"Identity": identity}) or [{}]
        full = invoke(client, connection, token, "Get-MailboxPermission", {"Identity": identity})
        send_as = invoke(client, connection, token, "Get-RecipientPermission", {"Identity": identity})
        rules = invoke(client, connection, token, "Get-InboxRule", {"Mailbox": identity})
    people = lambda u: str(u or "")
    return {
        "mailbox": _mailbox(row) if row else None,
        "fullAccess": sorted({people(p.get("User")) for p in full if "FullAccess" in str(p.get("AccessRights")) and not p.get("IsInherited")
                              and not people(p.get("User")).startswith(("NT AUTHORITY", "S-1-5"))}),
        "sendAs": sorted({people(p.get("Trustee")) for p in send_as if "SendAs" in str(p.get("AccessRights"))
                          and not people(p.get("Trustee")).startswith(("NT AUTHORITY", "S-1-5"))}),
        "rules": [inbox_rule(r) for r in rules],
    }


def inbox_rule(row: dict) -> dict:
    forwards = [str(x) for key in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo") for x in (row.get(key) or [])]
    moves_away = str(row.get("MoveToFolder") or "").lower() in ("rss feeds", "rss subscriptions", "conversation history", "archive")
    deletes = bool(row.get("DeleteMessage"))
    suspicious = []
    if forwards:
        suspicious.append("forwards mail to " + ", ".join(forwards[:3]))
    if deletes or moves_away:
        suspicious.append("hides mail from the user" if moves_away else "deletes mail")
    return {"id": row.get("Identity") or row.get("RuleIdentity"), "name": row.get("Name"), "enabled": bool(row.get("Enabled")),
            "description": str(row.get("Description") or "")[:500], "forwardsTo": forwards, "suspicious": suspicious}


def distribution_groups(connection) -> list[dict]:
    with session(connection) as (client, token):
        rows = invoke(client, connection, token, "Get-DistributionGroup", {"ResultSize": "Unlimited"})
    return sorted(({"id": r.get("ExternalDirectoryObjectId") or r.get("Guid"), "displayName": r.get("DisplayName"),
                    "address": r.get("PrimarySmtpAddress"), "type": str(r.get("RecipientTypeDetails") or ""),
                    "external": not bool(r.get("RequireSenderAuthenticationEnabled", True))} for r in rows),
                  key=lambda g: str(g["displayName"]).lower())


def group_members(connection, group: str) -> list[dict]:
    group = address(group, "group address")
    with session(connection) as (client, token):
        rows = invoke(client, connection, token, "Get-DistributionGroupMember", {"Identity": group, "ResultSize": "Unlimited"})
    return [{"displayName": r.get("DisplayName"), "address": r.get("PrimarySmtpAddress"), "type": r.get("RecipientType")} for r in rows]


def quarantine(connection) -> list[dict]:
    with session(connection) as (client, token):
        rows = invoke(client, connection, token, "Get-QuarantineMessage", {"PageSize": 200})
    return [{"id": r.get("Identity"), "received": r.get("ReceivedTime"), "sender": r.get("SenderAddress"),
             "recipients": r.get("RecipientAddress") or [], "subject": r.get("Subject"), "type": r.get("QuarantineTypes") or r.get("Type"),
             "released": bool(r.get("Released") or r.get("ReleaseStatus") == "RELEASED"), "expires": r.get("Expires")} for r in rows]


def message_trace(connection, sender: str = "", recipient: str = "", days: int = 2) -> list[dict]:
    days = max(1, min(int(days or 2), MAX_TRACE_DAYS))
    params: dict = {"StartDate": (utcnow() - timedelta(days=days)).isoformat() + "Z", "EndDate": utcnow().isoformat() + "Z",
                    "ResultSize": 1000}
    if sender:
        params["SenderAddress"] = address(sender, "sender address")
    if recipient:
        params["RecipientAddress"] = address(recipient, "recipient address")
    if not sender and not recipient:
        raise ExchangeError("Trace by a sender or a recipient address.")
    with session(connection) as (client, token):
        rows = invoke(client, connection, token, "Get-MessageTraceV2", params)
    return [{"received": r.get("Received"), "sender": r.get("SenderAddress"), "recipient": r.get("RecipientAddress"),
             "subject": r.get("Subject"), "status": r.get("Status"), "size": r.get("Size"), "messageId": r.get("MessageId")} for r in rows]


# --- writes -------------------------------------------------------------------------------------------------------

WRITES = {"Set-Mailbox", "Add-MailboxPermission", "Remove-MailboxPermission", "Add-RecipientPermission", "Remove-RecipientPermission",
          "Add-DistributionGroupMember", "Remove-DistributionGroupMember", "Release-QuarantineMessage", "Disable-InboxRule",
          # organisation settings applied by the standards (m365_standards.py)
          "Set-AdminAuditLogConfig", "Set-OrganizationConfig", "Set-HostedOutboundSpamFilterPolicy", "Set-TransportConfig",
          "Set-DkimSigningConfig", "Set-AntiPhishPolicy", "Set-MalwareFilterPolicy",
          # the inbound connector for Fenrir's mail gateway (mail_gateway.connect_m365)
          "New-InboundConnector", "Set-InboundConnector"}

# operation -> (title, what it needs from the request)
OPERATIONS = {
    "mailbox.convert": "Convert a mailbox to shared or back to a user mailbox",
    "mailbox.full_access": "Give or remove full access to a mailbox",
    "mailbox.send_as": "Give or remove Send As on a mailbox",
    "mailbox.forwarding": "Set or clear mail forwarding",
    "mailbox.alias": "Add or remove an email alias",
    "mailbox.hide": "Hide from or show in the address book",
    "dl.member": "Add or remove a distribution list member",
    "quarantine.release": "Release a quarantined message to its recipients",
    "inbox_rule.disable": "Turn off an inbox rule",
}


def plan(operation: str, parameters: dict) -> tuple[str, dict, str]:
    """(cmdlet, Exchange parameters, human description) for an allowlisted operation. Raises ExchangeError."""
    p = parameters or {}
    if operation not in OPERATIONS:
        raise ExchangeError("Unknown Exchange operation.")
    if operation == "quarantine.release":
        identity = str(p.get("messageId") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9\\\-_.@{}\[\]]{8,300}", identity):
            raise ExchangeError("Choose a quarantined message.")
        return "Release-QuarantineMessage", {"Identity": identity, "ReleaseToAll": True}, "Release the message to all its recipients"
    mailbox = address(p.get("mailbox"), "mailbox")
    if operation == "mailbox.convert":
        kind = {"shared": "Shared", "user": "Regular"}.get(str(p.get("to")))
        if not kind:
            raise ExchangeError("Convert to 'shared' or 'user'.")
        return "Set-Mailbox", {"Identity": mailbox, "Type": kind}, f"Convert {mailbox} to a {'shared' if kind == 'Shared' else 'user'} mailbox"
    if operation in ("mailbox.full_access", "mailbox.send_as"):
        user = address(p.get("user"), "user")
        add = bool(p.get("add", True))
        if operation == "mailbox.full_access":
            if add:
                return ("Add-MailboxPermission", {"Identity": mailbox, "User": user, "AccessRights": ["FullAccess"],
                                                  "AutoMapping": bool(p.get("autoMapping", True)), "InheritanceType": "All"},
                        f"Give {user} full access to {mailbox}")
            return ("Remove-MailboxPermission", {"Identity": mailbox, "User": user, "AccessRights": ["FullAccess"],
                                                 "InheritanceType": "All", "Confirm": False}, f"Remove {user}'s full access to {mailbox}")
        if add:
            return ("Add-RecipientPermission", {"Identity": mailbox, "Trustee": user, "AccessRights": ["SendAs"], "Confirm": False},
                    f"Let {user} send as {mailbox}")
        return ("Remove-RecipientPermission", {"Identity": mailbox, "Trustee": user, "AccessRights": ["SendAs"], "Confirm": False},
                f"Stop {user} sending as {mailbox}")
    if operation == "mailbox.forwarding":
        target = str(p.get("to") or "").strip()
        if not target:
            return ("Set-Mailbox", {"Identity": mailbox, "ForwardingSmtpAddress": None, "DeliverToMailboxAndForward": False},
                    f"Stop forwarding {mailbox}")
        target = address(target, "forwarding address")
        keep = bool(p.get("keepCopy", True))
        return ("Set-Mailbox", {"Identity": mailbox, "ForwardingSmtpAddress": "smtp:" + target, "DeliverToMailboxAndForward": keep},
                f"Forward {mailbox} to {target}" + (" and keep a copy" if keep else " without keeping a copy"))
    if operation == "mailbox.alias":
        alias = address(p.get("alias"), "alias")
        add = bool(p.get("add", True))
        return ("Set-Mailbox", {"Identity": mailbox, "EmailAddresses": {"add" if add else "remove": ["smtp:" + alias]}},
                f"{'Add' if add else 'Remove'} the alias {alias} {'to' if add else 'from'} {mailbox}")
    if operation == "mailbox.hide":
        hide = bool(p.get("hide", True))
        return ("Set-Mailbox", {"Identity": mailbox, "HiddenFromAddressListsEnabled": hide},
                f"{'Hide' if hide else 'Show'} {mailbox} {'from' if hide else 'in'} the address book")
    if operation == "dl.member":
        group = address(p.get("group"), "distribution list")
        add = bool(p.get("add", True))
        if add:
            return ("Add-DistributionGroupMember", {"Identity": group, "Member": mailbox, "BypassSecurityGroupManagerCheck": True},
                    f"Add {mailbox} to {group}")
        return ("Remove-DistributionGroupMember", {"Identity": group, "Member": mailbox, "BypassSecurityGroupManagerCheck": True,
                                                   "Confirm": False}, f"Remove {mailbox} from {group}")
    if operation == "inbox_rule.disable":
        rule = str(p.get("ruleId") or "").strip()
        if not rule or len(rule) > 300 or any(c in rule for c in "\"'`;|&$<>"):
            raise ExchangeError("Choose the inbox rule.")
        return "Disable-InboxRule", {"Mailbox": mailbox, "Identity": rule, "Confirm": False}, f"Turn off the inbox rule on {mailbox}"
    raise ExchangeError("Unknown Exchange operation.")


def execute(connection, operation: str, parameters: dict) -> str:
    cmdlet, params, description = plan(operation, parameters)
    with session(connection) as (client, token):
        try:
            invoke(client, connection, token, cmdlet, params)
        except httpx.RequestError:
            raise ExchangeError("Exchange's answer did not arrive; check the mailbox before trying again.", uncertain=True) from None
    return description + ": done"

