"""Teams, SharePoint and OneDrive for a Microsoft 365 connection, through Microsoft Graph.

* Teams with their owners, members and guests; a team with no owner (nobody can manage it) or a single owner is
  flagged.
* SharePoint sites from Microsoft's usage report: storage, files and last activity.
* The tenant's sharing settings, and two standards (m365_standards.py, kind "sharing"): no "Anyone" links (sharing
  limited to people who sign in) and guests cannot reshare.
* OneDrive hand-over for leavers (offboarding step): the leaver's OneDrive is shared with a colleague, who then has
  until the licence's 30-day grace period ends to move what must be kept.
"""
from __future__ import annotations

import csv
import io
from uuid import UUID

import httpx

from . import m365
from .m365_admin import microsoft_said, session

SHARING_LABEL = {"disabled": "Only people in the organisation", "existingExternalUserSharingOnly": "Existing guests only",
                 "externalUserSharingOnly": "New and existing guests (they sign in)",
                 "externalUserAndGuestSharing": "Anyone, including links that need no sign-in"}
STANDARDS = {
    "sharing.no-anyone-links": {"title": "SharePoint and OneDrive: no 'Anyone' links (guests must sign in)",
                                "ok": lambda s: s.get("sharingCapability") != "externalUserAndGuestSharing",
                                "patch": {"sharingCapability": "externalUserSharingOnly"},
                                "why": "files can be shared with links that work for anyone, without signing in"},
    "sharing.no-guest-resharing": {"title": "Guests cannot reshare files they were given",
                                   "ok": lambda s: s.get("isResharingByExternalUsersEnabled") is False,
                                   "patch": {"isResharingByExternalUsersEnabled": False},
                                   "why": "guests can share company files on with other people"},
}


class CollaborationError(Exception):
    pass


def _refused(response: httpx.Response) -> str:
    if response.status_code in (401, 403):
        return ("Microsoft refused: the connection needs Sites.Read.All, SharePointTenantSettings.ReadWrite.All, "
                "Team.ReadBasic.All and Files.ReadWrite.All (Microsoft 365 > Permissions > Update permissions)." + microsoft_said(response))
    return f"Microsoft refused the request (HTTP {response.status_code})." + microsoft_said(response)


def _all(client, headers, path: str, limit: int = 5000) -> list[dict]:
    rows, url = [], m365.GRAPH + path
    while url and len(rows) < limit:
        response = client.get(url, headers=headers)
        if response.status_code >= 400:
            raise CollaborationError(_refused(response))
        data = response.json()
        rows += data.get("value") or []
        url = data.get("@odata.nextLink")
    return rows


def teams(connection) -> list[dict]:
    with session(connection) as (client, headers):
        groups = _all(client, headers, "/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')"
                                       "&$select=id,displayName,visibility,createdDateTime,description&$top=999")
        out = []
        for group in groups[:300]:
            owners = _all(client, headers, f"/groups/{group['id']}/owners?$select=id,displayName,userPrincipalName")
            members = _all(client, headers, f"/groups/{group['id']}/members?$select=id,userType")
            guests = sum(1 for m in members if m.get("userType") == "Guest")
            issue = "no owner: nobody can manage it" if not owners else "one owner" if len(owners) == 1 else ""
            out.append({"id": group["id"], "name": group.get("displayName"), "visibility": group.get("visibility"),
                        "created": group.get("createdDateTime"), "owners": [o.get("userPrincipalName") or o.get("displayName") for o in owners],
                        "members": len(members), "guests": guests, "issue": issue})
    return sorted(out, key=lambda t: (t["issue"] != "no owner: nobody can manage it", t["issue"] == "", str(t["name"]).lower()))


def sites(connection) -> list[dict]:
    with session(connection) as (client, headers):
        response = client.get(m365.GRAPH + "/reports/getSharePointSiteUsageDetail(period='D30')", headers=headers, follow_redirects=True)
        if response.status_code >= 400:
            raise CollaborationError(_refused(response))
    rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig", errors="replace"))))
    out = []
    for r in rows:
        if r.get("Is Deleted") == "True":
            continue
        try:
            used = round(int(r.get("Storage Used (Byte)") or 0) / 1_073_741_824, 2)
        except ValueError:
            used = None
        out.append({"url": r.get("Site URL") or r.get("Site Id"), "owner": r.get("Owner Display Name"), "storageGB": used,
                    "files": r.get("File Count"), "activeFiles": r.get("Active File Count"),
                    "lastActivity": r.get("Last Activity Date") or "never", "template": r.get("Root Web Template")})
    return sorted(out, key=lambda s: -(s["storageGB"] or 0))


def sharing_settings(connection) -> dict:
    with session(connection) as (client, headers):
        response = client.get(m365.GRAPH + "/admin/sharepoint/settings", headers=headers)
        if response.status_code >= 400:
            raise CollaborationError(_refused(response))
        data = response.json()
    return {"sharingCapability": data.get("sharingCapability"), "label": SHARING_LABEL.get(data.get("sharingCapability"), data.get("sharingCapability")),
            "isResharingByExternalUsersEnabled": data.get("isResharingByExternalUsersEnabled"),
            "sharingDomainRestrictionMode": data.get("sharingDomainRestrictionMode"),
            "sharingAllowedDomainList": data.get("sharingAllowedDomainList") or [], "sharingBlockedDomainList": data.get("sharingBlockedDomainList") or []}


def evaluate(connection, standard: str) -> dict:
    entry = STANDARDS[standard]
    current = sharing_settings(connection)
    if entry["ok"](current):
        return {"status": "compliant", "detail": f"{entry['title']} (sharing: {current['label']})."}
    return {"status": "drifted", "detail": f"Not set: {entry['why']} (sharing: {current['label']})."}


def deploy(connection, standard: str) -> dict:
    entry = STANDARDS[standard]
    with session(connection) as (client, headers):
        response = client.patch(m365.GRAPH + "/admin/sharepoint/settings", headers=headers, json=entry["patch"])
        if response.status_code >= 400:
            raise CollaborationError(_refused(response))
    if evaluate(connection, standard)["status"] != "compliant":
        raise CollaborationError("Microsoft accepted the change but the setting still reads as before; check SharePoint admin.")
    return {"action": "updated", "setting": entry["title"]}


def share_onedrive(client, headers, leaver_id: str, delegate: str, leaver_name: str) -> str:
    """Offboarding: give a colleague edit access to the leaver's whole OneDrive. Returns the link."""
    response = client.post(m365.GRAPH + f"/users/{UUID(leaver_id)}/drive/root/invite", headers=headers,
                           json={"requireSignIn": True, "sendInvitation": True, "roles": ["write"], "recipients": [{"email": delegate}],
                                 "message": f"{leaver_name} has left. You have access to their OneDrive to move anything that must be "
                                            "kept: it will be deleted 30 days after their licence is removed."})
    if response.status_code == 404:
        raise CollaborationError("The leaver has no OneDrive (never used, or already deleted).")
    if response.status_code >= 400:
        raise CollaborationError(_refused(response))
    granted = (response.json().get("value") or [{}])[0]
    return (granted.get("link") or {}).get("webUrl") or ""
