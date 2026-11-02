"""Intune (Microsoft Endpoint Manager) for a Microsoft 365 connection, through Microsoft Graph.

* Managed devices (Windows, macOS, iOS/iPadOS, Android) with compliance state, and device actions: sync, restart,
  Defender quick scan and definition update, remote lock, locate, retire and wipe. Wipe and retire are destructive:
  the router asks for re-authentication (and the customer's approval rule, if any) first.
* BitLocker recovery keys and Windows LAPS passwords, revealed one at a time after re-authentication, audited and
  never stored by Fenrir.
* Compliance policies and configuration profiles, with their assignment counts.
* Apps, and assigning one to a group (required or available) or to all devices, keeping existing assignments.
* Autopilot devices, and importing hardware hashes (the CSV that Get-WindowsAutopilotInfo writes).

Permissions (app connection): DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementManagedDevices.PrivilegedOperations.All
(wipe, retire, lock), DeviceManagementConfiguration.Read.All, DeviceManagementApps.ReadWrite.All,
DeviceManagementServiceConfig.ReadWrite.All (Autopilot), BitlockerKey.Read.All, DeviceLocalCredential.Read.All. The
error from Microsoft names whichever is missing.
"""
from __future__ import annotations

import base64
import csv
import io
import re
from uuid import UUID

import httpx

from . import m365
from .m365_admin import microsoft_said, session

DEVICE_FIELDS = ("id,deviceName,userPrincipalName,userDisplayName,operatingSystem,osVersion,complianceState,lastSyncDateTime,"
                 "managementAgent,managedDeviceOwnerType,model,manufacturer,serialNumber,isEncrypted,azureADDeviceId,enrolledDateTime,"
                 "jailBroken,totalStorageSpaceInBytes,freeStorageSpaceInBytes")
# Fenrir action -> (Graph action, description, destructive, platforms or None for all)
ACTIONS = {
    "sync": ("syncDevice", "Sync with Intune now", False, None),
    "restart": ("rebootNow", "Restart the device", False, ("windows",)),
    "defender_scan": ("windowsDefenderScan", "Run a Defender quick scan", False, ("windows",)),
    "defender_update": ("windowsDefenderUpdateSignatures", "Update Defender's definitions", False, ("windows",)),
    "lock": ("remoteLock", "Lock the device", True, ("ios", "ipados", "android", "macos")),
    "locate": ("locateDevice", "Locate the device", False, ("ios", "ipados", "android", "windows")),
    "retire": ("retire", "Retire: remove company data and management, keep personal data", True, None),
    "wipe": ("wipe", "Wipe: factory reset the device", True, None),
}


class IntuneError(Exception):
    pass


def _get(client, headers, path):
    response = client.get(m365.GRAPH + path, headers=headers)
    if response.status_code >= 400:
        raise IntuneError(_refused(response))
    return response.json()


def _all(client, headers, path, limit: int = 5000) -> list[dict]:
    rows, url = [], m365.GRAPH + path
    while url and len(rows) < limit:
        response = client.get(url, headers=headers)
        if response.status_code >= 400:
            raise IntuneError(_refused(response))
        data = response.json()
        rows += data.get("value") or []
        url = data.get("@odata.nextLink")
    return rows


def _refused(response: httpx.Response) -> str:
    if response.status_code in (401, 403):
        return ("Microsoft refused: the connection needs the Intune permission for this (see Microsoft 365 > Permissions), "
                "and the tenant needs Intune licences." + microsoft_said(response))
    if response.status_code == 400 and "MDM" in response.text:
        return "This tenant has no Intune (MDM authority is not set)." + microsoft_said(response)
    return f"Microsoft refused the request (HTTP {response.status_code})." + microsoft_said(response)


def _platform(device: dict) -> str:
    return str(device.get("operatingSystem") or "").lower().replace(" ", "")


def _device(row: dict) -> dict:
    total, free = row.get("totalStorageSpaceInBytes") or 0, row.get("freeStorageSpaceInBytes") or 0
    return {"id": row.get("id"), "name": row.get("deviceName"), "user": row.get("userPrincipalName"), "userName": row.get("userDisplayName"),
            "os": row.get("operatingSystem"), "osVersion": row.get("osVersion"), "compliance": row.get("complianceState"),
            "lastSync": row.get("lastSyncDateTime"), "owner": row.get("managedDeviceOwnerType"), "model": row.get("model"),
            "manufacturer": row.get("manufacturer"), "serial": row.get("serialNumber"), "encrypted": row.get("isEncrypted"),
            "entraDeviceId": row.get("azureADDeviceId"), "enrolled": row.get("enrolledDateTime"), "jailbroken": row.get("jailBroken"),
            "storageFreePercent": round(100 * free / total) if total else None,
            "actions": [k for k, (_, _, _, platforms) in ACTIONS.items() if platforms is None or _platform(row) in platforms]}


def devices(connection) -> list[dict]:
    with session(connection) as (client, headers):
        rows = _all(client, headers, f"/deviceManagement/managedDevices?$select={DEVICE_FIELDS}&$top=999")
    return sorted((_device(r) for r in rows), key=lambda d: (d["compliance"] == "compliant", str(d["name"]).lower()))


def device_action(connection, device_id: str, action: str) -> str:
    if action not in ACTIONS:
        raise IntuneError("Unknown device action.")
    graph_action, description, _, platforms = ACTIONS[action]
    device_id = str(UUID(device_id))
    with session(connection) as (client, headers):
        row = _get(client, headers, f"/deviceManagement/managedDevices/{device_id}?$select=id,deviceName,operatingSystem")
        if platforms is not None and _platform(row) not in platforms:
            raise IntuneError(f"'{description}' is not available for {row.get('operatingSystem')} devices.")
        body = {"keepEnrollmentData": False, "keepUserData": False} if action == "wipe" else \
               {"quickScan": True} if action == "defender_scan" else None
        response = client.post(m365.GRAPH + f"/deviceManagement/managedDevices/{device_id}/{graph_action}", headers=headers,
                               **({"json": body} if body is not None else {}))
        if response.status_code >= 400:
            raise IntuneError(_refused(response))
    return f"{description}: sent to {row.get('deviceName')}. The device acts on it when it next checks in with Intune."


def bitlocker_keys(connection, device_id: str) -> list[dict]:
    """The recovery keys for one managed device (Graph returns a key only when asked for it by ID)."""
    device_id = str(UUID(device_id))
    with session(connection) as (client, headers):
        row = _get(client, headers, f"/deviceManagement/managedDevices/{device_id}?$select=id,deviceName,azureADDeviceId")
        entra = row.get("azureADDeviceId")
        if not entra:
            raise IntuneError("This device is not joined to Entra ID, so Microsoft holds no BitLocker key for it.")
        listed = _all(client, headers, f"/informationProtection/bitlocker/recoveryKeys?$filter=deviceId eq '{UUID(entra)}'")
        keys = []
        for item in listed[:10]:
            full = _get(client, headers, f"/informationProtection/bitlocker/recoveryKeys/{quote_id(item['id'])}?$select=key,volumeType,createdDateTime")
            keys.append({"id": item["id"], "volume": full.get("volumeType"), "created": full.get("createdDateTime"), "key": full.get("key")})
    if not keys:
        raise IntuneError("Microsoft holds no BitLocker recovery key for this device (BitLocker off, or the key was never backed up to Entra ID).")
    return keys


def laps_password(connection, device_id: str) -> dict:
    """The current Windows LAPS password for a managed device (Entra-backed LAPS)."""
    device_id = str(UUID(device_id))
    with session(connection) as (client, headers):
        row = _get(client, headers, f"/deviceManagement/managedDevices/{device_id}?$select=id,deviceName,azureADDeviceId")
        entra = row.get("azureADDeviceId")
        if not entra:
            raise IntuneError("This device is not joined to Entra ID.")
        response = client.get(m365.GRAPH + f"/directory/deviceLocalCredentials/{UUID(entra)}?$select=credentials,deviceName,lastBackupDateTime",
                              headers={**headers, "ocp-client-name": "Fenrir", "ocp-client-version": "1.0"})
        if response.status_code == 404:
            raise IntuneError("No LAPS password is backed up to Entra ID for this device (Windows LAPS is not configured for it).")
        if response.status_code >= 400:
            raise IntuneError(_refused(response))
        data = response.json()
    creds = sorted(data.get("credentials") or [], key=lambda c: str(c.get("backupDateTime") or ""), reverse=True)
    if not creds:
        raise IntuneError("No LAPS password is backed up for this device.")
    latest = creds[0]
    password = base64.b64decode(latest.get("passwordBase64") or "").decode("utf-8", errors="replace")
    return {"account": latest.get("accountName"), "password": password, "backedUp": latest.get("backupDateTime")}


def quote_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", str(value)):
        raise IntuneError("Invalid identifier.")
    return value


def policies(connection) -> dict:
    with session(connection) as (client, headers):
        compliance = _all(client, headers, "/deviceManagement/deviceCompliancePolicies?$expand=assignments")
        configurations = _all(client, headers, "/deviceManagement/deviceConfigurations?$expand=assignments")
    shape = lambda p: {"id": p.get("id"), "name": p.get("displayName"), "type": str(p.get("@odata.type", "")).split(".")[-1],
                       "modified": p.get("lastModifiedDateTime"), "assignments": len(p.get("assignments") or [])}
    return {"compliance": [shape(p) for p in compliance], "configuration": [shape(p) for p in configurations]}


def apps(connection) -> list[dict]:
    with session(connection) as (client, headers):
        rows = _all(client, headers, "/deviceAppManagement/mobileApps?$expand=assignments&$top=999")
    out = []
    for app in rows:
        kind = str(app.get("@odata.type", "")).split(".")[-1]
        if kind in ("managedAndroidLobApp", "managedIOSLobApp") or "Bundle" in kind:
            continue
        out.append({"id": app.get("id"), "name": app.get("displayName"), "publisher": app.get("publisher"), "type": kind,
                    "assignments": [{"intent": a.get("intent"), "target": _target_label(a.get("target") or {})} for a in app.get("assignments") or []]})
    return sorted(out, key=lambda a: str(a["name"]).lower())


def _target_label(target: dict) -> str:
    kind = str(target.get("@odata.type", ""))
    if kind.endswith("allDevicesAssignmentTarget"):
        return "All devices"
    if kind.endswith("allLicensedUsersAssignmentTarget"):
        return "All users"
    return "Group " + str(target.get("groupId") or "")


def assign_app(connection, app_id: str, intent: str, group_id: str | None) -> str:
    """Add one assignment, keeping the app's existing ones (Graph's assign replaces the whole list)."""
    if intent not in ("required", "available", "uninstall"):
        raise IntuneError("Intent is required, available or uninstall.")
    app_id = str(UUID(app_id))
    target = ({"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": str(UUID(group_id))} if group_id
              else {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"})
    if intent == "available" and not group_id:
        raise IntuneError("'Available' needs a user group (Company Portal offers it to the group's users).")
    with session(connection) as (client, headers):
        app = _get(client, headers, f"/deviceAppManagement/mobileApps/{app_id}?$expand=assignments")
        existing = [{"@odata.type": "#microsoft.graph.mobileAppAssignment", "intent": a.get("intent"), "target": a.get("target"),
                     **({"settings": a["settings"]} if a.get("settings") else {})} for a in app.get("assignments") or []]
        if any((a["target"] or {}).get("groupId") == target.get("groupId") and (a["target"] or {}).get("@odata.type") == target["@odata.type"]
               for a in existing):
            raise IntuneError("The app is already assigned to that target; change or remove that assignment in Intune.")
        response = client.post(m365.GRAPH + f"/deviceAppManagement/mobileApps/{app_id}/assign", headers=headers,
                               json={"mobileAppAssignments": existing + [{"@odata.type": "#microsoft.graph.mobileAppAssignment",
                                                                          "intent": intent, "target": target}]})
        if response.status_code >= 400:
            raise IntuneError(_refused(response))
    return f"{app.get('displayName')} assigned as {intent} to {_target_label(target)}"


def autopilot(connection) -> list[dict]:
    with session(connection) as (client, headers):
        rows = _all(client, headers, "/deviceManagement/windowsAutopilotDeviceIdentities")
    return [{"id": r.get("id"), "serial": r.get("serialNumber"), "model": r.get("model"), "manufacturer": r.get("manufacturer"),
             "groupTag": r.get("groupTag"), "profileStatus": r.get("deploymentProfileAssignmentStatus"),
             "enrollmentState": r.get("enrollmentState"), "lastContacted": r.get("lastContactedDateTime")} for r in rows]


def parse_hashes(text: str) -> list[dict]:
    """Rows from Get-WindowsAutopilotInfo's CSV (Device Serial Number, Windows Product ID, Hardware Hash[, Group Tag])."""
    reader = csv.DictReader(io.StringIO(text.strip()))
    out = []
    for row in reader:
        row = {str(k or "").strip().lower(): str(v or "").strip() for k, v in row.items()}
        serial, hardware = row.get("device serial number"), row.get("hardware hash")
        if not serial or not hardware:
            continue
        try:
            base64.b64decode(hardware, validate=True)
        except ValueError:
            raise IntuneError(f"The hardware hash for {serial} is not valid.") from None
        out.append({"serialNumber": serial[:100], "productKey": row.get("windows product id", "")[:100],
                    "hardwareIdentifier": hardware, "groupTag": (row.get("group tag") or "")[:100]})
    if not out:
        raise IntuneError("No devices found: paste the CSV that Get-WindowsAutopilotInfo writes (with its header row).")
    if len(out) > 500:
        raise IntuneError("At most 500 devices per import.")
    return out


def import_autopilot(connection, text: str, group_tag: str = "") -> dict:
    rows = parse_hashes(text)
    imported, failed = 0, []
    with session(connection) as (client, headers):
        for row in rows:
            body = {"@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity", "serialNumber": row["serialNumber"],
                    "productKey": row["productKey"], "hardwareIdentifier": row["hardwareIdentifier"],
                    "groupTag": group_tag or row["groupTag"], "state": {"deviceImportStatus": "pending"}}
            response = client.post(m365.GRAPH + "/deviceManagement/importedWindowsAutopilotDeviceIdentities", headers=headers, json=body)
            if response.status_code >= 400:
                failed.append({"serial": row["serialNumber"], "error": _refused(response)[:200]})
            else:
                imported += 1
    return {"imported": imported, "failed": failed,
            "message": f"{imported} device(s) sent to Autopilot; Microsoft takes up to 15 minutes to register them."}
