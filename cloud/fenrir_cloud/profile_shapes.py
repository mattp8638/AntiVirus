"""The system-profile fields displayed as text, flags, numbers and collections.

Older PowerShell collectors unwrap one-element collections. Repair those known
collections and reject structured values in scalar fields, including stored
profiles, without discarding extension sections such as Active Directory.
"""
from __future__ import annotations

_TEXT = str
_NUMBER = float
_FLAG = bool


def _fields(kind, names: str) -> dict:
    return dict.fromkeys(names.split(), kind)


PROFILE_SHAPE = {
    "hardware": {
        **_fields(_TEXT, "manufacturer model serial chassis biosVersion biosDate"), "secureBoot": _FLAG,
        "cpu": {**_fields(_TEXT, "name"), **_fields(_NUMBER, "cores threads maxMhz")},
        "memory": {**_fields(_NUMBER, "totalGb slotsUsed"), "modules": [{
            **_fields(_TEXT, "slot manufacturer partNumber"), **_fields(_NUMBER, "sizeGb speedMhz")}]},
        "gpus": [{**_fields(_TEXT, "name driverVersion"), "memoryGb": _NUMBER}],
        "tpm": {**_fields(_TEXT, "version manufacturer"), **_fields(_FLAG, "present ready")},
    },
    "os": {**_fields(_TEXT, "name version build displayVersion architecture installDate lastBoot timezone domain joinType activation lastUpdateInstalled"),
           "rebootPending": _FLAG, "rebootReasons": [_TEXT]},
    "disks": [{**_fields(_TEXT, "name model serial mediaType busType health status"),
               **_fields(_NUMBER, "sizeGb temperatureC temperatureMaxC wearPercent powerOnHours readErrors writeErrors startStopCount"), "smartOk": _FLAG}],
    "volumes": [{**_fields(_TEXT, "mount label fileSystem health"), **_fields(_NUMBER, "sizeGb freeGb"), "system": _FLAG,
                 "encryption": {**_fields(_TEXT, "status protection method"), "percent": _NUMBER, "protectors": [_TEXT]}}],
    "users": {"local": [{**_fields(_TEXT, "name fullName lastLogon passwordLastSet passwordExpires description"),
                         **_fields(_FLAG, "enabled admin passwordRequired")}],
              "profiles": [{**_fields(_TEXT, "name sid path lastUse"), "loaded": _FLAG}],
              "sessions": [_fields(_TEXT, "user session state idle logonTime")], "administratorsGroup": [_TEXT]},
    "network": {"adapters": [{**_fields(_TEXT, "name description mac status speed dhcp wifiSsid"),
                              **{key: [_TEXT] for key in ("ipv4", "ipv6", "gateway", "dns")}}]},
    "battery": {"present": _FLAG, "status": _TEXT,
                **_fields(_NUMBER, "chargePercent designCapacity fullChargeCapacity cycleCount healthPercent")},
    "security": {"antivirus": [{"name": _TEXT, **_fields(_FLAG, "enabled upToDate")}],
                 "defender": {**_fields(_FLAG, "realtime tamperProtection passive"), "signatureAgeDays": _NUMBER},
                 "firewall": [{"profile": _TEXT, "enabled": _FLAG}],
                 **_fields(_FLAG, "uac rdpEnabled smb1 lsaProtection apparmor gatekeeper sip"), **_fields(_TEXT, "sshRootLogin selinux")},
    "events": {**_fields(_NUMBER, "errorsLast24h criticalLast24h unexpectedShutdowns7d diskErrors7d bluescreens7d"),
               "recent": [{**_fields(_TEXT, "time log source level message"), "id": _NUMBER}]},
    "services": {"autoStopped": [_TEXT]},
    "startup": [_fields(_TEXT, "name command location user")],
    "printers": [{**_fields(_TEXT, "name driver port type"), "shared": _FLAG}],
    "monitors": [{**_fields(_TEXT, "manufacturer model serial"), "year": _NUMBER}],
    "shares": [_fields(_TEXT, "name path description")],
    "auditPolicy": [{**_fields(_TEXT, "guid name setting"), **_fields(_FLAG, "success failure")}],
}


def normalize_profile(value, shape=PROFILE_SHAPE):
    if isinstance(shape, dict):
        if not isinstance(value, dict):
            return {} if shape is PROFILE_SHAPE else None
        record = dict(value)
        for key, expected in shape.items():
            if key in record:
                record[key] = normalize_profile(record[key], expected)
        return record
    if isinstance(shape, list):
        # A singleton record from an old PowerShell Section is a real item.
        items = value if isinstance(value, list) else [value] if isinstance(value, dict) and value else []
        expected = shape[0]
        if isinstance(expected, dict):
            return [normalize_profile(item, expected) for item in items if isinstance(item, dict)]
        return [item for item in items if isinstance(item, expected)]
    if shape is _NUMBER:
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None
    return value if isinstance(value, shape) else None
