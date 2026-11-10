"""Device custom fields in automation: scripts read them, scripts set them, monitors test them.

Read: every script run gets the device's fields as environment variables, ``FENRIR_CF_<KEY>`` (upper case), plus
``FENRIR_DEVICE_ID``, ``FENRIR_DEVICE_NAME`` and ``FENRIR_CUSTOMER``. PowerShell: ``$env:FENRIR_CF_ASSET_TAG``;
bash: ``$FENRIR_CF_ASSET_TAG``.

Write: a script sets a field by printing a line of its own (at most 20 per run)::

    FENRIR-FIELD warranty_end=2027-03-01
    FENRIR-FIELD bitlocker_enabled=true
    FENRIR-FIELD last_backup_gb=

An empty value clears the field. Values are checked against the field's type exactly as when a technician types them;
unknown fields and bad values are skipped and noted in the audit log, never stored.

Test: a monitor condition with metric ``custom_field`` and target ``<key>`` compares the field with the threshold:
numbers as they are, checkboxes as 1/0, dates as days from today (negative once passed), so "warranty_end < 30" alerts
30 days before a warranty ends. Target ``<key>=<text>`` is 1 when a text or list field equals that text, else 0.
"""

from __future__ import annotations

import re
from datetime import date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Command, CustomField, Device, Tenant

WRITE_LINE = re.compile(r"^\s*FENRIR-FIELD\s+([a-z][a-z0-9_]{0,59})\s*=(.*)$", re.MULTILINE)
MAX_WRITES = 20
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TRUE, _FALSE = {"true", "yes", "1", "on"}, {"false", "no", "0", "off"}


def definitions(db: Session, tenant_id: str) -> dict[str, CustomField]:
    """The device fields that apply to a tenant's devices: those its MSP defined."""
    from .services import msp_tenant_id

    msp = msp_tenant_id(db, tenant_id)
    rows = db.execute(select(CustomField).where(CustomField.tenant_id == msp, CustomField.entity == "device")).scalars()
    return {f.key: f for f in rows}


def coerce(field: CustomField, value, *, from_text: bool = False):
    """The value to store, or None to clear. Raises ValueError for a value that does not fit the field. ``from_text``
    (script output) also accepts true/false, yes/no, 1/0 and on/off for checkboxes; the API wants a real boolean."""
    if value is None or value == "":
        return None
    kind = field.field_type
    if kind == "checkbox":
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if from_text and (text in _TRUE or text in _FALSE):
            return text in _TRUE
        raise ValueError(f"{field.label} must be true or false")
    if kind == "number":
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{field.label} must be a number") from None
        if number != number or number in (float("inf"), float("-inf")):
            raise ValueError(f"{field.label} must be a number")
        return int(number) if number.is_integer() else number
    text = str(value).strip()
    if kind == "date":
        if not _DATE.fullmatch(text):
            raise ValueError(f"{field.label} must be a date (YYYY-MM-DD)")
        try:
            date.fromisoformat(text)
        except ValueError:
            raise ValueError(f"{field.label} must be a real date (YYYY-MM-DD)") from None
    if kind == "select" and text not in (field.options or []):
        raise ValueError(f"{field.label} must be one of: {', '.join(field.options or [])}")
    return text[:500]


def _as_text(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


def script_environment(db: Session, device: Device) -> dict[str, str]:
    tenant = db.get(Tenant, device.tenant_id)
    env = {"FENRIR_DEVICE_ID": device.id, "FENRIR_DEVICE_NAME": device.hostname or "", "FENRIR_CUSTOMER": tenant.name if tenant else ""}
    values = device.custom_fields or {}
    for key in definitions(db, device.tenant_id):
        env[f"FENRIR_CF_{key.upper()}"] = _as_text(values.get(key))
    return env


def apply_script_output(db: Session, device: Device, command: Command) -> dict:
    """Store the fields a finished script set with FENRIR-FIELD lines. Returns {"set": [...], "skipped": {...}}."""
    from . import audit

    if command.type != "script.run" or command.status != "completed":
        return {"set": [], "skipped": {}}
    stdout = str((command.result or {}).get("stdout") or "")
    matches = WRITE_LINE.findall(stdout)[: MAX_WRITES + 1]
    if not matches:
        return {"set": [], "skipped": {}}
    fields = definitions(db, device.tenant_id)
    current = dict(device.custom_fields or {})
    changed: list[str] = []
    skipped: dict[str, str] = {}
    for index, (key, raw) in enumerate(matches):
        if index >= MAX_WRITES:
            skipped["..."] = f"only the first {MAX_WRITES} FENRIR-FIELD lines are used"
            break
        field = fields.get(key)
        if field is None:
            skipped[key] = "no such device field"
            continue
        try:
            value = coerce(field, raw.strip(), from_text=True)
        except ValueError as exc:
            skipped[key] = str(exc)
            continue
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value
        changed.append(key)
    if changed:
        device.custom_fields = current
    script = (command.payload or {}).get("scriptName") or "script"
    audit.record(db, f"script:{script}"[:200], "device.custom_fields.updated", device.id, device.tenant_id,
                 fields=sorted(set(changed)), skipped=skipped, commandId=command.id)
    return {"set": sorted(set(changed)), "skipped": skipped}


def condition_value(db: Session, device: Device, target: str, today: date | None = None) -> tuple[float | None, str]:
    """A monitor's view of a custom field (see the module docstring)."""
    key, _, expected = target.partition("=")
    key = key.strip()
    field = definitions(db, device.tenant_id).get(key)
    if field is None:
        return None, f"no device field called {key}"
    value = (device.custom_fields or {}).get(key)
    if value is None or value == "":
        return None, f"{field.label} is not set"
    if expected:
        equal = _as_text(value).strip().lower() == expected.strip().lower()
        return (1.0 if equal else 0.0), f"{field.label} is {_as_text(value)}"
    if field.field_type == "checkbox":
        return (1.0 if value is True else 0.0), f"{field.label} is {'yes' if value is True else 'no'}"
    if field.field_type == "number":
        return float(value), f"{field.label} is {value}"
    if field.field_type == "date":
        try:
            when = date.fromisoformat(str(value))
        except ValueError:
            return None, f"{field.label} is not a date"
        days = (when - (today or datetime.utcnow().date())).days
        return float(days), (f"{field.label} is in {days} days ({value})" if days >= 0 else f"{field.label} was {-days} days ago ({value})")
    return None, f"{field.label} is text: use {key}=<value> to compare it"
