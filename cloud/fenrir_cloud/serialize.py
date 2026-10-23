from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from sqlalchemy import inspect


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.title() for part in rest)


# Never serialised, whatever the model: hashes, keys and encrypted envelopes.
SECRET_COLUMNS = {"password_hash", "api_key_hash", "token_hash", "secret", "mfa_secret", "ciphertext", "secret_envelope",
                  "credentials_envelope"}


def to_dict(obj: Any, exclude: Iterable[str] = ()) -> dict:
    skip = SECRET_COLUMNS | set(exclude)
    out = {}
    for column in inspect(obj).mapper.column_attrs:
        if column.key in skip:
            continue
        value = getattr(obj, column.key)
        if isinstance(value, datetime):
            value = value.isoformat(timespec="seconds") + "Z"
        out[_camel(column.key)] = value
    return out


def snake(name: str) -> str:
    out = []
    for ch in name:
        if ch.isupper():
            out.append("_" + ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def apply_fields(obj: Any, body: dict, allowed: Iterable[str]) -> list[str]:
    """Copy camelCase keys from a request body onto snake_case attributes."""
    changed = []
    allowed = set(allowed)
    for key, value in body.items():
        attr = snake(key)
        if attr in allowed:
            setattr(obj, attr, value)
            changed.append(attr)
    return changed
