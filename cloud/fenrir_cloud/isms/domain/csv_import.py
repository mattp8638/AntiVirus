"""Minimal RFC 4180 CSV parser for register imports: quoted fields, escaped quotes, commas and line breaks inside
quotes, CRLF or LF, optional byte order mark."""

from __future__ import annotations

from ._js import JS_SPACES, js_trim


class CsvError(ValueError):
    pass


def parse_csv(text: str) -> list[list[str]]:
    if text.startswith("\ufeff"):
        text = text[1:]
    rows: list[list[str]] = []
    row: list[str] = []
    field: list[str] = []
    quoted = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quoted:
            if ch == '"':
                if i + 1 < n and text[i + 1] == '"':
                    field.append('"')
                    i += 1
                else:
                    quoted = False
            else:
                field.append(ch)
        elif ch == '"' and not field:
            quoted = True
        elif ch == ",":
            row.append("".join(field))
            field = []
        elif ch in "\r\n":
            if ch == "\r" and i + 1 < n and text[i + 1] == "\n":
                i += 1
            row.append("".join(field))
            rows.append(row)
            row, field = [], []
        else:
            field.append(ch)
        i += 1
    if quoted:
        raise CsvError("A quoted field is not closed.")
    if field or row:
        row.append("".join(field))
        rows.append(row)
    return [r for r in rows if any(js_trim(c) for c in r)]


def parse_csv_records(text: str) -> tuple[list[str], list[dict[str, str]]]:
    """Records keyed by lower-case, trimmed header names (spaces become underscores)."""
    rows = parse_csv(text)
    if not rows:
        return [], []
    headers = [JS_SPACES.sub("_", js_trim(h).lower()) for h in rows[0]]
    records = []
    for r in rows[1:]:
        rec: dict[str, str] = {}
        for i, h in enumerate(headers):
            rec[h] = js_trim(r[i] if i < len(r) else "")
        records.append(rec)
    return headers, records
