"""The Statement of Applicability as an Excel workbook: a cover sheet and one sortable, filterable sheet."""

from __future__ import annotations

import io
from datetime import datetime
from zoneinfo import ZoneInfo

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font

SOURCE = {"default": "In scope", "rule": "Scoping rule", "override": "Manual", "mandatory": "Mandatory",
          "derived": "Derived"}
COLUMNS = (("Control", 10), ("Title", 48), ("Theme", 24), ("Applicable", 12), ("Reason or justification", 60),
           ("Decided by", 14), ("Implementing controls", 40), ("How it is implemented", 60), ("Status", 24),
           ("Owner", 28))


def _put(ws, row: int, col: int, value) -> None:
    """Writes a value as plain text. openpyxl would turn text starting with "=" into a live formula, so customer text
    such as an implementation note can never become one."""
    cell = ws.cell(row=row, column=col, value=value)
    if isinstance(value, str):
        cell.data_type = "s"


def build_workbook(rows: list[dict], organization: str, framework: str, version: str, generated_by: str,
                   generated_at: datetime) -> bytes:
    wb = Workbook()
    cover = wb.active
    cover.title = "About"
    cover.column_dimensions["A"].width, cover.column_dimensions["B"].width = 28, 70
    applicable = sum(1 for r in rows if r["applicable"])
    when = generated_at.astimezone(ZoneInfo("Europe/London")).strftime("%d/%m/%Y")
    lines = [("Statement of Applicability", ""), ("Organization", organization),
             ("Framework", f"{framework} ({version})"), ("Generated", f"{when} by {generated_by}"),
             ("Controls listed", str(len(rows))), ("Applicable", str(applicable)),
             ("Not applicable", str(len(rows) - applicable)),
             ("Note", "Control identifiers and titles only. Each exclusion carries its justification.")]
    for i, (a, b) in enumerate(lines, start=1):
        _put(cover, i, 1, a)
        _put(cover, i, 2, b)
        cover.cell(row=i, column=1).font = Font(bold=True, size=14 if i == 1 else 11)

    ws = wb.create_sheet("Statement of Applicability")
    ws.freeze_panes = "A2"
    for col, (header, width) in enumerate(COLUMNS, start=1):
        _put(ws, 1, col, header)
        ws.cell(row=1, column=col).font = Font(bold=True)
        ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = width
    for i, r in enumerate(rows, start=2):
        values = (r["ref"], r["title"], r["group"], "Yes" if r["applicable"] else "No",
                  r["justification"] or r["reason"], SOURCE.get(r["source"], r["source"]),
                  "\n".join(f"{c['ref']} {c['title']}" for c in r["controls"]),
                  "\n".join(f"{c['ref']}: {c['implementation']}" for c in r["controls"] if c["implementation"]),
                  r["status"], ", ".join(r["owners"]))
        for col, value in enumerate(values, start=1):
            _put(ws, i, col, value)
            ws.cell(row=i, column=col).alignment = Alignment(vertical="top", wrap_text=True)
    ws.auto_filter.ref = f"A1:J{max(1, len(rows) + 1)}"
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()
