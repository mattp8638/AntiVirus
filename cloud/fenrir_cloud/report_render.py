"""Customer reports as one structured document, drawn as branded HTML (on screen, printable) or PDF (download, email).

A document is plain data, so the same report looks the same in both forms and can be stored as sent:

    {"title": str, "subtitle": str, "blocks": [block, ...]}

Blocks:
    {"type": "heading", "text": str}
    {"type": "paragraph", "text": str, "muted": bool}
    {"type": "score", "label": str, "value": int | None, "status": "good" | "warn" | "bad" | "none"}
    {"type": "kpis", "items": [{"value": str | number, "label": str}, ...]}
    {"type": "table", "columns": [str, ...], "rows": [[cell, ...], ...], "widths": [number, ...] (optional)}
        a cell is text, a number, or {"text": str, "status": "good" | "warn" | "bad" | "none"}
    {"type": "list", "items": [str, ...], "ordered": bool}

The brand (branding.get) supplies the logo, name, colours, contact line and footer.
"""

from __future__ import annotations

import html
import io
from datetime import datetime
from pathlib import Path

from . import branding

STATUS_COLOURS = {"good": "#15803d", "warn": "#b45309", "bad": "#b91c1c", "none": "#6b7280"}
FONTS = Path(__file__).resolve().parent / "fonts"
INK, MUTED, LINE = "#1b2430", "#5b6675", "#dde3ea"


def _cell_text(cell) -> str:
    if isinstance(cell, dict):
        return str(cell.get("text", ""))
    return "" if cell is None else str(cell)


def _cell_status(cell) -> str | None:
    return cell.get("status") if isinstance(cell, dict) else None


# --------------------------------------------------------------------------- HTML


def render_html(doc: dict, brand: dict) -> str:
    e = html.escape
    primary, on_primary = brand["primaryColour"], brand["onPrimary"]
    logo = (f'<img class="logo" alt="{e(brand["companyName"])}" src="data:image/png;base64,{brand["logo"]}">'
            if brand.get("logo") else f'<div class="mark">{e(brand["companyName"][:1])}</div>')
    parts: list[str] = []
    for block in doc.get("blocks", []):
        kind = block.get("type")
        if kind == "heading":
            parts.append(f"<h2>{e(block['text'])}</h2>")
        elif kind == "paragraph":
            parts.append(f"<p class=\"{'sub' if block.get('muted') else ''}\">{e(block['text'])}</p>")
        elif kind == "score":
            value = "n/a" if block.get("value") is None else block["value"]
            parts.append(f"<h2>{e(block['label'])}: <span class=\"score {e(block.get('status') or 'none')}\">{value}</span>"
                         "<span class=\"sub\"> / 100</span></h2>")
        elif kind == "kpis":
            cards = "".join(f"<div class=\"card\"><b>{e(str(i['value']))}</b>{e(i['label'])}</div>" for i in block["items"])
            parts.append(f"<div class=\"grid\">{cards}</div>")
        elif kind == "table":
            head = "".join(f"<th>{e(c)}</th>" for c in block["columns"])
            rows = "".join(
                "<tr>" + "".join(f"<td class=\"{e(_cell_status(c) or '')}\">{e(_cell_text(c))}</td>" for c in row) + "</tr>"
                for row in block["rows"]) or f"<tr><td colspan=\"{len(block['columns'])}\">None</td></tr>"
            parts.append(f"<table><tr>{head}</tr>{rows}</table>")
        elif kind == "list":
            tag = "ol" if block.get("ordered") else "ul"
            parts.append(f"<{tag}>" + "".join(f"<li>{e(i)}</li>" for i in block["items"]) + f"</{tag}>")
    contact = branding.contact_line(brand)
    footer = "".join(f"<div>{e(x)}</div>" for x in (brand.get("reportFooter"), contact) if x)
    status_css = "".join(f".{k}{{color:{v}}}" for k, v in STATUS_COLOURS.items())
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{e(doc['title'])}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:860px;margin:0 auto 32px;color:{INK};padding:0 16px}}
.bar{{display:flex;align-items:center;gap:14px;padding:18px 0;border-bottom:4px solid {primary};margin-bottom:20px}}
.logo{{max-height:48px;max-width:220px}}.mark{{width:44px;height:44px;border-radius:10px;background:{primary};color:{on_primary};
display:grid;place-items:center;font-weight:800;font-size:22px}}.brand{{font-weight:700;font-size:18px}}
h1{{margin:0 0 4px}}h2{{border-left:4px solid {primary};padding-left:10px;margin-top:28px}}.sub{{color:{MUTED}}}
.score{{font-size:56px;font-weight:700}}{status_css}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}}
.card{{border:1px solid {LINE};border-top:3px solid {primary};border-radius:10px;padding:14px}}.card b{{display:block;font-size:26px;color:{primary}}}
table{{width:100%;border-collapse:collapse;margin:8px 0 24px}}td,th{{border-bottom:1px solid #eef1f4;padding:6px 4px;text-align:left;vertical-align:top}}
th{{color:{MUTED};font-weight:600}}footer{{margin-top:40px;padding-top:12px;border-top:1px solid {LINE};color:{MUTED};font-size:13px}}
@media print{{body{{margin:0}}.card,table{{break-inside:avoid}}}}</style></head>
<body><div class="bar">{logo}<div class="brand">{e(brand['companyName'])}</div></div>
<h1>{e(doc['title'])}</h1><div class="sub">{e(doc.get('subtitle') or '')}</div>
{''.join(parts)}
<footer>{footer}<div>Prepared by {e(brand['companyName'])}</div></footer></body></html>"""


# --------------------------------------------------------------------------- PDF


def _rgb(colour: str) -> tuple[int, int, int]:
    return int(colour[1:3], 16), int(colour[3:5], 16), int(colour[5:7], 16)


def render_pdf(doc: dict, brand: dict, generated: datetime | None = None) -> bytes:
    from fpdf import FPDF
    from fpdf.fonts import FontFace

    primary = _rgb(brand["primaryColour"])
    logo = branding.logo_bytes(brand)
    contact = branding.contact_line(brand)
    footer_note = brand.get("reportFooter") or ""
    company = brand["companyName"]

    class Report(FPDF):
        def header(self):
            top = 10
            if logo:
                try:
                    self.image(io.BytesIO(logo), x=15, y=top, h=12)
                except Exception:  # an unreadable logo must not stop the report
                    pass
            self.set_xy(15, top)
            self.set_font("DejaVu", "B", 11)
            self.set_text_color(*_rgb(INK))
            self.cell(0, 12, company, align="R")
            self.set_draw_color(*primary)
            self.set_line_width(0.8)
            self.line(15, top + 15, self.w - 15, top + 15)
            self.set_y(top + 20)

        def footer(self):
            self.set_y(-18)
            self.set_draw_color(*_rgb(LINE))
            self.set_line_width(0.2)
            self.line(15, self.get_y(), self.w - 15, self.get_y())
            self.set_font("DejaVu", "", 7.5)
            self.set_text_color(*_rgb(MUTED))
            if footer_note:
                self.set_x(15)
                self.cell(0, 5, footer_note[:180], new_x="LMARGIN", new_y="NEXT")
            self.set_x(15)
            self.cell(self.w / 2, 5, contact or f"Prepared by {company}")
            self.cell(0, 5, f"Page {self.page_no()} of {{nb}}", align="R")

    pdf = Report(format="A4")
    pdf.set_margins(15, 15, 15)
    pdf.set_auto_page_break(True, margin=24)
    pdf.add_font("DejaVu", "", str(FONTS / "DejaVuSans.ttf"))
    pdf.add_font("DejaVu", "B", str(FONTS / "DejaVuSans-Bold.ttf"))
    pdf.set_title(doc["title"])
    pdf.set_author(company)
    pdf.set_creator("Fenrir")
    if generated:
        pdf.set_creation_date(generated)
    pdf.alias_nb_pages()
    pdf.add_page()
    width = pdf.w - pdf.l_margin - pdf.r_margin

    def text(size: float, bold: bool = False, colour: str = INK):
        pdf.set_font("DejaVu", "B" if bold else "", size)
        pdf.set_text_color(*_rgb(colour))

    text(18, True)
    pdf.multi_cell(width, 9, doc["title"], new_x="LMARGIN", new_y="NEXT")
    if doc.get("subtitle"):
        text(9.5, colour=MUTED)
        pdf.multi_cell(width, 5, doc["subtitle"], new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    for block in doc.get("blocks", []):
        kind = block.get("type")
        if kind == "heading":
            if pdf.get_y() > pdf.h - 50:
                pdf.add_page()
            pdf.ln(3)
            pdf.set_fill_color(*primary)
            pdf.rect(pdf.l_margin, pdf.get_y() + 1, 1.4, 6, style="F")
            pdf.set_x(pdf.l_margin + 4)
            text(12.5, True)
            pdf.multi_cell(width - 4, 8, block["text"], new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
        elif kind == "paragraph":
            text(9.5, colour=MUTED if block.get("muted") else INK)
            pdf.multi_cell(width, 5, block["text"], align="L", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        elif kind == "score":
            if pdf.get_y() > pdf.h - 50:
                pdf.add_page()
            status = block.get("status") or "none"
            value = "n/a" if block.get("value") is None else str(block["value"])
            pdf.ln(2)
            text(12.5, True)
            pdf.cell(pdf.get_string_width(block["label"] + ": ") + 1, 14, block["label"] + ": ")
            text(30, True, STATUS_COLOURS.get(status, MUTED))
            pdf.cell(pdf.get_string_width(value) + 2, 14, value)
            text(11, colour=MUTED)
            pdf.cell(0, 14, "/ 100", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        elif kind == "kpis":
            items = block["items"]
            per_row, gap, height = 4, 3, 22
            card = (width - gap * (per_row - 1)) / per_row
            for start in range(0, len(items), per_row):
                if pdf.get_y() + height > pdf.h - 26:
                    pdf.add_page()
                y = pdf.get_y()
                for i, item in enumerate(items[start:start + per_row]):
                    x = pdf.l_margin + i * (card + gap)
                    pdf.set_draw_color(*_rgb(LINE))
                    pdf.set_line_width(0.25)
                    pdf.rect(x, y, card, height, style="D", round_corners=True, corner_radius=2)
                    pdf.set_fill_color(*primary)
                    pdf.rect(x, y, card, 1.2, style="F")
                    pdf.set_xy(x + 3, y + 3)
                    value = str(item["value"])[:24]
                    size = 15.0
                    text(size, True, brand["primaryColour"])
                    while size > 8 and pdf.get_string_width(value) > card - 6:
                        size -= 1
                        text(size, True, brand["primaryColour"])
                    pdf.cell(card - 6, 8, value)
                    pdf.set_xy(x + 3, y + 11.5)
                    text(7.5, colour=MUTED)
                    pdf.multi_cell(card - 6, 3.6, str(item["label"])[:70], align="L", max_line_height=3.6)
                pdf.set_xy(pdf.l_margin, y + height + gap)
            pdf.ln(2)
        elif kind == "table":
            columns = block["columns"]
            widths = block.get("widths") or [1] * len(columns)
            text(8.5)
            pdf.set_draw_color(*_rgb(LINE))
            pdf.set_line_width(0.2)
            heading = FontFace(emphasis="BOLD", color=_rgb(MUTED), fill_color=(244, 246, 249))
            rows = block["rows"] or [["None"] + [""] * (len(columns) - 1)]
            pdf.set_fill_color(255, 255, 255)
            with pdf.table(col_widths=tuple(widths), width=width, headings_style=heading, line_height=5,
                           borders_layout="HORIZONTAL_LINES", text_align="LEFT", padding=1.2,
                           cell_fill_mode="NONE") as table:
                head = table.row()
                for column in columns:
                    head.cell(column)
                for values in rows:
                    row = table.row()
                    for cell in values:
                        status = _cell_status(cell)
                        style = FontFace(color=_rgb(STATUS_COLOURS[status]), emphasis="BOLD") if status in STATUS_COLOURS else None
                        row.cell(_cell_text(cell), style=style)
            pdf.ln(4)
        elif kind == "list":
            text(9.5)
            for n, item in enumerate(block["items"], 1):
                marker = f"{n}." if block.get("ordered") else "•"
                pdf.set_x(pdf.l_margin + 2)
                pdf.cell(7, 5.5, marker)
                pdf.multi_cell(width - 9, 5.5, item, align="L", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

    return bytes(pdf.output())
