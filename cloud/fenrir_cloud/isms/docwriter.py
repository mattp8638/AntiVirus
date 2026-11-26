"""Word and PDF output for ISMS documents: title, a document control table, the body blocks and the requirements the
document supports. Word uses python-docx; PDF uses fpdf2 with the DejaVu fonts Fenrir already ships, so no separate
conversion service is needed."""

from __future__ import annotations

import io
import re
from dataclasses import dataclass, field
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor
from fpdf import FPDF

from .docgen import parse_markdown, plain_text

FONTS = Path(__file__).resolve().parent.parent / "fonts"


@dataclass
class DocumentMeta:
    title: str
    number: str
    version: int
    status: str
    organization: str
    owner: str
    approved_by: str | None
    approved_on: str | None
    next_review: str | None
    classification: str
    generated_on: str
    brand_colour: str = "1E3A8A"
    satisfies: list[str] = field(default_factory=list)  # e.g. "ISO/IEC 27001 5.2"


def _brand(meta: DocumentMeta) -> str:
    colour = (meta.brand_colour or "").lstrip("#")
    return colour if re.fullmatch(r"[0-9A-Fa-f]{6}", colour) else "1E3A8A"


def _control_rows(meta: DocumentMeta) -> list[tuple[str, str]]:
    return [("Document number", meta.number), ("Version", str(meta.version)), ("Status", meta.status),
            ("Owner", meta.owner),
            ("Approved by", f"{meta.approved_by}, {meta.approved_on or ''}" if meta.approved_by else "Not yet approved"),
            ("Next review", meta.next_review or "Not set"), ("Classification", meta.classification),
            ("Generated", meta.generated_on)]


# Word -----------------------------------------------------------------------------------------------------------

def _runs(paragraph, inline, bold=False, colour: str | None = None, size: float | None = None) -> None:
    for text, b in inline:
        run = paragraph.add_run(text)
        run.bold = b or bold
        if colour:
            run.font.color.rgb = RGBColor.from_string(colour)
        if size:
            run.font.size = Pt(size)


def _field(paragraph, code: str, size: float) -> None:
    """A Word field such as PAGE or NUMPAGES."""
    run = paragraph.add_run()
    run.font.size = Pt(size)
    for kind, text in (("begin", None), (None, code), ("end", None)):
        if kind:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        run._r.append(el)


def _shade(cell, colour: str) -> None:
    shading = OxmlElement("w:shd")
    shading.set(qn("w:val"), "clear")
    shading.set(qn("w:color"), "auto")
    shading.set(qn("w:fill"), colour)
    cell._tc.get_or_add_tcPr().append(shading)


def build_docx(meta: DocumentMeta, blocks: list[dict]) -> bytes:
    brand = _brand(meta)
    doc = Document()
    doc.core_properties.title = meta.title
    doc.core_properties.author = "Fenrir"
    doc.core_properties.comments = f"{meta.number} version {meta.version}"
    style = doc.styles["Normal"]
    style.font.name, style.font.size = "Arial", Pt(11)
    section = doc.sections[0]
    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _runs(header, [(f"{meta.organization}: {meta.title}", False)], colour="555555", size=9)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _runs(footer, [(f"{meta.number} version {meta.version} ({meta.status}). {meta.classification}. Page ", False)],
          colour="555555", size=8)
    _field(footer, "PAGE", 8)
    _runs(footer, [(" of ", False)], colour="555555", size=8)
    _field(footer, "NUMPAGES", 8)

    _runs(doc.add_paragraph(), [(meta.organization, False)], colour="555555", size=12)
    _runs(doc.add_paragraph(style="Title"), [(meta.title, True)], colour=brand, size=24)
    table = doc.add_table(rows=0, cols=2)
    table.style = "Table Grid"
    for key, value in _control_rows(meta):
        cells = table.add_row().cells
        _runs(cells[0].paragraphs[0], [(key, True)])
        cells[1].paragraphs[0].add_run(value)
    doc.add_paragraph()
    for block in blocks:
        for n in parse_markdown(block["markdown"]):
            if n["type"] == "heading":
                _runs(doc.add_heading(level=n["level"]), n["text"], colour=brand)
            elif n["type"] == "paragraph":
                _runs(doc.add_paragraph(), n["text"])
            elif n["type"] == "list":
                for item in n["items"]:
                    _runs(doc.add_paragraph(style="List Number" if n["ordered"] else "List Bullet"), item)
            else:
                t = doc.add_table(rows=1, cols=max(1, len(n["header"])))
                t.style = "Table Grid"
                for i, h in enumerate(n["header"]):
                    cell = t.rows[0].cells[i]
                    _shade(cell, brand)
                    _runs(cell.paragraphs[0], h, bold=True, colour="FFFFFF")
                for r in n["rows"]:
                    cells = t.add_row().cells
                    for i in range(len(n["header"])):
                        _runs(cells[i].paragraphs[0], r[i] if i < len(r) else [("", False)])
                doc.add_paragraph()
    if meta.satisfies:
        _runs(doc.add_heading(level=2), [("Requirements this document supports", False)], colour=brand)
        doc.add_paragraph(", ".join(meta.satisfies))
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


# PDF ------------------------------------------------------------------------------------------------------------

class _Pdf(FPDF):
    def __init__(self, meta: DocumentMeta):
        super().__init__(format="A4")
        self.meta = meta
        self.add_font("DejaVu", "", str(FONTS / "DejaVuSans.ttf"))
        self.add_font("DejaVu", "B", str(FONTS / "DejaVuSans-Bold.ttf"))
        self.set_margins(18, 18, 18)
        self.set_auto_page_break(True, 18)
        self.alias_nb_pages()

    def header(self):
        self.set_font("DejaVu", "", 8)
        self.set_text_color(85, 85, 85)
        self.cell(0, 6, f"{self.meta.organization}: {self.meta.title}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self):
        self.set_y(-14)
        self.set_font("DejaVu", "", 7)
        self.set_text_color(85, 85, 85)
        m = self.meta
        self.cell(0, 6, f"{m.number} version {m.version} ({m.status}). {m.classification}. Page {self.page_no()} of "
                        "{nb}", align="C")


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    return int(hex_colour[0:2], 16), int(hex_colour[2:4], 16), int(hex_colour[4:6], 16)


def _pdf_inline(pdf: _Pdf, inline, size: float = 10, colour=(0, 0, 0)) -> None:
    """Writes bold and plain runs as they are (fpdf2's own markdown mode would also read -- and __ as formatting)."""
    pdf.set_text_color(*colour)
    for text, bold in inline:
        pdf.set_font("DejaVu", "B" if bold else "", size)
        pdf.write(size * 0.5, text)
    pdf.ln(size * 0.5)


def build_pdf(meta: DocumentMeta, blocks: list[dict]) -> bytes:
    brand = _rgb(_brand(meta))
    pdf = _Pdf(meta)
    pdf.add_page()
    pdf.set_font("DejaVu", "", 11)
    pdf.set_text_color(85, 85, 85)
    pdf.cell(0, 6, meta.organization, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "B", 20)
    pdf.set_text_color(*brand)
    pdf.multi_cell(0, 9, meta.title, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_text_color(0, 0, 0)
    with pdf.table(col_widths=(35, 65), text_align="LEFT", line_height=6) as table:
        for key, value in _control_rows(meta):
            row = table.row()
            pdf.set_font("DejaVu", "B", 9)
            row.cell(key)
            pdf.set_font("DejaVu", "", 9)
            row.cell(value)
    pdf.ln(4)
    for block in blocks:
        for n in parse_markdown(block["markdown"]):
            if n["type"] == "heading":
                pdf.ln(2)
                pdf.set_font("DejaVu", "B", {1: 15, 2: 13, 3: 11}[n["level"]])
                pdf.set_text_color(*brand)
                pdf.multi_cell(0, 7, plain_text(n["text"]), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
            elif n["type"] == "paragraph":
                _pdf_inline(pdf, n["text"])
                pdf.ln(1.5)
            elif n["type"] == "list":
                for i, item in enumerate(n["items"], start=1):
                    _pdf_inline(pdf, [((f"{i}. " if n["ordered"] else "• "), False), *item])
                pdf.ln(1.5)
            else:
                pdf.set_font("DejaVu", "", 8)
                with pdf.table(text_align="LEFT", line_height=5,
                               headings_style=None) as table:
                    head = table.row()
                    for h in n["header"]:
                        head.cell(plain_text(h))
                    for r in n["rows"]:
                        row = table.row()
                        for i in range(len(n["header"])):
                            row.cell(plain_text(r[i]) if i < len(r) else "")
                pdf.ln(3)
    if meta.satisfies:
        pdf.set_font("DejaVu", "B", 13)
        pdf.set_text_color(*brand)
        pdf.multi_cell(0, 7, "Requirements this document supports", new_x="LMARGIN", new_y="NEXT")
        _pdf_inline(pdf, [(", ".join(meta.satisfies), False)])
    return bytes(pdf.output())
