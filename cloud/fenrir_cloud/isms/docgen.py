"""Document templates: placeholders, the Markdown subset, safe HTML, block rendering and the context hash.

Ported from the standalone app's ``packages/docgen`` and held to it by ``tests/test_isms_parity.py``.

Placeholders are a small, logic-less subset of Handlebars:
    {{a.b}}                        a value (lists are joined with ", "; missing values are empty)
    {{#each list}}...{{/each}}     repeat; inside, {{this}}, {{this.x}} and {{@index}} (from 1)
    {{#if a}}...{{else}}...{{/if}} and {{#unless a}}...{{/unless}}
Nothing is evaluated as code. The Markdown subset has headings (#, ##, ###), paragraphs, bullet and numbered lists,
pipe tables and **bold**.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from .content.template_blocks import parse_blocks


class TemplateError(ValueError):
    pass


# Placeholders ---------------------------------------------------------------------------------------------------

_TAG = re.compile(r"\{\{\s*([#/]?)\s*([^}]*?)\s*\}\}")


@dataclass
class _Node:
    type: str  # text | var | each | if | unless
    value: str
    children: list = field(default_factory=list)
    else_children: list = field(default_factory=list)


def _parse(src: str) -> list[_Node]:
    root = _Node("text", "")
    stack: list[list] = [[root, False]]

    def target() -> list:
        node, in_else = stack[-1]
        return node.else_children if in_else else node.children

    last = 0
    for m in _TAG.finditer(src):
        if m.start() > last:
            target().append(_Node("text", src[last:m.start()]))
        last = m.end()
        kind, expr = m.group(1), m.group(2).strip()
        if kind == "#":
            parts = expr.split(None, 1)
            helper = parts[0] if parts else ""
            arg = parts[1].split()[0] if len(parts) > 1 and parts[1].split() else ""
            if helper not in ("each", "if", "unless"):
                raise TemplateError(f"Unsupported helper #{helper}")
            node = _Node(helper, arg)
            target().append(node)
            stack.append([node, False])
        elif kind == "/":
            if len(stack) == 1 or stack[-1][0].type != expr:
                raise TemplateError(f"{{{{/{expr}}}}} does not close an open block")
            stack.pop()
        elif expr == "else":
            if stack[-1][0].type not in ("if", "unless"):
                raise TemplateError("{{else}} outside {{#if}}")
            stack[-1][1] = True
        else:
            target().append(_Node("var", expr))
    if last < len(src):
        target().append(_Node("text", src[last:]))
    if len(stack) != 1:
        raise TemplateError(f"{{{{#{stack[-1][0].type}}}}} is not closed")
    return root.children


def _lookup(path: str, ctx: dict, item: Any, index: int) -> Any:
    if path == "this":
        return item
    if path == "@index":
        return index
    cur = item if path.startswith("this.") else ctx
    for part in (path[5:] if path.startswith("this.") else path).split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _truthy(v: Any) -> bool:
    if isinstance(v, list):
        return len(v) > 0
    if isinstance(v, dict):
        return True
    if isinstance(v, float) and math.isnan(v):
        return False
    return bool(v)


def _str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return ", ".join(_str(x) for x in v)
    if isinstance(v, dict):
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _run(nodes: list[_Node], ctx: dict, item: Any, index: int) -> str:
    out: list[str] = []
    for n in nodes:
        if n.type == "text":
            out.append(n.value)
        elif n.type == "var":
            out.append(_str(_lookup(n.value, ctx, item, index)))
        elif n.type == "each":
            items = _lookup(n.value, ctx, item, index)
            if isinstance(items, list):
                for i, it in enumerate(items, start=1):
                    out.append(_run(n.children, ctx, it, i))
        else:
            cond = _truthy(_lookup(n.value, ctx, item, index))
            show = cond if n.type == "if" else not cond
            out.append(_run(n.children if show else n.else_children, ctx, item, index))
    return "".join(out)


def render_mustache(template: str, ctx: dict) -> str:
    return _run(_parse(template), ctx, None, 0)


# Markdown subset ------------------------------------------------------------------------------------------------

Inline = list  # [(text, bold)]


def parse_inline(s: str) -> Inline:
    out = []
    for p in re.split(r"(\*\*[^*]+\*\*)", s):
        if not p:
            continue
        if p.startswith("**") and p.endswith("**") and len(p) > 4:
            out.append((p[2:-2], True))
        else:
            out.append((p, False))
    return out or [("", False)]


def _cells(line: str) -> list[Inline]:
    t = line.strip()
    t = t[1:] if t.startswith("|") else t
    t = t[:-1] if t.endswith("|") else t
    return [parse_inline(c.strip()) for c in t.split("|")]


def parse_markdown(src: str) -> list[dict]:
    lines = src.replace("\r\n", "\n").split("\n")
    out: list[dict] = []
    para: list[str] = []

    def flush() -> None:
        if para:
            out.append({"type": "paragraph", "text": parse_inline(" ".join(para).strip())})
        para.clear()

    i = 0
    while i < len(lines):
        t = lines[i].strip()
        if not t:
            flush()
            i += 1
            continue
        h = re.match(r"^(#{1,3})\s+(.*)$", t)
        if h:
            flush()
            out.append({"type": "heading", "level": len(h.group(1)), "text": parse_inline(h.group(2))})
            i += 1
            continue
        if t.startswith("|"):
            flush()
            block = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                block.append(lines[i].strip())
                i += 1
            sep = next((k for k, line in enumerate(block) if re.match(r"^\|?\s*:?-{3,}", line)), -1)
            out.append({"type": "table", "header": _cells(block[0]),
                        "rows": [_cells(line) for line in block[2 if sep == 1 else 1:]]})
            continue
        bullet, num = re.match(r"^[-*]\s+(.*)$", t), re.match(r"^\d+\.\s+(.*)$", t)
        if bullet or num:
            flush()
            ordered = bool(num)
            items = []
            while i < len(lines):
                m = re.match(r"^\d+\.\s+(.*)$" if ordered else r"^[-*]\s+(.*)$", lines[i].strip())
                if not m:
                    break
                items.append(parse_inline(m.group(1)))
                i += 1
            out.append({"type": "list", "ordered": ordered, "items": items})
            continue
        para.append(t)
        i += 1
    flush()
    return out


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _inline_html(runs: Inline) -> str:
    return "".join(f"<strong>{_esc(t)}</strong>" if b else _esc(t) for t, b in runs)


def to_html(nodes: list[dict]) -> str:
    """Safe HTML for the in-app view: every piece of text is escaped."""
    parts = []
    for n in nodes:
        if n["type"] == "heading":
            parts.append(f"<h{n['level'] + 1}>{_inline_html(n['text'])}</h{n['level'] + 1}>")
        elif n["type"] == "paragraph":
            parts.append(f"<p>{_inline_html(n['text'])}</p>")
        elif n["type"] == "list":
            tag = "ol" if n["ordered"] else "ul"
            parts.append(f"<{tag}>" + "".join(f"<li>{_inline_html(i)}</li>" for i in n["items"]) + f"</{tag}>")
        else:
            head = "".join(f'<th scope="col">{_inline_html(c)}</th>' for c in n["header"])
            body = "".join("<tr>" + "".join(f"<td>{_inline_html(c)}</td>" for c in r) + "</tr>" for r in n["rows"])
            parts.append(f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
    return "\n".join(parts)


def plain_text(runs: Inline) -> str:
    return "".join(t for t, _ in runs)


# Rendering, hashing and changes ---------------------------------------------------------------------------------

def render_template(body: str, context: dict, excluded: set[str] | frozenset = frozenset(),
                    overrides: dict[str, str] | None = None) -> list[dict]:
    """Blocks after placeholders are filled in. Excluded blocks are left out; overridden blocks use the customer's
    wording (placeholders still work), so their edits survive regeneration."""
    blocks, issues = parse_blocks(body)
    if issues:
        raise TemplateError("Template structure: " + "; ".join(issues))
    overrides = overrides or {}
    return [{"ref": b.ref, "markdown": render_mustache(overrides.get(b.ref, b.body), context).strip(),
             "overridden": b.ref in overrides} for b in blocks if b.ref not in excluded]


def _canonical_value(v: Any) -> Any:
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return v


def canonical_json(v: Any) -> str:
    """Stable JSON with object keys sorted, as the standalone app's canonicalJson writes it."""
    if isinstance(v, dict):
        keys = sorted(v)
        return "{" + ",".join(f"{json.dumps(k, ensure_ascii=False)}:{canonical_json(v[k])}" for k in keys) + "}"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonical_json(x) for x in v) + "]"
    return json.dumps(_canonical_value(v), ensure_ascii=False)


def context_hash(context: Any, template_id: str, overrides: dict[str, str], excluded: set[str]) -> str:
    """Hash of everything that shapes a document: data, template, overrides and excluded sections."""
    return hashlib.sha256(canonical_json({"context": context, "templateId": template_id,
                                          "overrides": dict(sorted(overrides.items())),
                                          "excluded": sorted(excluded)}).encode()).hexdigest()


def used_paths(body: str) -> set[str]:
    from .content.template_blocks import placeholders

    used: set[str] = set()
    for m in re.finditer(r"::: block [^\n]+\n([\s\S]*?)\n:::", body):
        used |= set(placeholders(m.group(1))[0])
    return used


def context_for_template(body: str, full: dict) -> dict:
    """Only the values a template uses, so unrelated changes do not mark a document out of date."""
    out: dict = {}
    for path in used_paths(body):
        src: Any = full
        for part in path.split("."):
            src = src.get(part) if isinstance(src, dict) else None
        out[path] = src
    return out


def diff_blocks(before: list[dict], after: list[dict]) -> list[dict]:
    """What would change in each block if the document were regenerated now."""
    a = {b["ref"]: b["markdown"] for b in before}
    b = {x["ref"]: x["markdown"] for x in after}
    out = []
    for ref in list(dict.fromkeys([*a, *b])):
        x, y = a.get(ref), b.get(ref)
        if x is None:
            out.append({"ref": ref, "change": "added", "before": None, "after": y})
        elif y is None:
            out.append({"ref": ref, "change": "removed", "before": x, "after": None})
        elif x != y:
            out.append({"ref": ref, "change": "changed", "before": x, "after": y})
    return out
