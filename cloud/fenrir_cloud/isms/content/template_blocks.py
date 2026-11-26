"""Template body syntax.

    ::: block isp.secure-development
    Markdown with {{organization.legal_name}} placeholders and {{#each controls}}...{{/each}} loops.
    :::

Every block has a ref. Rules can switch a block off with a ``template_section`` target, and tenant wording overrides
attach to the same ref so they survive regeneration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class TemplateBlock:
    ref: str
    body: str
    line: int


_OPEN = re.compile(r"^:::\s*block\s+([a-z0-9]+(?:[.-][a-z0-9]+)*)\s*$")
_CLOSE = re.compile(r"^:::\s*$")
_TAG = re.compile(r"\{\{\s*([#/]?)([^}]*?)\s*\}\}")


def parse_blocks(body: str) -> tuple[list[TemplateBlock], list[str]]:
    blocks: list[TemplateBlock] = []
    issues: list[str] = []
    current: tuple[str, int, list[str]] | None = None
    for i, raw in enumerate(body.split("\n"), start=1):
        line = raw.rstrip()
        if m := _OPEN.match(line):
            if current:
                issues.append(f'line {i}: block "{m.group(1)}" opened inside block "{current[0]}"')
            current = (m.group(1), i, [])
            continue
        if _CLOSE.match(line):
            if not current:
                issues.append(f"line {i}: ::: closes no open block")
                continue
            blocks.append(TemplateBlock(current[0], "\n".join(current[2]).strip(), current[1]))
            current = None
            continue
        if current:
            current[2].append(raw)
        elif line.strip() and not line.startswith("<!--"):
            issues.append(f"line {i}: content outside a block (wrap it in ::: block <ref>)")
    if current:
        issues.append(f'line {current[1]}: block "{current[0]}" is never closed')
    return blocks, issues


def placeholders(body: str) -> tuple[list[str], list[str]]:
    """Top-level placeholder paths used in a block, and structural issues with helpers."""
    paths: set[str] = set()
    issues: list[str] = []
    stack: list[str] = []
    for m in _TAG.finditer(body):
        kind, expr = m.group(1), m.group(2).strip()
        if kind == "#":
            parts = expr.split(None, 1)
            helper = parts[0] if parts else ""
            arg = parts[1].split()[0] if len(parts) > 1 and parts[1].split() else ""
            if helper not in ("each", "if", "unless"):
                issues.append(f'unsupported helper "#{helper}"')
                continue
            if arg and "each" not in stack:
                paths.add(arg)
            stack.append(helper)
        elif kind == "/":
            top = stack.pop() if stack else None
            if top != expr:
                issues.append(f'"{{{{/{expr}}}}}" does not close "{top or "nothing"}"')
        elif expr == "else" or expr.startswith(("this", "@", "../")):
            continue
        elif "each" not in stack:
            paths.add(expr)
    if stack:
        issues.append(f'unclosed helper "#{stack[-1]}"')
    return sorted(paths), issues
