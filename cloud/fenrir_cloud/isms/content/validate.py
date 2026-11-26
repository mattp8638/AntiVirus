"""Validates a set of packs published together. Cross-pack refs must resolve inside the set.

Errors block loading. Warnings (an unmapped requirement) and info (an unmapped control) are coverage reports.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ValidationError

from ..domain.expression import parse_expression
from .loader import PACKS_ROOT, RawPack
from .schema import (
    RESTRICTED_LICENCES, SHORT_TITLE_MAX, CommonControl, Group, Mapping, PackMeta, Question, Requirement, Rule,
    TemplateFrontMatter,
)
from .template_blocks import TemplateBlock, parse_blocks, placeholders

Severity = Literal["error", "warning", "info"]
EM_DASH = chr(0x2014)  # written as a code point so this file passes its own rule


@dataclass(frozen=True)
class Issue:
    severity: Severity
    pack: str
    where: str
    message: str


@dataclass
class ValidTemplate:
    path: Path
    meta: TemplateFrontMatter
    body: str
    blocks: list[TemplateBlock]


@dataclass
class ValidatedPack:
    dir: Path
    meta: PackMeta
    groups: list[Group] = field(default_factory=list)
    requirements: list[Requirement] = field(default_factory=list)
    controls: list[CommonControl] = field(default_factory=list)
    mappings: list[Mapping] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    templates: list[ValidTemplate] = field(default_factory=list)


@dataclass
class ValidationResult:
    ok: bool
    issues: list[Issue]
    packs: list[ValidatedPack]

    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]


def display(path: Path | str) -> str:
    path = Path(path)
    try:
        return str(path.relative_to(PACKS_ROOT.parent))
    except ValueError:
        return str(path)


def _format(error: ValidationError) -> str:
    parts = []
    for e in error.errors():
        loc = ".".join(str(x) for x in e["loc"])
        parts.append(f"{loc}: {e['msg']}" if loc else e["msg"])
    return "; ".join(parts)


def _duplicates(values: list[str]) -> list[str]:
    return [v for v, n in Counter(values).items() if n > 1]


def validate_packs(raws: list[RawPack]) -> ValidationResult:
    issues: list[Issue] = []
    packs: list[ValidatedPack] = []

    for raw in raws:
        name = display(raw.dir)

        def push(severity: Severity, where: str, message: str) -> None:
            issues.append(Issue(severity, name, where, message))

        for e in raw.load_errors:
            push("error", "load", e)
        for path, content in raw.text:
            for i, line in enumerate(content.split("\n"), start=1):
                if EM_DASH in line:
                    push("error", f"{display(path)}:{i}", "em dash character is not allowed")

        try:
            meta = PackMeta.model_validate(raw.meta if raw.meta is not None else {})
        except ValidationError as e:
            push("error", "pack.yaml", _format(e))
            continue

        def items(file: str, model: type[BaseModel]) -> list:
            data = raw.files.get(file)
            if data is None:
                return []
            if not isinstance(data, list):
                push("error", f"{file}.yaml", "must be a YAML list")
                return []
            out = []
            for i, item in enumerate(data):
                ref = f" ({item['ref']})" if isinstance(item, dict) and "ref" in item else ""
                label = f"{file}.yaml[{i}]{ref}"
                if isinstance(item, dict) and "licence" not in item:
                    push("error", label, "missing licence")
                if file == "rules" and isinstance(item, dict) and "when" not in item:
                    push("error", label, "when $: expression is missing")
                try:
                    out.append(model.model_validate(item))
                except ValidationError as e:
                    push("error", label, _format(e))
            return out

        templates: list[ValidTemplate] = []
        for t in raw.templates:
            where = display(t.path)
            if isinstance(t.front_matter, dict) and "licence" not in t.front_matter:
                push("error", where, "missing licence")
            try:
                fm = TemplateFrontMatter.model_validate(t.front_matter if t.front_matter is not None else {})
            except ValidationError as e:
                push("error", where, _format(e))
                continue
            blocks, block_issues = parse_blocks(t.body)
            for msg in block_issues:
                push("error", where, msg)
            templates.append(ValidTemplate(t.path, fm, t.body, blocks))

        packs.append(ValidatedPack(
            raw.dir, meta, groups=items("groups", Group), requirements=items("requirements", Requirement),
            controls=items("controls", CommonControl), mappings=items("mappings", Mapping),
            questions=items("questions", Question), rules=items("rules", Rule), templates=templates))

    issues.extend(_cross_checks(packs))
    return ValidationResult(not any(i.severity == "error" for i in issues), issues, packs)


def _cross_checks(packs: list[ValidatedPack]) -> list[Issue]:
    issues: list[Issue] = []
    pack_ids = [p.meta.id for p in packs]
    for d in _duplicates(pack_ids):
        issues.append(Issue("error", d, "pack.yaml", f'duplicate pack id "{d}"'))

    control_refs = {c.ref for p in packs for c in p.controls}
    question_refs = {q.ref for p in packs for q in p.questions}
    block_refs = {b.ref for p in packs for t in p.templates for b in t.blocks}
    for what, values in (
        ("common control ref", [c.ref for p in packs for c in p.controls]),
        ("question ref", [q.ref for p in packs for q in p.questions]),
        ("template block ref", [b.ref for p in packs for t in p.templates for b in t.blocks]),
        ("template doc_type", [t.meta.doc_type for p in packs for t in p.templates]),
    ):
        where = {"common control ref": "controls", "question ref": "questions"}.get(what, "templates")
        for d in _duplicates(values):
            issues.append(Issue("error", "*", where, f'duplicate {what} "{d}"'))

    mapped_controls: set[str] = set()
    framework_refs = {p.meta.framework: {r.ref for r in p.requirements}
                      for p in packs if p.meta.kind == "framework" and p.meta.framework}
    mapped_requirements = {m.requirement for p in packs for m in p.mappings}

    for p in packs:
        name = display(p.dir)

        def add(severity: Severity, where: str, message: str) -> None:
            issues.append(Issue(severity, name, where, message))

        restricted = p.meta.licence in RESTRICTED_LICENCES
        if p.meta.kind != "framework" and (p.groups or p.requirements):
            add("error", "pack.yaml", "only framework packs may contain groups or requirements")
        if p.meta.kind != "control-library" and p.controls:
            add("error", "pack.yaml", "only control-library packs may contain controls")
        if p.meta.kind != "templates" and p.templates:
            add("error", "pack.yaml", "only templates packs may contain templates")
        if p.meta.licence == "open" and not p.meta.attribution:
            add("error", "pack.yaml", "open licence needs an attribution")

        # Groups
        group_refs = {g.ref for g in p.groups}
        for d in _duplicates([g.ref for g in p.groups]):
            add("error", "groups.yaml", f'duplicate group ref "{d}"')
        for g in p.groups:
            if g.parent and g.parent not in group_refs:
                add("error", f"groups.yaml ({g.ref})", f'parent "{g.parent}" does not exist')
            if len(g.title) >= SHORT_TITLE_MAX:
                add("error", f"groups.yaml ({g.ref})", f"title must be under {SHORT_TITLE_MAX} characters")

        # Requirements
        req_refs = {r.ref for r in p.requirements}
        mandatory = {r.ref for r in p.requirements if r.mandatory}
        for d in _duplicates([r.ref for r in p.requirements]):
            add("error", "requirements.yaml", f'duplicate requirement ref "{d}"')
        for r in p.requirements:
            where = f"requirements.yaml ({r.ref})"
            if r.group not in group_refs:
                add("error", where, f'group "{r.group}" does not exist')
            if len(r.short_title) >= SHORT_TITLE_MAX:
                add("error", where, f"short_title must be under {SHORT_TITLE_MAX} characters")
            if (restricted or r.licence in RESTRICTED_LICENCES) and r.text is not None:
                add("error", where, f'"{r.licence}" items may hold ref, short_title, group, mandatory and original '
                                    "guidance only, not text")

        # Dependencies: mappings must point at controls in the libraries this pack depends on.
        deps = list(p.meta.depends_on or ())
        for d in deps:
            if d not in pack_ids:
                add("error", "pack.yaml", f'depends_on "{d}" is not in this content set')
        dep_controls = ({c.ref for x in packs if x.meta.id in deps for c in x.controls} if deps else control_refs)

        # Mappings
        for m in p.mappings:
            where = f"mappings.yaml ({m.requirement} -> {m.control})"
            if p.meta.kind == "framework" and m.requirement not in req_refs:
                add("error", where, f'requirement "{m.requirement}" does not exist')
            if m.control not in control_refs:
                add("error", where, f'common control "{m.control}" does not exist')
            elif m.control not in dep_controls:
                add("error", where, f'common control "{m.control}" is not in a library listed in depends_on')
            mapped_controls.add(m.control)
        for d in _duplicates([f"{m.requirement} -> {m.control}" for m in p.mappings]):
            add("error", "mappings.yaml", f'duplicate mapping "{d}"')

        # Questions and rules
        for d in _duplicates([q.ref for q in p.questions]):
            add("error", "questions.yaml", f'duplicate question ref "{d}"')
        for d in _duplicates([r.ref for r in p.rules]):
            add("error", "rules.yaml", f'duplicate rule ref "{d}"')
        for rule in p.rules:
            where = f"rules.yaml ({rule.ref})"
            parsed = parse_expression(rule.when)
            for i in parsed.issues:
                add("error", where, f"when {i.path}: {i.message}")
            for v in parsed.variables:
                if v not in question_refs:
                    add("error", where, f'references unknown question "{v}"')
            for t in rule.targets:
                known = {"requirement": req_refs, "group": group_refs, "control": control_refs,
                         "template_section": block_refs}[t.type]
                if t.ref not in known:
                    add("error", where, f'{t.type} target "{t.ref}" does not exist')
                if t.type == "requirement" and t.ref in mandatory:
                    add("error", where, f'requirement "{t.ref}" is mandatory; rules may not target it')
                if t.type == "group" and any(r.group == t.ref and r.mandatory for r in p.requirements):
                    add("error", where, f'group "{t.ref}" contains mandatory requirements; rules may not target it')

        # Templates
        for t in p.templates:
            where = display(t.path)
            found = [b.ref for b in t.blocks]
            declared = set(t.meta.sections)
            for b in found:
                if b not in declared:
                    add("error", where, f'block "{b}" is not listed in sections')
            for s in t.meta.sections:
                if s not in found:
                    add("error", where, f'section "{s}" has no matching block')
            fields = t.meta.merge_fields
            for b in t.blocks:
                paths, ph_issues = placeholders(b.body)
                for msg in ph_issues:
                    add("error", f"{where} ({b.ref})", msg)
                for path in paths:
                    if not any(path == f or path.startswith(f + ".") for f in fields):
                        add("error", f"{where} ({b.ref})", f'placeholder "{path}" is not declared in merge_fields')
            for s in t.meta.satisfies:
                refs = framework_refs.get(s.framework)
                if refs is None:
                    add("warning", where, f'satisfies framework "{s.framework}", which is not in this content set')
                elif s.ref not in refs:
                    add("error", where, f"satisfies {s.framework} {s.ref}, which does not exist")

        # Coverage
        if p.meta.kind == "framework":
            for r in p.requirements:
                if not r.mandatory and r.ref not in mapped_requirements:
                    add("warning", f"requirements.yaml ({r.ref})", "no common control is mapped to this requirement")

    for p in packs:
        for c in p.controls:
            if c.ref not in mapped_controls:
                issues.append(Issue("info", display(p.dir), f"controls.yaml ({c.ref})",
                                    "control is not mapped to any requirement"))
    return issues
