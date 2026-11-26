"""Applicability engine. Pure and deterministic: the same inputs always give the same applicability set, with a
reason for every item.

Precedence for an item: mandatory > override > require > include > exclude > default. Mandatory requirements cannot
be excluded by anything. Manual overrides need a justification and cannot exclude an item a rule requires.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Literal

from .expression import Answers, matches

TargetType = Literal["group", "requirement", "control", "template_section"]
Effect = Literal["include", "exclude", "require"]
ItemType = Literal["requirement", "control", "template_section"]
Source = Literal["default", "mandatory", "rule", "override", "derived"]


@dataclass(frozen=True)
class RequirementInput:
    framework: str
    ref: str
    group: str
    mandatory: bool


@dataclass(frozen=True)
class GroupInput:
    framework: str
    ref: str
    parent: str | None = None


@dataclass(frozen=True)
class MappingInput:
    framework: str
    requirement: str
    control: str
    strength: Literal["satisfies", "partial", "related"]


@dataclass(frozen=True)
class Target:
    type: TargetType
    ref: str


@dataclass(frozen=True)
class RuleInput:
    ref: str
    framework: str  # the framework the rule's group and requirement targets belong to
    when: Any
    effect: Effect
    targets: tuple[Target, ...]
    reason: str


@dataclass(frozen=True)
class OverrideInput:
    type: ItemType
    key: str  # for requirements "<framework>:<ref>", otherwise the ref
    applicable: bool
    justification: str


@dataclass
class ApplicabilityInput:
    answers: Answers
    groups: list[GroupInput]
    requirements: list[RequirementInput]
    controls: list[str]
    template_sections: list[str]
    mappings: list[MappingInput]
    rules: list[RuleInput]
    overrides: list[OverrideInput] = field(default_factory=list)


@dataclass(frozen=True)
class Decision:
    type: ItemType
    key: str
    applicable: bool
    source: Source
    reason: str
    rule_refs: tuple[str, ...]
    locked: bool  # true when a manual override is not allowed (mandatory or required by a rule)
    justification: str | None = None


@dataclass(frozen=True)
class RejectedOverride:
    override: OverrideInput
    problem: str


@dataclass
class ApplicabilityResult:
    decisions: dict[str, Decision]  # insertion order matches the standalone engine
    rejected_overrides: list[RejectedOverride]


def item_key(type_: str, key: str) -> str:
    return f"{type_}:{key}"


def requirement_key(framework: str, ref: str) -> str:
    return f"{framework}:{ref}"


_RANK = {"require": 3, "include": 2, "exclude": 1}


def _strongest(hits: list[tuple[str, RuleInput]]) -> tuple[str, list[RuleInput]] | None:
    if not hits:
        return None
    top = max(_RANK[e] for e, _ in hits)
    effect = next(e for e, r in _RANK.items() if r == top)
    unique: dict[str, RuleInput] = {}
    for e, rule in hits:
        if e == effect:
            unique[rule.ref] = rule  # the last rule with a ref wins, as in a JavaScript Map
    return effect, [unique[k] for k in sorted(unique)]


def _from_rules(type_: ItemType, key: str, hit: tuple[str, list[RuleInput]]) -> Decision:
    effect, rules = hit
    return Decision(type_, key, applicable=effect != "exclude", source="rule",
                    reason=" ".join(r.reason for r in rules), rule_refs=tuple(r.ref for r in rules),
                    locked=effect == "require")


def compute_applicability(inp: ApplicabilityInput) -> ApplicabilityResult:
    # 1. Which rules fire.
    firing = [r for r in inp.rules if matches(r.when, inp.answers)]

    # 2. Rule hits per item. Group targets reach every requirement in the group and its descendants.
    children: dict[str, list[str]] = {}
    for g in inp.groups:
        if g.parent:
            children.setdefault(requirement_key(g.framework, g.parent), []).append(g.ref)

    def descendants(framework: str, ref: str) -> set[str]:
        out, stack = {ref}, [ref]
        while stack:
            cur = stack.pop()
            for c in children.get(requirement_key(framework, cur), []):
                if c not in out:
                    out.add(c)
                    stack.append(c)
        return out

    hits: dict[str, list[tuple[str, RuleInput]]] = {}

    def add_hit(k: str, rule: RuleInput) -> None:
        hits.setdefault(k, []).append((rule.effect, rule))

    for rule in firing:
        for t in rule.targets:
            if t.type == "requirement":
                add_hit(item_key("requirement", requirement_key(rule.framework, t.ref)), rule)
            elif t.type in ("control", "template_section"):
                add_hit(item_key(t.type, t.ref), rule)
            else:
                groups = descendants(rule.framework, t.ref)
                for r in inp.requirements:
                    if r.framework == rule.framework and r.group in groups:
                        add_hit(item_key("requirement", requirement_key(r.framework, r.ref)), rule)

    decisions: dict[str, Decision] = {}
    rejected: list[RejectedOverride] = []
    overrides: dict[str, OverrideInput] = {}
    for o in inp.overrides:
        overrides[item_key(o.type, o.key)] = o  # a later duplicate wins but keeps the first one's place

    def apply_override(d: Decision) -> Decision:
        k = item_key(d.type, d.key)
        o = overrides.pop(k, None)
        if o is None:
            return d
        justification = o.justification.strip()
        if not justification:
            rejected.append(RejectedOverride(o, "A justification is required."))
            return d
        if d.locked and not o.applicable:
            problem = ("Mandatory requirements cannot be excluded." if d.source == "mandatory"
                       else f"Required by {', '.join(d.rule_refs)}.")
            rejected.append(RejectedOverride(o, problem))
            return d
        return replace(d, applicable=o.applicable, source="override", reason=justification,
                       justification=justification, locked=False)

    # 3. Requirements.
    for r in inp.requirements:
        key = requirement_key(r.framework, r.ref)
        if r.mandatory:
            d = Decision("requirement", key, True, "mandatory", "Mandatory requirement of the framework.", (), True)
        else:
            hit = _strongest(hits.get(item_key("requirement", key), []))
            d = (_from_rules("requirement", key, hit) if hit else
                 Decision("requirement", key, True, "default", "In scope of the selected framework.", (), False))
        decisions[item_key("requirement", key)] = apply_override(d)

    # 4. Controls: applicable when an applicable requirement maps to them, unless a rule or override says otherwise.
    supporting: dict[str, list[str]] = {}
    for m in inp.mappings:
        if m.strength == "related":
            continue
        req = decisions.get(item_key("requirement", requirement_key(m.framework, m.requirement)))
        if req is not None and req.applicable:
            supporting.setdefault(m.control, []).append(f"{m.framework} {m.requirement}")
    for c in sorted(inp.controls):
        hit = _strongest(hits.get(item_key("control", c), []))
        reqs = sorted(set(supporting.get(c, [])))
        if hit and hit[0] != "include":
            d = _from_rules("control", c, hit)
        elif reqs:
            d = Decision("control", c, True, "derived", f"Needed for {', '.join(reqs)}.",
                         tuple(r.ref for r in hit[1]) if hit else (), False)
        elif hit:
            d = _from_rules("control", c, hit)
        else:
            d = Decision("control", c, False, "derived", "No applicable requirement maps to this control.", (), False)
        decisions[item_key("control", c)] = apply_override(d)

    # 5. Template sections.
    for s in sorted(inp.template_sections):
        hit = _strongest(hits.get(item_key("template_section", s), []))
        d = (_from_rules("template_section", s, hit) if hit else
             Decision("template_section", s, True, "default", "Included by default.", (), False))
        decisions[item_key("template_section", s)] = apply_override(d)

    for o in overrides.values():
        rejected.append(RejectedOverride(o, "No such item in the programme."))
    return ApplicabilityResult(decisions, rejected)


@dataclass(frozen=True)
class Change:
    key: str
    type: ItemType
    item: str
    before: bool | None
    after: bool | None
    reason: str


def diff_applicability(before: dict[str, Decision], after: dict[str, Decision]) -> list[Change]:
    """Items that switch on or off (or appear or disappear) between two runs, for review before applying."""
    out: list[Change] = []
    for k in sorted(set(before) | set(after)):
        a, b = before.get(k), after.get(k)
        if (a.applicable if a else None) == (b.applicable if b else None):
            continue
        d = b or a
        out.append(Change(k, d.type, d.key, a.applicable if a else None, b.applicable if b else None,
                          b.reason if b else "Removed from the programme."))
    return out
