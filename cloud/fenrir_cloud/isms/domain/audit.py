"""Internal audit (ISO 27001 9.2): checklists, programme coverage, completion rules and reproducible sampling."""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal, TypeVar

from ._js import js_trim

T = TypeVar("T")


@dataclass(frozen=True)
class AuditableRequirement:
    framework: str
    ref: str
    title: str
    group_ref: str
    group_title: str
    mandatory: bool
    applicable: bool
    controls: tuple[str, ...]
    sort: float


@dataclass(frozen=True)
class ChecklistItem:
    framework: str
    ref: str
    title: str
    group_title: str
    mandatory: bool
    controls: str
    sort: int


def checklist_key(framework: str, ref: str) -> str:
    return f"{framework}:{ref}"


def build_checklist(requirements: list[AuditableRequirement], groups: list[str] | None = None) -> list[ChecklistItem]:
    """Every mandatory clause and every applicable requirement, optionally limited to some groups."""
    wanted = set(groups) if groups else None
    picked = [r for r in requirements if (r.mandatory or r.applicable) and (wanted is None or r.group_ref in wanted)]
    picked.sort(key=lambda r: (r.framework, r.sort))
    return [ChecklistItem(r.framework, r.ref, r.title, r.group_title, r.mandatory, ", ".join(r.controls), i)
            for i, r in enumerate(picked)]


@dataclass(frozen=True)
class Coverage:
    required: int
    covered: int
    percent: int
    missing: list[dict]


def programme_coverage(requirements: list[AuditableRequirement], covered_keys: Iterable[str]) -> Coverage:
    """How much of what must be audited the programme's audits cover."""
    covered = set(covered_keys)
    required = [r for r in requirements if r.mandatory or r.applicable]
    missing = [{"framework": r.framework, "ref": r.ref, "title": r.title} for r in required
               if checklist_key(r.framework, r.ref) not in covered]
    n = len(required)
    c = n - len(missing)
    return Coverage(n, c, math.floor(c / n * 100) if n else 100, missing)


CheckResult = Literal["conforms", "observation", "minor", "major", "not_assessed"]


@dataclass(frozen=True)
class AuditForCompletion:
    status: Literal["planned", "in_progress", "completed"]
    independence_note: str
    summary: str
    results: tuple[CheckResult | None, ...]


def audit_completion_blockers(a: AuditForCompletion) -> list[str]:
    out = []
    if a.status != "in_progress":
        out.append("Start the audit before completing it.")
    if not a.results:
        out.append("Generate the checklist.")
    left = sum(1 for r in a.results if r is None)
    if left:
        out.append(f"Record a result for every checklist item ({left} left).")
    if not js_trim(a.independence_note):
        out.append("Record how the auditors are independent of the areas audited.")
    if not js_trim(a.summary):
        out.append("Write the audit summary.")
    return out


def result_counts(results: list[CheckResult | None]) -> dict[str, int]:
    return {"conforms": results.count("conforms"), "observation": results.count("observation"),
            "minor": results.count("minor"), "major": results.count("major"),
            "notAssessed": results.count("not_assessed"), "open": results.count(None)}


# Sampling: the same population, size and seed always give the same sample, so an auditor's sample can be re-drawn
# and checked. FNV-1a seed, mulberry32 PRNG, partial Fisher-Yates shuffle, bit for bit as in the standalone app.

def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _imul(a: int, b: int) -> int:
    """Math.imul as an unsigned 32-bit value (every operation below is the same modulo 2^32)."""
    return _u32(a * b)


def _utf16_units(s: str) -> list[int]:
    data = s.encode("utf-16-le")
    return [data[i] | (data[i + 1] << 8) for i in range(0, len(data), 2)]


def _seed_number(seed: str) -> int:
    h = 2166136261
    for unit in _utf16_units(seed):  # charCodeAt reads UTF-16 code units
        h = _imul(h ^ unit, 16777619)
    return h


def _mulberry32(a: int) -> Callable[[], float]:
    state = _u32(a)

    def rand() -> float:
        nonlocal state
        state = _u32(state + 0x6D2B79F5)
        t = _imul(state ^ (state >> 15), 1 | state)
        t = _u32(t + _imul(t ^ (t >> 7), 61 | t)) ^ t
        return (t ^ (t >> 14)) / 4294967296

    return rand


def draw_sample(items: list[T], size: float, seed: str, key: Callable[[T], str]) -> list[T]:
    """Picks ``size`` items (or all, if fewer) in a stable order, sorted by key first so input order does not matter."""
    pool = sorted(items, key=key)
    n = min(max(0, math.floor(size)), len(pool))
    rand = _mulberry32(_seed_number(seed))
    for i in range(n):
        j = i + math.floor(rand() * (len(pool) - i))
        pool[i], pool[j] = pool[j], pool[i]
    return pool[:n]


def suggested_sample_size(population: int) -> int:
    if population <= 5:
        return population
    if population <= 25:
        return 5
    if population <= 100:
        return 10
    if population <= 250:
        return 15
    return 25
