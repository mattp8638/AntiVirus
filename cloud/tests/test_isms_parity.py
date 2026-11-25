"""The Python ISMS engine gives exactly the standalone engine's results.

``fixtures/isms_parity.json.gz`` holds outputs recorded from the frozen standalone app by
``scripts/isms/parity_fixtures.mts``: 3,000 random expressions with mixed-type answers, malformed expressions, and 30
random onboarding profiles (with overrides) run through the applicability engine over every shipped pack.
"""

import gzip
import json
from functools import lru_cache
from pathlib import Path

import pytest

from fenrir_cloud.isms.domain.applicability import (
    ApplicabilityInput, GroupInput, MappingInput, OverrideInput, RequirementInput, RuleInput, Target,
    compute_applicability, diff_applicability,
)
from fenrir_cloud.isms.domain.expression import ExpressionError, evaluate, parse_expression

FIXTURE = Path(__file__).parent / "fixtures" / "isms_parity.json.gz"


@lru_cache(maxsize=1)
def fixture() -> dict:
    return json.loads(gzip.decompress(FIXTURE.read_bytes()))


def canon(v):
    """JSON text that tells true from 1 and treats 1.0 as 1, as JavaScript does."""
    def norm(x):
        if isinstance(x, float) and x.is_integer():
            return int(x)
        if isinstance(x, list):
            return [norm(y) for y in x]
        if isinstance(x, dict):
            return {k: norm(y) for k, y in x.items()}
        return x
    return json.dumps(norm(v), separators=(",", ":"))


def test_expressions_evaluate_as_in_the_standalone_engine():
    mismatches = []
    for case in fixture()["expressions"]:
        try:
            got = {"value": evaluate(case["expression"], case["answers"])}
        except ExpressionError:
            got = {"error": True}
        want = {"error": True} if case.get("error") else {"value": case["value"]}
        if canon(got) != canon(want):
            mismatches.append((case["expression"], case["answers"], want, got))
    assert mismatches == [], f"{len(mismatches)} mismatches, first: {mismatches[0]}"


def test_malformed_expressions_report_the_same_problems():
    for case in fixture()["parses"]:
        got = parse_expression(case["expression"])
        assert [(i.path, i.message) for i in got.issues] == [(i["path"], i["message"]) for i in case["issues"]]
        assert got.variables == case["variables"]


def _base() -> dict:
    b = fixture()["applicability"]["base"]
    return dict(
        groups=[GroupInput(g["framework"], g["ref"], g["parent"]) for g in b["groups"]],
        requirements=[RequirementInput(r["framework"], r["ref"], r["group"], r["mandatory"]) for r in b["requirements"]],
        controls=b["controls"], template_sections=b["templateSections"],
        mappings=[MappingInput(m["framework"], m["requirement"], m["control"], m["strength"]) for m in b["mappings"]],
        rules=[RuleInput(r["ref"], r["framework"], r["when"], r["effect"],
                         tuple(Target(t["type"], t["ref"]) for t in r["targets"]), r["reason"]) for r in b["rules"]],
    )


def _decision(d) -> dict:
    return {"type": d.type, "key": d.key, "applicable": d.applicable, "source": d.source, "reason": d.reason,
            "ruleRefs": list(d.rule_refs), "locked": d.locked, "justification": d.justification}


CASES = range(30)


@pytest.mark.parametrize("n", CASES)
def test_applicability_matches_the_standalone_engine(n):
    case = fixture()["applicability"]["cases"][n]
    overrides = [OverrideInput(o["type"], o["key"], o["applicable"], o["justification"]) for o in case["overrides"]]
    result = compute_applicability(ApplicabilityInput(answers=case["answers"], overrides=overrides, **_base()))
    got = [[k, _decision(d)] for k, d in result.decisions.items()]
    want = [[k, {f: d[f] for f in ("type", "key", "applicable", "source", "reason", "ruleRefs", "locked",
                                   "justification")}] for k, d in case["decisions"]]
    assert got == want  # same keys, same order, same reasons
    assert [(r.override.type, r.override.key, r.problem) for r in result.rejected_overrides] == [
        (r["override"]["type"], r["override"]["key"], r["problem"]) for r in case["rejected"]]


def test_applicability_diff_matches_the_standalone_engine():
    cases = fixture()["applicability"]["cases"]
    before = compute_applicability(ApplicabilityInput(answers=cases[0]["answers"], **_base())).decisions
    after = compute_applicability(ApplicabilityInput(answers=cases[1]["answers"], **_base())).decisions
    got = [{"key": c.key, "type": c.type, "item": c.item, "from": c.before, "to": c.after, "reason": c.reason}
           for c in diff_applicability(before, after)]
    assert got == fixture()["applicability"]["diff"]
    assert got  # the two profiles differ, so the diff is not trivially empty
