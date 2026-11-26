"""ISMS applicability engine (ported from the standalone engine's tests)."""

import dataclasses

from fenrir_cloud.isms.domain.applicability import (
    ApplicabilityInput, GroupInput, MappingInput, OverrideInput, RequirementInput, RuleInput, Target,
    compute_applicability, diff_applicability,
)


def rule(ref, effect, reason, targets, when=True):
    return RuleInput(ref=ref, framework="iso", when=when, effect=effect, reason=reason,
                     targets=tuple(Target(t, r) for t, r in targets))


def base(answers, **extra) -> ApplicabilityInput:
    inp = ApplicabilityInput(
        answers=answers,
        groups=[GroupInput("iso", "clause-6"), GroupInput("iso", "annex-a"),
                GroupInput("iso", "annex-a-7", "annex-a"), GroupInput("iso", "annex-a-8", "annex-a")],
        requirements=[RequirementInput("iso", "6.1.3", "clause-6", True),
                      RequirementInput("iso", "A.7.1", "annex-a-7", False),
                      RequirementInput("iso", "A.8.13", "annex-a-8", False),
                      RequirementInput("iso", "A.8.25", "annex-a-8", False)],
        controls=["CC-BKP-01", "CC-DEV-01", "CC-PHY-01", "CC-ORPHAN-01"],
        template_sections=["isp.purpose", "isp.secure-development"],
        mappings=[MappingInput("iso", "A.7.1", "CC-PHY-01", "satisfies"),
                  MappingInput("iso", "A.8.13", "CC-BKP-01", "satisfies"),
                  MappingInput("iso", "A.8.25", "CC-DEV-01", "satisfies"),
                  MappingInput("iso", "A.8.13", "CC-ORPHAN-01", "related")],
        rules=[rule("R-DEV-01", "exclude", "No in-house development.",
                    [("requirement", "A.8.25"), ("control", "CC-DEV-01"),
                     ("template_section", "isp.secure-development")],
                    when={"==": [{"var": "develops_software"}, False]}),
               rule("R-PHY-01", "exclude", "No premises.", [("group", "annex-a-7")],
                    when={"==": [{"var": "has_premises"}, False]})],
    )
    return dataclasses.replace(inp, **extra)


def get(inp, key):
    return compute_applicability(inp).decisions[key]


def test_includes_everything_by_default_with_a_reason():
    r = compute_applicability(base({"develops_software": True, "has_premises": True}))
    assert all(d.reason for d in r.decisions.values())
    d = r.decisions["requirement:iso:A.8.25"]
    assert (d.applicable, d.source) == (True, "default")
    c = r.decisions["control:CC-DEV-01"]
    assert (c.applicable, c.source, c.reason) == (True, "derived", "Needed for iso A.8.25.")
    assert r.decisions["template_section:isp.secure-development"].applicable


def test_excludes_rule_targets_with_the_rule_reason():
    r = compute_applicability(base({"develops_software": False, "has_premises": True}))
    d = r.decisions["requirement:iso:A.8.25"]
    assert (d.applicable, d.source, d.rule_refs, d.reason) == (False, "rule", ("R-DEV-01",), "No in-house development.")
    assert not r.decisions["control:CC-DEV-01"].applicable
    assert not r.decisions["template_section:isp.secure-development"].applicable
    assert r.decisions["requirement:iso:A.8.13"].applicable


def test_applies_group_targets_to_requirements_in_the_group():
    inp = base({"develops_software": True, "has_premises": False})
    d = get(inp, "requirement:iso:A.7.1")
    assert (d.applicable, d.rule_refs) == (False, ("R-PHY-01",))
    c = get(inp, "control:CC-PHY-01")
    assert (c.applicable, c.reason) == (False, "No applicable requirement maps to this control.")


def test_applies_group_targets_to_descendant_groups():
    inp = base({"develops_software": True, "has_premises": True})
    inp.rules.append(rule("R-ALL-01", "exclude", "Everything off.", [("group", "annex-a")]))
    assert not get(inp, "requirement:iso:A.8.13").applicable
    assert get(inp, "requirement:iso:6.1.3").applicable


def test_never_excludes_mandatory_requirements():
    inp = base({}, overrides=[OverrideInput("requirement", "iso:6.1.3", False, "We do not want this.")])
    inp.rules.append(rule("R-BAD-01", "exclude", "x", [("requirement", "6.1.3")]))
    r = compute_applicability(inp)
    d = r.decisions["requirement:iso:6.1.3"]
    assert (d.applicable, d.source, d.locked) == (True, "mandatory", True)
    assert "Mandatory" in r.rejected_overrides[0].problem


def test_require_beats_include_beats_exclude():
    inp = base({"develops_software": False})
    inp.rules.append(rule("R-INC-01", "include", "Contract demands it.", [("requirement", "A.8.25")]))
    d = get(inp, "requirement:iso:A.8.25")
    assert (d.applicable, d.rule_refs, d.locked) == (True, ("R-INC-01",), False)
    inp.rules.append(rule("R-REQ-01", "require", "Regulator requires it.", [("requirement", "A.8.25")]))
    d = get(inp, "requirement:iso:A.8.25")
    assert (d.applicable, d.rule_refs, d.locked) == (True, ("R-REQ-01",), True)


def test_accepts_justified_overrides_and_rejects_unjustified_or_locked_ones():
    inp = base({"develops_software": False, "has_premises": True}, overrides=[
        OverrideInput("requirement", "iso:A.8.25", True, "We are starting a dev team."),
        OverrideInput("requirement", "iso:A.8.13", False, "  "),
        OverrideInput("control", "CC-NOPE-01", False, "x"),
    ])
    inp.rules.append(rule("R-REQ-02", "require", "Required.", [("template_section", "isp.purpose")]))
    inp.overrides.append(OverrideInput("template_section", "isp.purpose", False, "Remove it."))
    r = compute_applicability(inp)
    d = r.decisions["requirement:iso:A.8.25"]
    assert (d.applicable, d.source, d.justification) == (True, "override", "We are starting a dev team.")
    assert r.decisions["requirement:iso:A.8.13"].applicable
    assert [x.problem for x in r.rejected_overrides] == [
        "A justification is required.", "Required by R-REQ-02.", "No such item in the programme."]


def test_ignores_related_mappings_when_deriving_controls():
    assert not get(base({}), "control:CC-ORPHAN-01").applicable


def test_keeps_a_control_on_when_an_include_rule_targets_it_without_a_requirement():
    inp = base({}, mappings=[])
    inp.rules.append(rule("R-INC-02", "include", "Customer contract.", [("control", "CC-ORPHAN-01")]))
    d = get(inp, "control:CC-ORPHAN-01")
    assert (d.applicable, d.source) == (True, "rule")


def test_is_deterministic():
    a = list(compute_applicability(base({"develops_software": False})).decisions.items())
    b = list(compute_applicability(base({"develops_software": False})).decisions.items())
    assert a == b


def test_diff_lists_items_that_switch_when_an_answer_changes():
    before = compute_applicability(base({"develops_software": True, "has_premises": True})).decisions
    after = compute_applicability(base({"develops_software": False, "has_premises": True})).decisions
    assert [(c.key, c.before, c.after) for c in diff_applicability(before, after)] == [
        ("control:CC-DEV-01", True, False),
        ("requirement:iso:A.8.25", True, False),
        ("template_section:isp.secure-development", True, False),
    ]
    assert diff_applicability(before, before) == []


def test_diff_reports_items_added_or_removed():
    before = compute_applicability(base({})).decisions
    smaller = base({}, template_sections=["isp.purpose"])
    changes = diff_applicability(before, compute_applicability(smaller).decisions)
    assert len(changes) == 1
    c = changes[0]
    assert (c.key, c.type, c.item, c.before, c.after, c.reason) == (
        "template_section:isp.secure-development", "template_section", "isp.secure-development", True, None,
        "Removed from the programme.")
    back = diff_applicability(compute_applicability(smaller).decisions, before)[0]
    assert (back.before, back.after) == (None, True)
