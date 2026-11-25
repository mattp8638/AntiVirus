"""ISMS content packs: the shipped packs validate, and the validator catches each kind of mistake.

Licence rule: every pack and every item records its licence basis, and identifier-and-title items (ISO, IEC, Crown
copyright pending) never carry requirement text. These tests are the CI gate for that rule.
"""

import copy

import pytest

from fenrir_cloud.isms.content import PACKS_ROOT, find_pack_dirs, load_pack, validate_packs
from fenrir_cloud.isms.content.loader import parse_yaml
from fenrir_cloud.isms.content.questionnaires import load_questionnaires
from fenrir_cloud.isms.content.template_blocks import parse_blocks, placeholders

EM = chr(0x2014)


@pytest.fixture(scope="module")
def pristine():
    return [load_pack(d) for d in find_pack_dirs(PACKS_ROOT, ("questionnaires",))]


@pytest.fixture
def raws(pristine):
    return copy.deepcopy(pristine)


def by_id(raws, pack_id):
    return next(r for r in raws if r.meta["id"] == pack_id)


def errors(raws):
    return [f"{i.where}: {i.message}" for i in validate_packs(raws).issues if i.severity == "error"]


def joined(raws):
    return "\n".join(errors(raws))


# The shipped packs -------------------------------------------------------------------------------------------

def test_shipped_packs_validate_with_no_errors_or_warnings(pristine):
    result = validate_packs(pristine)
    assert [i for i in result.issues if i.severity != "info"] == []
    assert sorted(p.meta.id for p in result.packs) == [
        "common-controls", "cyber-essentials", "iso22301-2019", "iso27001-2022", "iso42001-2023", "ncsc-caf",
        "nist-csf-2", "templates", "uk-gdpr"]


def test_iso27001_holds_93_annex_a_controls_and_mandatory_clauses(pristine):
    iso = next(p for p in validate_packs(pristine).packs if p.meta.id == "iso27001-2022")
    annex = [r for r in iso.requirements if r.ref.startswith("A.")]
    assert len(annex) == 93
    assert [sum(r.ref.startswith(f"A.{t}.") for r in annex) for t in (5, 6, 7, 8)] == [37, 8, 14, 34]
    clauses = [r for r in iso.requirements if not r.ref.startswith("A.")]
    assert all(r.mandatory for r in clauses)
    assert {r.ref.split(".")[0] for r in clauses} == {"4", "5", "6", "7", "8", "9", "10"}
    assert not any(r.mandatory for r in annex)


def test_every_annex_a_control_has_a_satisfying_common_control(pristine):
    iso = next(p for p in validate_packs(pristine).packs if p.meta.id == "iso27001-2022")
    satisfied = {m.requirement for m in iso.mappings if m.strength == "satisfies"}
    assert [r.ref for r in iso.requirements if r.ref.startswith("A.") and r.ref not in satisfied] == []


def test_restricted_packs_stay_at_identifier_and_title_level(pristine):
    for p in validate_packs(pristine).packs:
        if p.meta.licence in ("id-and-title", "crown-copyright-pending"):
            assert all(r.text is None for r in p.requirements), p.meta.id
    iso = next(p for p in validate_packs(pristine).packs if p.meta.id == "iso27001-2022")
    assert iso.meta.licence == "id-and-title"
    assert all(r.licence == "id-and-title" for r in iso.requirements)


def test_questionnaires_load():
    qs = load_questionnaires()
    assert qs and all(q.licence and q.questions for q in qs)


# Failure cases ----------------------------------------------------------------------------------------------

def test_rejects_an_item_with_no_licence(raws):
    del by_id(raws, "iso27001-2022").files["requirements"][3]["licence"]
    assert any("missing licence" in e for e in errors(raws))


def test_rejects_a_pack_with_no_licence(raws):
    del by_id(raws, "templates").meta["licence"]
    assert "pack.yaml: licence" in joined(raws)


def test_rejects_a_template_with_no_licence(raws):
    t = by_id(raws, "templates").templates[0]
    del t.front_matter["licence"]
    assert f"{t.path.name}: missing licence" in joined(raws)


def test_rejects_an_unknown_licence(raws):
    by_id(raws, "iso27001-2022").files["requirements"][0]["licence"] = "borrowed"
    assert 'unknown licence "borrowed"' in joined(raws)


def test_rejects_a_mapping_to_a_control_that_does_not_exist(raws):
    by_id(raws, "iso27001-2022").files["mappings"].append(
        {"requirement": "A.8.13", "control": "CC-NONE-01", "strength": "related", "rationale": "x",
         "licence": "original"})
    assert 'common control "CC-NONE-01" does not exist' in joined(raws)


def test_rejects_a_mapping_to_a_requirement_that_does_not_exist(raws):
    by_id(raws, "iso27001-2022").files["mappings"] = [
        {"requirement": "A.9.99", "control": "CC-BKP-01", "strength": "related", "rationale": "x",
         "licence": "original"}]
    assert 'requirement "A.9.99" does not exist' in joined(raws)


def test_rejects_a_rule_that_targets_a_mandatory_clause(raws):
    by_id(raws, "iso27001-2022").files["rules"][0]["targets"].append({"type": "requirement", "ref": "6.1.3"})
    assert '"6.1.3" is mandatory' in joined(raws)


def test_rejects_a_rule_that_targets_a_group_holding_mandatory_clauses(raws):
    by_id(raws, "iso27001-2022").files["rules"][0]["targets"] = [{"type": "group", "ref": "clause-6"}]
    assert 'group "clause-6" contains mandatory' in joined(raws)


def test_rejects_unknown_questions_targets_and_bad_expressions(raws):
    by_id(raws, "iso27001-2022").files["rules"] = [
        {"ref": "R-X-01", "reason": "r", "when": {"==": [{"var": "no_such_question"}, True]}, "effect": "include",
         "targets": [{"type": "template_section", "ref": "isp.nope"}], "licence": "original"},
        {"ref": "R-X-02", "reason": "r", "when": {"regex": ["a"]}, "effect": "include",
         "targets": [{"type": "control", "ref": "CC-BKP-01"}], "licence": "original"},
        {"ref": "R-X-03", "reason": "r", "effect": "include",
         "targets": [{"type": "control", "ref": "CC-BKP-01"}], "licence": "original"},
    ]
    e = joined(raws)
    assert 'unknown question "no_such_question"' in e
    assert 'template_section target "isp.nope" does not exist' in e
    assert 'unsupported operator "regex"' in e
    assert "expression is missing" in e


def test_rejects_an_em_dash_anywhere_in_a_pack(raws):
    fw = by_id(raws, "iso27001-2022")
    fw.text.append((fw.dir / "requirements.yaml", f"short_title: Bad {EM} title"))
    assert "em dash" in joined(raws)


def test_rejects_full_text_on_identifier_and_title_items(raws):
    by_id(raws, "iso27001-2022").files["requirements"][5]["text"] = "Copied normative text would go here."
    assert "not text" in joined(raws)


def test_rejects_full_text_on_crown_copyright_pending_items(raws):
    by_id(raws, "cyber-essentials").files["requirements"][0]["text"] = "Copied text."
    assert "not text" in joined(raws)


def test_rejects_short_titles_of_80_characters_or_more(raws):
    by_id(raws, "iso27001-2022").files["requirements"][4]["short_title"] = "x" * 80
    assert "under 80 characters" in joined(raws)


def test_rejects_duplicate_refs_and_unknown_fields(raws):
    controls = by_id(raws, "common-controls").files["controls"]
    second = controls[1]["ref"]
    controls.append({**controls[0], "extra": "field"})
    controls.append(dict(controls[1]))
    e = joined(raws)
    assert f'duplicate common control ref "{second}"' in e
    assert "extra: Extra inputs are not permitted" in e


def test_rejects_loose_scalars(raws):
    by_id(raws, "iso27001-2022").files["requirements"][0]["mandatory"] = "yes"
    assert "mandatory" in joined(raws)


def test_rejects_undeclared_placeholders_and_blocks(raws):
    t = by_id(raws, "templates").templates[0]
    t.body += "\n::: block isp.extra\nHello {{tenant.secret}}\n:::\n"
    e = joined(raws)
    assert 'placeholder "tenant.secret" is not declared' in e
    assert 'block "isp.extra" is not listed in sections' in e


def test_warns_when_a_requirement_has_no_mapped_control(raws):
    fw = by_id(raws, "iso27001-2022")
    fw.files["mappings"] = [m for m in fw.files["mappings"] if m["requirement"] != "A.8.13"]
    r = validate_packs(raws)
    assert r.ok
    assert any(i.severity == "warning" and i.where == "requirements.yaml (A.8.13)" for i in r.issues)


def test_reports_an_unknown_pack_file(tmp_path):
    (tmp_path / "pack.yaml").write_text("id: x\nkind: templates\npack_version: 1.0.0\nlicence: original\n")
    (tmp_path / "stuff.yaml").write_text("[]\n")
    assert any("unknown pack file" in e for e in errors([load_pack(tmp_path)]))


# YAML and template syntax -----------------------------------------------------------------------------------

def test_yaml_reads_only_true_and_false_as_booleans():
    errs: list[str] = []
    assert parse_yaml("a: no\nb: on\nc: true\nd: False\n", "x", errs) == {"a": "no", "b": "on", "c": True, "d": False}
    assert errs == []


def test_yaml_rejects_duplicate_keys():
    errs: list[str] = []
    parse_yaml("a: 1\na: 2\n", "x.yaml", errs)
    assert errs and 'duplicate key "a"' in errs[0]


def test_template_blocks_report_structure_problems():
    _, issues = parse_blocks("stray\n::: block a.b\n::: block a.c\nx\n:::\n:::\n::: block a.d\n")
    assert issues == ["line 1: content outside a block (wrap it in ::: block <ref>)",
                      'line 3: block "a.c" opened inside block "a.b"', "line 6: ::: closes no open block",
                      'line 7: block "a.d" is never closed']


def test_placeholders_skip_loop_bodies_and_check_helpers():
    paths, issues = placeholders("{{org.name}} {{#each controls}}{{ref}}{{/each}} {{#if x}}{{else}}{{/if}} {{#with y}}")
    assert paths == ["controls", "org.name", "x"]
    assert issues == ['unsupported helper "#with"']
    _, issues = placeholders("{{#if a}}{{/each}}")
    assert issues == ['"{{/each}}" does not close "if"']
