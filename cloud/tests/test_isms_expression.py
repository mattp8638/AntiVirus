"""ISMS applicability expressions (ported from the standalone engine's tests)."""

import pytest

from fenrir_cloud.isms.domain.expression import ExpressionError, evaluate, matches, parse_expression


def test_collects_variables_from_nested_expressions():
    r = parse_expression({"and": [{"==": [{"var": "develops_software"}, False]},
                                  {"in": ["health", {"var": "data_types"}]}]})
    assert r.issues == []
    assert r.variables == ["data_types", "develops_software"]


def test_rejects_unknown_operators():
    assert 'unsupported operator "regex"' in parse_expression({"regex": ["a", "b"]}).issues[0].message


def test_rejects_wrong_arity():
    assert "takes 2 to 2" in parse_expression({"==": [1]}).issues[0].message
    assert len(parse_expression({"if": [True, 1]}).issues) == 1


def test_rejects_nodes_with_several_keys():
    assert "exactly one key" in parse_expression({"==": [1, 1], "!=": [1, 2]}).issues[0].message


def test_rejects_an_empty_or_non_string_var():
    assert len(parse_expression({"var": ""}).issues) == 1
    assert len(parse_expression({"var": [3]}).issues) == 1


def test_reports_a_missing_expression():
    assert parse_expression().issues[0].message == "expression is missing"


def test_accepts_literals_and_arrays_of_literals():
    assert parse_expression(True).issues == []
    assert parse_expression([1, "a", None]).issues == []
    assert parse_expression(None).issues == []  # null is a literal, not a missing expression


def test_visits_the_default_of_a_var():
    assert parse_expression({"var": ["a", {"var": "b"}]}).variables == ["a", "b"]


ANSWERS = {"develops_software": False, "headcount": 120, "data_types": ["personal", "payment_card"],
           "sector": "logistics"}


def test_evaluates_equality():
    assert matches({"==": [{"var": "develops_software"}, False]}, ANSWERS) is True
    assert matches({"!=": [{"var": "sector"}, "logistics"]}, ANSWERS) is False
    assert matches({"===": [{"var": "headcount"}, 120]}, ANSWERS) is True
    assert matches({"!==": [{"var": "headcount"}, "120"]}, ANSWERS) is True


def test_applies_loose_equality_across_types():
    assert evaluate({"==": [1, "1"]}, {}) is True
    assert evaluate({"==": [True, 1]}, {}) is True
    assert evaluate({"==": [None, 0]}, {}) is False
    assert evaluate({"==": [{"var": "missing"}, None]}, {}) is True
    assert evaluate({"===": [True, 1]}, {}) is False  # Python's True == 1 must not leak through
    assert evaluate({"===": [1, 1.0]}, {}) is True


def test_compares_numbers_and_strings():
    assert matches({">": [{"var": "headcount"}, 50]}, ANSWERS)
    assert matches({">=": [{"var": "headcount"}, 120]}, ANSWERS)
    assert not matches({"<": [{"var": "headcount"}, 50]}, ANSWERS)
    assert matches({"<=": ["a", "b"]}, ANSWERS)
    assert not matches({"<": [{"var": "missing"}, 5]}, ANSWERS)
    assert not matches({"<": [5, [1]]}, ANSWERS)
    assert matches({"<": [5, "10"]}, ANSWERS)  # mixed types compare as numbers, as in JavaScript
    assert not matches({"<": ["abc", 10]}, ANSWERS)


def test_handles_logic_operators_with_short_circuit_values():
    result = evaluate({"and": [True, "x", 0]}, {})
    assert result == 0 and not isinstance(result, bool)
    assert evaluate({"and": [1, 2]}, {}) == 2
    assert evaluate({"or": [0, "", "y"]}, {}) == "y"
    assert evaluate({"or": [0, False]}, {}) is False
    assert evaluate({"!": [[]]}, {}) is True
    assert evaluate({"!!": [[1]]}, {}) is True


def test_checks_membership_in_arrays_and_strings():
    assert matches({"in": ["payment_card", {"var": "data_types"}]}, ANSWERS)
    assert not matches({"in": ["health", {"var": "data_types"}]}, ANSWERS)
    assert matches({"in": ["gist", {"var": "sector"}]}, ANSWERS)
    assert not matches({"in": ["x", 5]}, ANSWERS)


def test_supports_if_and_var_defaults():
    assert evaluate({"if": [{"var": "develops_software"}, "dev", "no-dev"]}, ANSWERS) == "no-dev"
    assert evaluate({"if": [True, "a", "b"]}, {}) == "a"
    assert evaluate({"var": ["unanswered", "default"]}, {}) == "default"
    assert evaluate([{"var": "sector"}, 1], ANSWERS) == ["logistics", 1]


def test_throws_on_an_invalid_expression():
    with pytest.raises(ExpressionError):
        evaluate({"nope": []}, {})
