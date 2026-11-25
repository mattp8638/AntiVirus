"""ISMS domain logic: risk, readiness, tasks, reviews, digests, CSV import and nonconformities (ported from the
standalone app's unit tests)."""

import dataclasses
from datetime import datetime, timezone

import pytest

from fenrir_cloud.isms.domain import improvement, readiness, reports, review, risk, tasks
from fenrir_cloud.isms.domain._js import js_round, js_trim, parse_day
from fenrir_cloud.isms.domain.audit import draw_sample, suggested_sample_size
from fenrir_cloud.isms.domain.csv_import import CsvError, parse_csv, parse_csv_records
from fenrir_cloud.isms.domain.readiness import ReadinessRequirement as RR

M = risk.default_risk_method()


# Risk method ------------------------------------------------------------------------------------------------

def test_risk_default_method_is_valid():
    assert risk.validate_risk_method(M) == []
    assert risk.max_score(M) == 25


def test_risk_scores_and_bands():
    assert risk.risk_score(M, 3, 4) == 12
    assert risk.risk_score(M, None, 4) is None
    assert risk.risk_score(M, 6, 1) is None
    assert risk.risk_score(M, 1, 0) is None
    assert [risk.risk_level(M, s).level for s in (4, 5, 12, 25)] == ["low", "medium", "high", "critical"]
    assert risk.risk_level(M, None) is None


def test_risk_appetite():
    assert risk.within_appetite(M, 8) and not risk.within_appetite(M, 9) and not risk.within_appetite(M, None)


def test_risk_heat_map():
    grid, unrated = risk.heat_map(M, [(1, 1), (5, 4), (5, 4), (None, 2)])
    assert grid[0][0] == 1 and grid[3][4] == 2 and unrated == 1
    assert sum(map(sum, grid)) == 3


def test_risk_reports_invalid_methods():
    bad = dataclasses.replace(
        M, likelihood_scale=[risk.ScalePoint(1, "A", ""), risk.ScalePoint(3, "", "")],
        levels=[risk.LevelBand(2, "x", "X"), risk.LevelBand(2, "y", "Y"), risk.LevelBand(99, "z", "Z")],
        appetite=0, acceptance_criteria=" ", review_months=40)
    fields = {i.field for i in risk.validate_risk_method(bad)}
    assert {"likelihoodScale", "levels", "appetite", "acceptanceCriteria", "reviewMonths"} <= fields
    assert "Add at least one level." in [i.message for i in risk.validate_risk_method(dataclasses.replace(M, levels=[]))]


def test_risk_review_dates():
    assert risk.next_review_date(datetime(2026, 11, 18, 10, tzinfo=timezone.utc), 12) == "2027-11-18"
    assert risk.next_review_date(datetime(2026, 1, 31, 10, tzinfo=timezone.utc), 1) == "2026-02-28"
    assert risk.next_review_date(datetime(2026, 8, 31, 10, tzinfo=timezone.utc), 6) == "2027-02-28"


# Readiness --------------------------------------------------------------------------------------------------

def test_requirement_needs_every_implementing_control_evidenced():
    status = readiness.requirement_status
    assert status(RR("a", True, ("implemented_evidenced", "implemented_evidenced"))) == "met"
    assert status(RR("a", True, ("implemented_evidenced", "implemented"))) == "partial"
    assert status(RR("a", True, ("in_progress",))) == "partial"
    assert status(RR("a", True, ("not_started",))) == "not_met"
    assert status(RR("a", True, ("not_applicable",))) == "no_controls"
    assert status(RR("a", True, ())) == "no_controls"
    assert status(RR("a", False, ("implemented_evidenced",))) == "not_applicable"


def test_readiness_matches_the_hand_calculation():
    # 4 applicable with controls: 1 met, 2 partial, 1 not met; 1 not applicable; 1 clause without controls.
    r = readiness.compute_readiness([
        RR("A.8.13", True, ("implemented_evidenced",)), RR("A.8.5", True, ("implemented",)),
        RR("A.5.15", True, ("in_progress",)), RR("A.5.7", True, ("not_started",)),
        RR("A.8.25", False, ("not_applicable",)), RR("6.1.2", True, ()),
    ])
    assert (r.met, r.partial, r.not_met, r.applicable, r.not_applicable, r.without_controls, r.score) == (
        1, 2, 1, 4, 1, 1, 25)
    assert "requirements met" in r.formula
    assert readiness.compute_readiness([]).score is None


def test_readiness_rounds_halves_up_like_the_standalone_app():
    # 1 of 8 is 12.5 per cent; 1 of 16 is 6.25, which rounds to 6.3 (Python's round() would give 6.2).
    reqs = [RR(str(i), True, ("implemented_evidenced",) if i == 0 else ("not_started",)) for i in range(16)]
    assert readiness.compute_readiness(reqs).score == 6.3
    assert js_round(2.5) == 3 and js_round(-2.5) == -2


def test_control_coverage():
    c = readiness.control_coverage(["implemented_evidenced", "implemented", "not_applicable"])
    assert (c.evidenced, c.applicable, c.score) == (1, 2, 50)
    assert readiness.control_coverage(["not_applicable"]).score is None


# Tasks ------------------------------------------------------------------------------------------------------

def test_recurrence_maps_control_frequencies():
    assert tasks.recurrence_for("quarterly") == "quarterly"
    assert tasks.recurrence_for("continuous") is None
    assert tasks.recurrence_for("event-driven") is None
    assert tasks.recurrence_for(None) is None


def test_add_interval_clamps_month_ends():
    assert tasks.add_interval("2026-11-18", "daily") == "2026-11-19"
    assert tasks.add_interval("2026-11-18", "weekly") == "2026-11-25"
    assert tasks.add_interval("2026-01-31", "monthly") == "2026-02-28"
    assert tasks.add_interval("2026-11-30", "quarterly") == "2027-02-28"
    assert tasks.add_interval("2026-08-31", "six-monthly") == "2027-02-28"
    assert tasks.add_interval("2028-02-29", "annual") == "2029-02-28"
    with pytest.raises(ValueError):
        tasks.add_interval("nope", "daily")


def test_next_due_date_is_never_in_the_past():
    assert tasks.next_due_date("quarterly", None, "2026-11-18") == "2027-02-18"
    assert tasks.next_due_date("monthly", "2026-11-01", "2026-11-18") == "2026-12-01"
    assert tasks.next_due_date("monthly", "2026-01-01", "2026-11-18") == "2026-12-01"


def test_task_urgency_and_days():
    assert tasks.task_urgency("2026-11-17", "2026-11-18") == "overdue"
    assert tasks.task_urgency("2026-11-25", "2026-11-18") == "due_soon"
    assert tasks.task_urgency("2026-12-25", "2026-11-18") == "later"
    assert tasks.days_between("2026-11-01", "2026-11-18") == 17


def test_dates_roll_over_like_javascript():
    assert parse_day("2026-02-30").isoformat() == "2026-03-02"
    with pytest.raises(ValueError):
        parse_day("2026-02-32")
    assert js_trim("\ufeff x \u00a0") == "x"


# Management review and digests ------------------------------------------------------------------------------

def test_review_lists_missing_inputs():
    full = {i["key"]: {} for i in review.REVIEW_INPUTS}
    assert review.missing_inputs(full) == []
    assert review.missing_inputs({**full, "risk": None, "audits": None}) == ["audits", "risk"]
    assert {i["clause"][:7] for i in review.REVIEW_INPUTS} == {f"9.3.2 {c}" for c in "abcdefg"}


def test_review_period_start():
    assert review.review_period_start("2026-11-18", "2026-05-01") == "2026-05-01"
    assert review.review_period_start("2026-11-18", None) == "2025-11-18"
    assert review.review_period_start("2026-11-18", "2027-01-01") == "2025-11-18"
    assert review.review_period_start("2028-02-29", None) == "2027-03-01"


def _utc(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def test_weekly_digests_go_on_monday_mornings():
    # 18/11/2026 is a Wednesday.
    assert reports.next_digest_at(_utc("2026-11-18T12:00:00Z"), "weekly") == _utc("2026-11-23T07:00:00Z")
    assert reports.next_digest_at(_utc("2026-11-23T06:59:00Z"), "weekly") == _utc("2026-11-23T07:00:00Z")
    assert reports.next_digest_at(_utc("2026-11-23T07:00:00Z"), "weekly") == _utc("2026-11-30T07:00:00Z")


def test_monthly_digests_go_on_the_first():
    assert reports.next_digest_at(_utc("2026-11-18T12:00:00Z"), "monthly") == _utc("2026-12-01T07:00:00Z")
    assert reports.next_digest_at(_utc("2026-12-01T06:00:00Z"), "monthly") == _utc("2026-12-01T07:00:00Z")
    assert reports.next_digest_at(_utc("2026-12-31T23:00:00Z"), "monthly") == _utc("2027-01-01T07:00:00Z")


# CSV import -------------------------------------------------------------------------------------------------

def test_csv_quotes_commas_and_new_lines():
    assert parse_csv('a,b\r\n"x, y","say ""hi""\nthere"\n') == [["a", "b"], ["x, y", 'say "hi"\nthere']]


def test_csv_skips_blank_lines_and_bom_keeps_empty_fields():
    assert parse_csv("\ufeffa,,c\n\n,,\nd,e,f") == [["a", "", "c"], ["d", "e", "f"]]


def test_csv_rejects_an_unclosed_quote():
    with pytest.raises(CsvError, match="not closed"):
        parse_csv('"abc')


def test_csv_records_by_normalized_header():
    assert parse_csv_records("Name, Owner Email\nCRM , a@b.example\nShort") == (
        ["name", "owner_email"], [{"name": "CRM", "owner_email": "a@b.example"}, {"name": "Short", "owner_email": ""}])
    assert parse_csv_records("") == ([], [])


# Nonconformities --------------------------------------------------------------------------------------------

def nc(kind="nonconformity", status="open", root_cause=""):
    return improvement.NcState(kind, status, root_cause)


def test_nc_stage_walks_the_corrective_action_workflow():
    stage = improvement.nc_stage
    assert stage(nc(), []) == "needs_root_cause"
    assert stage(nc(root_cause="No checklist"), []) == "needs_actions"
    assert stage(nc(root_cause="x"), [True, False]) == "actions_in_progress"
    assert stage(nc(root_cause="x"), [True]) == "ready_for_check"
    assert stage(nc(status="closed"), []) == "closed"
    assert stage(nc(status="cancelled"), []) == "cancelled"
    assert stage(nc(kind="opportunity"), []) == "open_opportunity"


def test_effectiveness_blockers():
    b = improvement.effectiveness_blockers
    assert b(nc(), []) == ["Record the root cause.", "Plan at least one corrective action."]
    assert b(nc(root_cause="x"), [False]) == ["Complete every corrective action."]
    assert b(nc(root_cause="x"), [True]) == []
    assert len(b(nc(status="closed", root_cause="x"), [])) == 1
    assert len(b(nc(kind="opportunity"), [])) == 1


# Sampling ---------------------------------------------------------------------------------------------------

ITEMS = [{"id": f"item-{i:02d}"} for i in range(50)]


def key(x):
    return x["id"]


def test_sample_is_reproducible_and_independent_of_input_order():
    a = draw_sample(ITEMS, 10, "audit-2026", key)
    assert a == draw_sample(list(reversed(ITEMS)), 10, "audit-2026", key)
    assert len({key(x) for x in a}) == 10
    assert draw_sample(ITEMS, 10, "another seed", key) != a


def test_sample_small_populations_and_odd_sizes():
    assert len(draw_sample(ITEMS[:3], 10, "s", key)) == 3
    assert draw_sample(ITEMS, 0, "s", key) == []
    assert draw_sample(ITEMS, -2, "s", key) == []
    assert draw_sample([], 5, "s", key) == []


def test_suggested_sample_size_ladder():
    assert [suggested_sample_size(n) for n in (3, 20, 80, 200, 1000)] == [3, 5, 10, 15, 25]
