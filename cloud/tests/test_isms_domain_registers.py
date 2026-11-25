"""ISMS domain logic: audit checklists, objectives, people, privacy, suppliers, incidents, continuity and AI
management (ported from the standalone app's unit tests)."""

import dataclasses
import re

import pytest

from fenrir_cloud.isms.domain import ai_management as ai
from fenrir_cloud.isms.domain import audit, continuity, objectives, people, privacy, suppliers


# Audit checklists -------------------------------------------------------------------------------------------

def req(ref, **over):
    base = dict(framework="iso27001", ref=ref, title=f"Title {ref}",
                group_ref="annex-a-5" if ref.startswith("A.") else "clause-4", group_title="Group",
                mandatory=not ref.startswith("A."), applicable=True, controls=(),
                sort=int(re.sub(r"\D", "", ref)))
    return audit.AuditableRequirement(**{**base, **over})


REQS = [req("4.1"), req("A.5.2", controls=("CC-GOV-01", "CC-GOV-02")), req("A.5.1"),
        req("A.8.28", applicable=False, group_ref="annex-a-8"), req("4.2", applicable=False)]


def test_checklist_includes_mandatory_clauses_and_applicable_controls_in_order():
    items = audit.build_checklist(REQS)
    assert [i.ref for i in items] == ["4.1", "4.2", "A.5.1", "A.5.2"]
    assert items[3].controls == "CC-GOV-01, CC-GOV-02"
    assert [i.sort for i in items] == [0, 1, 2, 3]


def test_checklist_can_be_limited_to_groups():
    assert [i.ref for i in audit.build_checklist(REQS, ["annex-a-5"])] == ["A.5.1", "A.5.2"]


def test_programme_coverage():
    c = audit.programme_coverage([req("4.1"), req("A.5.1"), req("A.8.28", applicable=False)], ["iso27001:4.1"])
    assert (c.required, c.covered, c.percent, c.missing) == (
        2, 1, 50, [{"framework": "iso27001", "ref": "A.5.1", "title": "Title A.5.1"}])
    assert audit.programme_coverage([], []).percent == 100


def test_audit_completion_blockers():
    b = audit.audit_completion_blockers
    assert len(b(audit.AuditForCompletion("planned", "", "", ()))) == 4
    assert b(audit.AuditForCompletion("in_progress", "External auditor", "", ("conforms", None))) == [
        "Record a result for every checklist item (1 left).", "Write the audit summary."]
    assert b(audit.AuditForCompletion("in_progress", "x", "y", ("conforms",))) == []


def test_audit_result_counts():
    c = audit.result_counts(["conforms", "minor", None, "minor"])
    assert (c["conforms"], c["minor"], c["open"]) == (1, 2, 1)


# Objectives -------------------------------------------------------------------------------------------------

def v(day, value):
    return objectives.Measurement(day, value)


def test_objective_health_trend_and_staleness_when_higher_is_better():
    s = objectives.summarize_objective([v("2026-10-01", 80), v("2026-09-01", 70)], "at_least", 90, "monthly",
                                       "2026-10-15")
    assert s == objectives.ObjectiveSummary(v("2026-10-01", 80), "not_met", "improving", False)
    s = objectives.summarize_objective([v("2026-01-01", 95)], "at_least", 90, "monthly", "2026-10-15")
    assert (s.health, s.trend, s.stale) == ("met", "unknown", True)


def test_objective_lower_is_better():
    s = objectives.summarize_objective([v("2026-09-01", 5), v("2026-10-01", 7)], "at_most", 4, "quarterly",
                                       "2026-10-02")
    assert (s.health, s.trend) == ("not_met", "worsening")
    s = objectives.summarize_objective([v("2026-09-01", 3), v("2026-10-01", 3)], "at_most", 4, "annual",
                                       "2026-10-02")
    assert (s.health, s.trend) == ("met", "steady")
    assert objectives.summarize_objective([], "at_most", 4, "annual", "2026-10-02").health == "no_data"
    assert objectives.meets_target(4, "at_most", 4)


def test_chart_geometry():
    g = objectives.chart_geometry([v("2026-02-01", 50), v("2026-01-01", 0)], 100, 216, 116)
    assert [p.measured_on for p in g.points] == ["2026-01-01", "2026-02-01"]
    assert (g.points[0].x, g.points[0].y, g.points[1].x, g.target_y) == (8, 108, 208, 8)
    assert objectives.chart_geometry([v("2026-01-01", 5)], 5, 100, 50).points[0].x == 50


# People -----------------------------------------------------------------------------------------------------

def test_raci_accepts_one_accountable_and_a_responsible():
    cells = [people.RaciCell("a", "r1", "A"), people.RaciCell("a", "r2", "R"), people.RaciCell("a", "r3", "I")]
    assert people.raci_issues(["a"], cells) == []


def test_raci_reports_missing_and_duplicate_roles():
    cells = [people.RaciCell("a", "r1", "A"), people.RaciCell("a", "r2", "A"), people.RaciCell("a", "r3", "R"),
             people.RaciCell("b", "r1", "C")]
    assert [(i.activity_id, i.problem) for i in people.raci_issues(["a", "b", "c"], cells)] == [
        ("a", "several_accountable"), ("b", "no_accountable"), ("b", "no_responsible"), ("c", "no_accountable"),
        ("c", "no_responsible")]


def test_competence_status_by_expiry():
    s = people.competence_status
    assert s(None, "2026-11-18") == "no_expiry"
    assert s("2026-11-17", "2026-11-18") == "expired"
    assert s("2026-11-18", "2026-11-18") == "expiring"
    assert s("2026-12-18", "2026-11-18") == "expiring"
    assert s("2026-12-19", "2026-11-18") == "current"
    assert s("2026-11-25", "2026-11-18", 5) == "current"


def test_ack_progress_counts_targeted_people_once():
    assert people.ack_progress(["u1", "u2", "u3"], ["u1", "u1", "u9"]) == people.AckProgress(3, 1, 33)
    assert people.ack_progress([], []) == people.AckProgress(0, 0, 100)


# Privacy ----------------------------------------------------------------------------------------------------

def test_dpia_screening():
    assert not privacy.dpia_required({}).required
    assert not privacy.dpia_required({"profiling": True}).required
    assert privacy.dpia_required({"automated_decisions": True}).required
    r = privacy.dpia_required({"profiling": True, "tracking": True})
    assert r.required and len(r.reasons) == 2


ROPA = privacy.ProcessingRecord("contract", False, "", False, None, "6 years after the contract ends", ("Customers",),
                                ("Contact details",), False, False)


def test_processing_record_gaps():
    assert privacy.processing_gaps(ROPA) == []
    bad = dataclasses.replace(ROPA, lawful_basis=None, special_category=True, transfers=True, retention=" ",
                              data_subjects=(), data_categories=(), dpia_required=True)
    assert len(privacy.processing_gaps(bad)) == 7


def test_dpia_risk():
    assert privacy.dpia_risk_level("low", "low") == "low"
    assert privacy.dpia_risk_level("low", "high") == "medium"
    assert privacy.dpia_risk_level("medium", "high") == "high"
    assert not privacy.prior_consultation_needed(["medium"])
    assert privacy.prior_consultation_needed(["low", "high"])


def test_calendar_months_end_on_the_last_day_of_shorter_months():
    assert privacy.add_calendar_months("2026-03-15", 1) == "2026-04-15"
    assert privacy.add_calendar_months("2026-01-31", 1) == "2026-02-28"
    assert privacy.add_calendar_months("2028-01-31", 1) == "2028-02-29"
    assert privacy.add_calendar_months("2026-11-30", 3) == "2027-02-28"


def test_dsr_deadline():
    assert privacy.dsr_deadline("2026-05-10") == "2026-06-10"
    assert privacy.dsr_deadline("2026-05-10", 2) == "2026-08-10"
    with pytest.raises(ValueError):
        privacy.dsr_deadline("2026-05-10", 3)


# Suppliers and incidents ------------------------------------------------------------------------------------

def test_supplier_tier():
    t = suppliers.supplier_tier
    assert [t("personal", "low"), t("none", "high"), t("internal", "low"), t("none", "medium"), t("none", "low")] == [
        1, 1, 2, 2, 3]


QS = [suppliers.WeightedQuestion("a", 2), suppliers.WeightedQuestion("b", 1, critical=True),
      suppliers.WeightedQuestion("c", 1)]


def test_questionnaire_scoring():
    s = suppliers.score_questionnaire
    assert s(QS, {"a": "yes", "b": "yes", "c": "yes"}) == suppliers.QuestionnaireScore(100, "acceptable", [])
    assert s(QS, {"a": "partly", "b": "yes", "c": "yes"}).outcome == "acceptable_with_actions"
    assert s(QS, {"a": "yes", "b": "no", "c": "yes"}).outcome == "not_acceptable"
    assert s(QS, {"a": "yes", "b": "yes", "c": "not_applicable"}).score == 100
    assert s(QS, {"a": "yes"}).unanswered == ["b", "c"]
    assert s(QS, {"a": "no", "b": "yes", "c": "no"}).outcome == "not_acceptable"


def test_incidents_move_forward_and_need_lessons_to_close():
    assert suppliers.can_move_to("reported", "contained")
    assert not suppliers.can_move_to("resolved", "investigating")
    assert suppliers.closure_blockers("low", "", "", False, None) == []
    assert len(suppliers.closure_blockers("high", "", "", True, None)) == 3
    assert suppliers.breach_deadline("2026-11-18T10:00:00.000Z") == "2026-11-21T10:00:00.000Z"


# Business continuity ----------------------------------------------------------------------------------------

def test_impact_rises_over_time_and_gives_the_mtpd():
    assert continuity.normalize_impacts({4: 2, 24: 1, 72: 4}) == {4: 2, 24: 2, 72: 4}
    assert continuity.suggested_mtpd({4: 1, 24: 3, 72: 4, 168: 5}) == 72
    assert continuity.suggested_mtpd({4: 1, 24: 2}) is None


def test_recovery_priority():
    assert [continuity.recovery_priority(h) for h in (None, 4, 48, 168)] == [None, 1, 2, 3]


BIA = continuity.BiaActivity(72, 24, 4, {72: 4}, 2, 1, "2026-06-01", "2026-11-18")


def test_bia_issues():
    assert continuity.bia_issues(BIA) == []
    assert continuity.bia_issues(dataclasses.replace(BIA, rto_hours=96)) == [
        "The recovery time objective must be shorter than the maximum tolerable disruption."]
    assert continuity.bia_issues(dataclasses.replace(BIA, last_exercised_on="2025-01-01")) == [
        "Exercise its plan (at least once a year)."]
    empty = dataclasses.replace(BIA, impacts={}, mtpd_hours=None, rto_hours=None, rpo_hours=None, dependencies=0,
                                plans=0)
    assert len(continuity.bia_issues(empty)) == 6


def test_rto_met():
    assert continuity.rto_met(3, 4) is True and continuity.rto_met(6, 4) is False
    assert continuity.rto_met(None, 4) is None


# AI management ----------------------------------------------------------------------------------------------

def test_ai_risk_tier_takes_the_highest():
    assert ai.ai_risk_tier({}) == "minimal"
    assert ai.ai_risk_tier({"generates": True}) == "limited"
    assert ai.ai_risk_tier({"generates": True, "employment": True}) == "high"
    assert ai.ai_risk_tier({"employment": True, "social_scoring": True}) == "unacceptable"


AI_OK = ai.AiSystem("high", "in_use", "Shortlist applicants", "A recruiter reviews every shortlist", True, True, True,
                    True, "deployer")


def test_ai_system_gaps():
    assert ai.ai_system_gaps(AI_OK) == []
    assert ai.ai_system_gaps(dataclasses.replace(AI_OK, status="retired", purpose="")) == []
    worst = dataclasses.replace(AI_OK, tier="unacceptable", purpose="", human_oversight="", processing_linked=False,
                                supplier_linked=False)
    assert len(ai.ai_system_gaps(worst)) == 5
    assert ai.ai_system_gaps(dataclasses.replace(AI_OK, has_approved_assessment=False)) == [
        "Complete and approve an AI impact assessment."]
