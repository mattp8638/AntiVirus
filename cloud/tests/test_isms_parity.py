"""The Python ISMS engine gives exactly the standalone engine's results.

``fixtures/isms_parity.json.gz`` holds outputs recorded from the frozen standalone app by
``scripts/isms/parity_fixtures.mts``: 3,000 random expressions with mixed-type answers, malformed expressions, and 30
random onboarding profiles (with overrides) run through the applicability engine over every shipped pack, and over
10,000 random calls to the rest of the domain logic (scoring, risk, dates, audits, suppliers, privacy, continuity, AI
management), audit samples and CSV imports.
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


# Other domain logic --------------------------------------------------------------------------------------------

from dataclasses import asdict  # noqa: E402
from datetime import datetime  # noqa: E402

from fenrir_cloud.isms.domain import (  # noqa: E402
    ai_management, audit, continuity, csv_import, improvement, objectives, people, privacy, readiness, reports,
    review, risk, suppliers, tasks,
)
from fenrir_cloud.isms.domain._js import iso_instant  # noqa: E402


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def _ts(v):
    """Python results in the standalone app's JSON shape (camelCase keys, dataclasses as objects)."""
    if hasattr(v, "__dataclass_fields__"):
        return {_camel(k): _ts(x) for k, x in asdict(v).items()}
    if isinstance(v, dict):
        return {(_camel(k) if isinstance(k, str) else str(k)): _ts(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_ts(x) for x in v]
    return v


def _method(m: dict) -> risk.RiskMethod:
    return risk.RiskMethod([risk.ScalePoint(**p) for p in m["likelihoodScale"]],
                           [risk.ScalePoint(**p) for p in m["impactScale"]],
                           [risk.LevelBand(**lv) for lv in m["levels"]], m["appetite"], m["acceptanceCriteria"],
                           m["reviewMonths"])


def _req(r: dict) -> readiness.ReadinessRequirement:
    return readiness.ReadinessRequirement(r["ref"], r["applicable"], tuple(r["controlStates"]))


def _audit_req(r: dict) -> audit.AuditableRequirement:
    return audit.AuditableRequirement(r["framework"], r["ref"], r["title"], r["groupRef"], r["groupTitle"],
                                      r["mandatory"], r["applicable"], tuple(r["controls"]), r["sort"])


def _measures(vs):
    return [objectives.Measurement(v["measuredOn"], v["value"]) for v in vs]


def _impacts(d: dict) -> dict:
    return {int(k): v for k, v in d.items()}


def _instant(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


ADAPTERS = {
    "computeReadiness": lambda reqs: readiness.compute_readiness([_req(r) for r in reqs]),
    "controlCoverage": readiness.control_coverage,
    "validateRiskMethod": lambda m: risk.validate_risk_method(_method(m)),
    "riskScore": lambda m, l, i: risk.risk_score(_method(m), l, i),
    "riskLevel": lambda m, s: risk.risk_level(_method(m), s),
    "withinAppetite": lambda m, s: risk.within_appetite(_method(m), s),
    "heatMap": lambda m, rs: dict(zip(("grid", "unrated"), risk.heat_map(
        _method(m), [(r["likelihood"], r["impact"]) for r in rs]))),
    "addInterval": tasks.add_interval,
    "nextDueDate": tasks.next_due_date,
    "taskUrgency": tasks.task_urgency,
    "daysBetween": tasks.days_between,
    "recurrenceFor": tasks.recurrence_for,
    "competenceStatus": people.competence_status,
    "reviewPeriodStart": review.review_period_start,
    "addCalendarMonths": privacy.add_calendar_months,
    "dsrDeadline": privacy.dsr_deadline,
    "nextDigestAt": lambda d, f: {"date": iso_instant(reports.next_digest_at(_instant(d), f))},
    "breachDeadline": suppliers.breach_deadline,
    "ackProgress": people.ack_progress,
    "summarizeObjective": lambda vs, *rest: objectives.summarize_objective(_measures(vs), *rest),
    "chartGeometry": lambda vs, *rest: objectives.chart_geometry(_measures(vs), *rest),
    "raciIssues": lambda acts, cells: people.raci_issues(
        acts, [people.RaciCell(c["activityId"], c["roleId"], c["letter"]) for c in cells]),
    "scoreQuestionnaire": lambda qs, answers: suppliers.score_questionnaire(
        [suppliers.WeightedQuestion(q["ref"], q["weight"], q.get("critical", False)) for q in qs], answers),
    "supplierTier": suppliers.supplier_tier,
    "closureBlockers": lambda i: suppliers.closure_blockers(
        i["severity"], i["rootCause"], i["lessonsLearned"], i["personalData"], i["reportedToAuthorityAt"]),
    "canMoveTo": suppliers.can_move_to,
    "normalizeImpacts": lambda d: continuity.normalize_impacts(_impacts(d)),
    "suggestedMtpd": lambda d: continuity.suggested_mtpd(_impacts(d)),
    "recoveryPriority": continuity.recovery_priority,
    "biaIssues": lambda a: continuity.bia_issues(continuity.BiaActivity(
        a["mtpdHours"], a["rtoHours"], a["rpoHours"], _impacts(a["impacts"]), a["dependencies"], a["plans"],
        a["lastExercisedOn"], a["today"])),
    "rtoMet": continuity.rto_met,
    "dpiaRequired": privacy.dpia_required,
    "dpiaRiskLevel": privacy.dpia_risk_level,
    "aiRiskTier": ai_management.ai_risk_tier,
    "aiSystemGaps": lambda s: ai_management.ai_system_gaps(ai_management.AiSystem(
        s["tier"], s["status"], s["purpose"], s["humanOversight"], s["personalData"], s["processingLinked"],
        s["hasApprovedAssessment"], s["supplierLinked"], s["role"])),
    "processingGaps": lambda p: privacy.processing_gaps(privacy.ProcessingRecord(
        p["lawfulBasis"], p["specialCategory"], p["specialCondition"], p["transfers"], p["transferSafeguard"],
        p["retention"], tuple(p["dataSubjects"]), tuple(p["dataCategories"]), p["dpiaRequired"],
        p["hasApprovedDpia"])),
    "ncStage": lambda nc, acts: improvement.nc_stage(
        improvement.NcState(nc["kind"], nc["status"], nc["rootCause"]), [a["done"] for a in acts]),
    "effectivenessBlockers": lambda nc, acts: improvement.effectiveness_blockers(
        improvement.NcState(nc["kind"], nc["status"], nc["rootCause"]), [a["done"] for a in acts]),
    "auditCompletionBlockers": lambda a: audit.audit_completion_blockers(audit.AuditForCompletion(
        a["status"], a["independenceNote"], a["summary"], tuple(a["results"]))),
    "missingInputs": review.missing_inputs,
    "suggestedSampleSize": audit.suggested_sample_size,
    "buildChecklist": lambda reqs, *groups: audit.build_checklist([_audit_req(r) for r in reqs], *groups),
    "programmeCoverage": lambda reqs, keys: audit.programme_coverage([_audit_req(r) for r in reqs], keys),
}

def _call(fn: str, args: list):
    try:
        return _ts(ADAPTERS[fn](*args))
    except (ValueError, KeyError) as e:
        return {"error": "RangeError" if fn == "dsrDeadline" else "Error", "detail": str(e)}


def _same(got, want) -> bool:
    if isinstance(want, dict) and "error" in want and isinstance(got, dict) and "error" in got:
        return True
    if isinstance(want, float) and isinstance(got, (int, float)) and not isinstance(got, bool):
        return abs(got - want) <= 1e-9 * max(1, abs(want))
    if isinstance(want, list) and isinstance(got, list):
        return len(got) == len(want) and all(_same(g, w) for g, w in zip(got, want))
    if isinstance(want, dict) and isinstance(got, dict):
        return got.keys() == want.keys() and all(_same(got[k], want[k]) for k in want)
    return canon(got) == canon(want)


def test_every_domain_function_is_covered():
    recorded = {c["fn"] for c in fixture()["domain"]}
    assert recorded == set(ADAPTERS), recorded ^ set(ADAPTERS)


@pytest.mark.parametrize("fn", sorted(ADAPTERS))
def test_domain_function_matches_the_standalone_engine(fn):
    cases = [c for c in fixture()["domain"] if c["fn"] == fn]
    bad = [(c["args"], c["out"], got) for c in cases if not _same(got := _call(fn, c["args"]), c["out"])]
    assert not bad, f"{len(bad)} of {len(cases)} differ; first: args={bad[0][0]} want={bad[0][1]} got={bad[0][2]}"


def test_sampling_matches_the_standalone_engine():
    for c in fixture()["samples"]:
        got = [x["k"] for x in audit.draw_sample([{"k": k} for k in c["keys"]], c["size"], c["seed"], lambda x: x["k"])]
        assert got == c["out"], c["seed"]


def test_csv_parsing_matches_the_standalone_engine():
    for c in fixture()["csvs"]:
        try:
            headers, records = csv_import.parse_csv_records(c["text"])
            got = {"rows": csv_import.parse_csv(c["text"]), "records": {"headers": headers, "records": records}}
        except csv_import.CsvError:
            got = {"error": True}
        assert got == c["out"], repr(c["text"])
