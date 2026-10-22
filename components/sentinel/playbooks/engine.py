from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


class LifecycleStage(str, Enum):
    PREPARATION = "preparation"
    DETECTION = "detection"
    TRIAGE = "triage"
    SCOPING = "scoping"
    EVIDENCE_COLLECTION = "evidence_collection"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    LESSONS_LEARNT = "lessons_learnt"


LIFECYCLE_ORDER: List[LifecycleStage] = [
    LifecycleStage.PREPARATION,
    LifecycleStage.DETECTION,
    LifecycleStage.TRIAGE,
    LifecycleStage.SCOPING,
    LifecycleStage.EVIDENCE_COLLECTION,
    LifecycleStage.CONTAINMENT,
    LifecycleStage.ERADICATION,
    LifecycleStage.RECOVERY,
    LifecycleStage.VERIFICATION,
    LifecycleStage.REPORTING,
    LifecycleStage.LESSONS_LEARNT,
]


@dataclass(frozen=True)
class Question:
    id: str
    stage: LifecycleStage
    text: str
    answer_type: str = "boolean"
    required: bool = True
    applies_to: List[str] = field(default_factory=list)
    show_if: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Task:
    id: str
    stage: LifecycleStage
    title: str
    description: str
    required: bool = True
    blocks_closure: bool = False
    evidence_required: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    incident_types: List[str]
    when: Dict[str, Any]
    severity_delta: int = 0
    move_to_stage: Optional[LifecycleStage] = None
    add_tasks: List[Task] = field(default_factory=list)
    add_evidence: List[str] = field(default_factory=list)
    escalation_required: bool = False
    closure_blocks: List[str] = field(default_factory=list)
    report_notes: List[str] = field(default_factory=list)

    def matches(self, context: "PlaybookContext") -> bool:
        if self.incident_types and context.incident_type not in self.incident_types:
            return False
        return all(context.answers.get(key) == expected for key, expected in self.when.items())


@dataclass
class PlaybookContext:
    incident_type: str
    answers: Dict[str, Any] = field(default_factory=dict)
    base_severity_score: int = 25
    current_stage: LifecycleStage = LifecycleStage.DETECTION
    existing_tasks_completed: List[str] = field(default_factory=list)
    attached_evidence: List[str] = field(default_factory=list)


@dataclass
class PlaybookResult:
    incident_type: str
    current_stage: LifecycleStage
    severity_score: int
    severity: str
    escalation_required: bool
    matched_rules: List[str]
    next_questions: List[Question]
    tasks: List[Task]
    evidence_required: List[str]
    closure_blocks: List[str]
    closure_ready: bool
    report_summary: str
    lifecycle_progress: Dict[str, str]


class IncidentLifecycleEngine:
    """Rule-driven incident playbook engine.

    The engine is deliberately deterministic. It does not rely on AI-generated
    response logic, so severity, evidence, escalation and closure behaviour can be
    audited and tested.
    """

    def __init__(self, questions: Iterable[Question], rules: Iterable[Rule]) -> None:
        self.questions = list(questions)
        self.rules = list(rules)

    def evaluate(self, context: PlaybookContext) -> PlaybookResult:
        matched_rules = [rule for rule in self.rules if rule.matches(context)]

        severity_score = context.base_severity_score + sum(rule.severity_delta for rule in matched_rules)
        severity_score = max(0, min(100, severity_score))

        target_stage = self._calculate_stage(context, matched_rules)
        tasks = self._dedupe_tasks(task for rule in matched_rules for task in rule.add_tasks)
        evidence_required = self._dedupe_strings(
            evidence for rule in matched_rules for evidence in rule.add_evidence
        )
        closure_blocks = self._dedupe_strings(
            block for rule in matched_rules for block in rule.closure_blocks
        )
        escalation_required = any(rule.escalation_required for rule in matched_rules)
        next_questions = self._next_questions(context)
        closure_ready = self._closure_ready(context, tasks, evidence_required, closure_blocks)

        return PlaybookResult(
            incident_type=context.incident_type,
            current_stage=target_stage,
            severity_score=severity_score,
            severity=self._severity_label(severity_score),
            escalation_required=escalation_required,
            matched_rules=[rule.id for rule in matched_rules],
            next_questions=next_questions,
            tasks=tasks,
            evidence_required=evidence_required,
            closure_blocks=closure_blocks,
            closure_ready=closure_ready,
            report_summary=self._build_report_summary(context, matched_rules, severity_score, target_stage),
            lifecycle_progress=self._lifecycle_progress(target_stage),
        )

    def _calculate_stage(self, context: PlaybookContext, matched_rules: List[Rule]) -> LifecycleStage:
        current_index = LIFECYCLE_ORDER.index(context.current_stage)
        target = context.current_stage
        for rule in matched_rules:
            if rule.move_to_stage is None:
                continue
            candidate_index = LIFECYCLE_ORDER.index(rule.move_to_stage)
            if candidate_index > current_index and candidate_index >= LIFECYCLE_ORDER.index(target):
                target = rule.move_to_stage
        return target

    def _next_questions(self, context: PlaybookContext) -> List[Question]:
        questions: List[Question] = []
        for question in self.questions:
            if question.id in context.answers:
                continue
            if question.applies_to and context.incident_type not in question.applies_to:
                continue
            if not self._show_if_matches(question.show_if, context.answers):
                continue
            questions.append(question)
        return questions

    @staticmethod
    def _show_if_matches(show_if: Dict[str, Any], answers: Dict[str, Any]) -> bool:
        return all(answers.get(key) == expected for key, expected in show_if.items())

    @staticmethod
    def _dedupe_tasks(tasks: Iterable[Task]) -> List[Task]:
        seen = set()
        result = []
        for task in tasks:
            if task.id in seen:
                continue
            seen.add(task.id)
            result.append(task)
        return result

    @staticmethod
    def _dedupe_strings(values: Iterable[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    @staticmethod
    def _severity_label(score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 55:
            return "High"
        if score >= 30:
            return "Medium"
        return "Low"

    @staticmethod
    def _closure_ready(
        context: PlaybookContext,
        tasks: List[Task],
        evidence_required: List[str],
        closure_blocks: List[str],
    ) -> bool:
        blocking_task_ids = {task.id for task in tasks if task.blocks_closure}
        completed = set(context.existing_tasks_completed)
        evidence = set(context.attached_evidence)
        if not blocking_task_ids.issubset(completed):
            return False
        if not set(evidence_required).issubset(evidence):
            return False
        if closure_blocks:
            return False
        return True

    @staticmethod
    def _lifecycle_progress(current_stage: LifecycleStage) -> Dict[str, str]:
        current_index = LIFECYCLE_ORDER.index(current_stage)
        progress: Dict[str, str] = {}
        for index, stage in enumerate(LIFECYCLE_ORDER):
            if index < current_index:
                progress[stage.value] = "complete_or_previous"
            elif index == current_index:
                progress[stage.value] = "current"
            else:
                progress[stage.value] = "pending"
        return progress

    @staticmethod
    def _build_report_summary(
        context: PlaybookContext,
        matched_rules: List[Rule],
        severity_score: int,
        target_stage: LifecycleStage,
    ) -> str:
        notes = [note for rule in matched_rules for note in rule.report_notes]
        if not notes:
            notes.append("The playbook is awaiting further triage answers or tool findings.")
        return "\n".join(
            [
                f"Incident type: {context.incident_type}",
                f"Current lifecycle stage: {target_stage.value}",
                f"Calculated severity score: {severity_score}",
                "Response notes:",
                *[f"- {note}" for note in notes],
            ]
        )
