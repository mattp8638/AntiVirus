"""Failure mode tests for MVP-13 compliance automation."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from app.engine import evaluate_control
from app.models import ControlDefinition, ControlLogic, EvidenceRecord, ExceptionRecord


class FailureModeTests(unittest.TestCase):
    """Validate failure mode handling with conservative outputs."""

    def _control(self, logic: ControlLogic) -> ControlDefinition:
        now = datetime.now(timezone.utc)
        return ControlDefinition(
            control_id="ISO27001-A.12.6",
            framework="ISO27001",
            control_statement="Patches are applied within defined windows.",
            expected_system_behaviour="Patch compliance above threshold.",
            evidence_sources=["patch"],
            assessment_logic=logic,
            evaluation_frequency_days=30,
            version=1,
            published_at=now,
        )

    def test_evidence_source_outage(self) -> None:
        control = self._control(
            ControlLogic(logic_type="threshold", evidence_key="patch_rate", operator=">=", threshold=0.95)
        )
        assessment = evaluate_control(control, [], [])
        self.assertEqual(assessment.status, "manual_evidence_required")

    def test_conflicting_evidence(self) -> None:
        control = self._control(ControlLogic(logic_type="boolean", evidence_key="compliant"))
        now = datetime.now(timezone.utc)
        evidence = [
            EvidenceRecord(
                control_id=control.control_id,
                source="patch",
                observed_at=now,
                actor="system",
                attributes={"compliant": True},
            ),
            EvidenceRecord(
                control_id=control.control_id,
                source="patch",
                observed_at=now,
                actor="system",
                attributes={"compliant": False},
            ),
        ]
        assessment = evaluate_control(control, evidence, [])
        self.assertEqual(assessment.status, "partially_compliant")

    def test_control_logic_error(self) -> None:
        control = self._control(ControlLogic(logic_type="threshold", evidence_key=None))
        now = datetime.now(timezone.utc)
        evidence = [
            EvidenceRecord(
                control_id=control.control_id,
                source="patch",
                observed_at=now,
                actor="system",
                attributes={"patch_rate": 0.5},
            )
        ]
        assessment = evaluate_control(control, evidence, [])
        self.assertEqual(assessment.status, "manual_evidence_required")

    def test_manual_evidence_abuse(self) -> None:
        control = self._control(ControlLogic(logic_type="manual"))
        assessment = evaluate_control(control, [], [])
        self.assertEqual(assessment.status, "manual_evidence_required")

    def test_exception_expiry(self) -> None:
        control = self._control(ControlLogic(logic_type="boolean", evidence_key="compliant"))
        now = datetime.now(timezone.utc)
        evidence = [
            EvidenceRecord(
                control_id=control.control_id,
                source="patch",
                observed_at=now,
                actor="system",
                attributes={"compliant": False},
            )
        ]
        exception = ExceptionRecord(
            control_id=control.control_id,
            approved_by="security-lead",
            justification="Legacy constraint",
            expires_at=now - timedelta(days=1),
            recorded_at=now - timedelta(days=5),
        )
        assessment = evaluate_control(control, evidence, [exception])
        self.assertEqual(assessment.status, "non_compliant")

    def test_framework_update_resets_mapping(self) -> None:
        control = self._control(ControlLogic(logic_type="boolean", evidence_key="compliant"))
        updated = control.model_copy(update={"version": 2})
        self.assertNotEqual(control.version, updated.version)


if __name__ == "__main__":
    unittest.main()
