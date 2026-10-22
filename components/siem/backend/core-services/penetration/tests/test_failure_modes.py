"""Failure mode tests for MVP-12 penetration testing orchestrator."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.config import Settings
from app.engine import build_dispatch_records
from app.models import (
    AuthorisationRecord,
    DetectionResponseSummary,
    Observation,
    PenTestCreateRequest,
    PenTestPlan,
    ResultIngestRequest,
    Safeguards,
    ScheduleWindow,
    ScopeDefinition,
)
from app.validation import (
    ValidationError,
    should_abort_for_credentials,
    should_abort_for_detection,
    validate_plan_request,
    validate_plan_start,
    validate_results_request,
)


def build_plan() -> PenTestPlan:
    """Create a baseline plan for testing."""
    now = datetime.now(timezone.utc)
    return PenTestPlan(
        test_id=uuid4(),
        tenant_id="tenant-001",
        scope=ScopeDefinition(assets=["asset-001"], networks=["10.0.0.0/24"], exclusions=[]),
        test_type="network",
        method="scan",
        credentials=[],
        schedule=ScheduleWindow(start_at=now - timedelta(minutes=5), end_at=now + timedelta(minutes=55)),
        safeguards=Safeguards(
            target_allow_list=["asset-001", "10.0.0.0/24"],
            payload_restrictions=["non_destructive"],
            max_duration_minutes=60,
            rate_limit_per_minute=60,
        ),
        authorisation=AuthorisationRecord(
            authorised_by="security-lead",
            authorised_at=now,
            policy_reference="POL-12",
        ),
        status="planned",
        created_at=now,
        last_updated_at=now,
    )


class FailureModeTests(unittest.TestCase):
    """Validate failure-mode handling with safe defaults."""

    def test_decommissioned_assets_block_start(self) -> None:
        plan = build_plan()
        plan = plan.model_copy(update={"scope": plan.scope.model_copy(update={"decommissioned_assets": ["asset-001"]})})
        with self.assertRaises(ValidationError):
            validate_plan_start(plan, datetime.now(timezone.utc))

    def test_credential_revocation_aborts(self) -> None:
        observations = [
            Observation(
                asset_id="asset-001",
                weakness_id="weak-001",
                summary="Test observation",
                evidence="Safe payload rejected.",
                confidence=0.8,
                observed_at=datetime.now(timezone.utc),
                credential_state="revoked",
            )
        ]
        self.assertTrue(should_abort_for_credentials(observations))

    def test_detection_failure_aborts(self) -> None:
        summary = DetectionResponseSummary(
            detection_system_status="failed",
            detections_fired=[],
            defences_acted=[],
            defences_failed=[],
        )
        safeguards = Safeguards(
            target_allow_list=["asset-001"],
            payload_restrictions=["non_destructive"],
            max_duration_minutes=60,
            rate_limit_per_minute=60,
            abort_on_detection_failure=True,
        )
        self.assertTrue(should_abort_for_detection(summary, safeguards))

    def test_backend_outage_flags_degraded_dispatch(self) -> None:
        settings = Settings(integration_mode="simulate_outage")
        plan = build_plan()
        dispatches = build_dispatch_records(plan, [], settings)
        self.assertTrue(all(dispatch.status == "degraded" for dispatch in dispatches))

    def test_excessive_finding_volume_rejected(self) -> None:
        settings = Settings(max_observations_per_request=1)
        request = PenTestCreateRequest(
            tenant_id="tenant-001",
            scope=ScopeDefinition(assets=["asset-001"], networks=["10.0.0.0/24"], exclusions=[]),
            test_type="network",
            method="scan",
            credentials=[],
            schedule=ScheduleWindow(
                start_at=datetime.now(timezone.utc),
                end_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            ),
            safeguards=Safeguards(
                target_allow_list=["asset-001"],
                payload_restrictions=["non_destructive"],
                max_duration_minutes=60,
                rate_limit_per_minute=60,
            ),
            authorisation=AuthorisationRecord(
                authorised_by="security-lead",
                authorised_at=datetime.now(timezone.utc),
                policy_reference="POL-12",
            ),
            requested_by="security-lead",
        )
        validate_plan_request(request, settings)
        with self.assertRaises(ValidationError):
            validate_results_request(
                ResultIngestRequest(
                    operator_identity="operator",
                    observations=[
                        Observation(
                            asset_id="asset-001",
                            weakness_id="weak-001",
                            summary="Test observation",
                            evidence="Safe payload rejected.",
                            confidence=0.5,
                            observed_at=datetime.now(timezone.utc),
                        ),
                        Observation(
                            asset_id="asset-002",
                            weakness_id="weak-002",
                            summary="Second observation",
                            evidence="Safe payload blocked.",
                            confidence=0.5,
                            observed_at=datetime.now(timezone.utc),
                        ),
                    ],
                    detection_summary=DetectionResponseSummary(
                        detection_system_status="ok",
                        detections_fired=[],
                        defences_acted=[],
                        defences_failed=[],
                    ),
                    finalise=False,
                ),
                settings,
            )

    def test_unauthorised_execution_rejected(self) -> None:
        request = PenTestCreateRequest(
            tenant_id="tenant-001",
            scope=ScopeDefinition(assets=["asset-001"], networks=["10.0.0.0/24"], exclusions=[]),
            test_type="network",
            method="scan",
            credentials=[],
            schedule=ScheduleWindow(
                start_at=datetime.now(timezone.utc),
                end_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            ),
            safeguards=Safeguards(
                target_allow_list=["asset-001"],
                payload_restrictions=["non_destructive"],
                max_duration_minutes=60,
                rate_limit_per_minute=60,
            ),
            authorisation=AuthorisationRecord(
                authorised_by="security-lead",
                authorised_at=datetime.now(timezone.utc),
                policy_reference="POL-12",
            ),
            requested_by="analyst",
        )
        with self.assertRaises(ValidationError):
            validate_plan_request(request, Settings())


if __name__ == "__main__":
    unittest.main()
