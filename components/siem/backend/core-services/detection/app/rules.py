"""Default rule definitions for MVP-8."""
from __future__ import annotations

from .models import RuleDefinition, RuleOutputTemplate, RuleSuppression


def default_rules() -> list[RuleDefinition]:
    """Seed a minimal rule set to exercise each rule type."""
    return [
        RuleDefinition(
            rule_id="unsigned_binary_temp",
            version="1.0.0",
            name="Unsigned binary executed from temp",
            description="Detects execution of unsigned binaries from temporary paths.",
            rule_type="single_event",
            trigger_event_types=["process.execute"],
            required_context=["asset", "identity"],
            suppression=RuleSuppression(dedupe_window_seconds=900),
            output=RuleOutputTemplate(
                finding_type="unsigned_binary_temp",
                severity="medium",
                confidence_base=0.6,
                explanation_template=(
                    "Process execution event '{event_type}' on asset '{asset_id}' "
                    "ran an unsigned binary from a temporary location. "
                    "This behaviour is uncommon and warrants review."
                ),
            ),
        ),
        RuleDefinition(
            rule_id="privileged_login_sequence",
            version="1.0.0",
            name="Failed login followed by privileged access",
            description="Failed logins followed by a successful privileged login within 10 minutes.",
            rule_type="sequence",
            trigger_event_types=["auth.login.failure", "auth.login.success"],
            sequence_event_types=["auth.login.failure", "auth.login.success"],
            time_window_seconds=600,
            required_context=["identity", "asset"],
            suppression=RuleSuppression(dedupe_window_seconds=1200),
            output=RuleOutputTemplate(
                finding_type="privileged_login_sequence",
                severity="high",
                confidence_base=0.75,
                explanation_template=(
                    "Multiple failed logins were followed by a successful privileged login "
                    "for identity '{identity_id}' on asset '{asset_id}' within {time_window} seconds."
                ),
            ),
        ),
        RuleDefinition(
            rule_id="cpu_deviation_off_hours",
            version="1.0.0",
            name="CPU usage deviates from baseline",
            description="CPU usage exceeds baseline during off-hours.",
            rule_type="behavioural_deviation",
            trigger_event_types=["telemetry.cpu"],
            deviation_multiplier=4.0,
            required_context=["baseline", "asset"],
            suppression=RuleSuppression(dedupe_window_seconds=1800),
            output=RuleOutputTemplate(
                finding_type="cpu_deviation_off_hours",
                severity="medium",
                confidence_base=0.55,
                explanation_template=(
                    "Telemetry '{metric_name}' on asset '{asset_id}' reported {metric_value}, "
                    "which is {multiplier}x above baseline {baseline_value}."
                ),
            ),
        ),
        RuleDefinition(
            rule_id="patch_missing_exploit_signal",
            version="1.0.0",
            name="Patch missing with exploit-like behaviour",
            description="Combines missing patch context with exploit-like process behaviour.",
            rule_type="cross_domain",
            trigger_event_types=["process.suspicious"],
            required_context=["patch_state", "asset", "identity"],
            suppression=RuleSuppression(dedupe_window_seconds=1800),
            output=RuleOutputTemplate(
                finding_type="patch_missing_exploit_signal",
                severity="high",
                confidence_base=0.7,
                explanation_template=(
                    "Suspicious process behaviour on asset '{asset_id}' coincided with missing patches "
                    "({missing_patches}). This increases concern for exploitation."
                ),
            ),
        ),
    ]
