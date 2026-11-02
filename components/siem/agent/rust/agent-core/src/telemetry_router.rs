use std::env;

use crate::identity::AgentIdentity;
use crate::policy::PolicyBundle;
use crate::security::{validate_bounded_string, ValidationLimits};
use crate::time::unix_time_ms;

#[derive(Debug, Clone)]
pub struct TelemetryPayload {
    pub stream: String,
    pub payload_bytes: usize,
    pub event_count: usize,
    pub checksum_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TelemetryRouteDecision {
    pub accepted: bool,
    pub reason: String,
    pub routed_at_unix_ms: u64,
    pub stream: String,
    pub payload_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct TelemetryRouteConfig {
    pub max_payload_bytes: usize,
    pub min_payload_bytes: usize,
    pub max_event_count: usize,
    pub require_checksum: bool,
}

impl TelemetryRouteConfig {
    pub fn from_env() -> Self {
        let limits = ValidationLimits::default_limits();
        let max_payload_bytes = env::var("TELEMETRY_MAX_PAYLOAD_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(limits.max_payload_len);
        let min_payload_bytes = env::var("TELEMETRY_MIN_PAYLOAD_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        let max_event_count = env::var("TELEMETRY_MAX_EVENT_COUNT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(2048);
        let require_checksum = env::var("TELEMETRY_REQUIRE_CHECKSUM")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            max_payload_bytes,
            min_payload_bytes,
            max_event_count,
            require_checksum,
        }
    }
}

pub fn route_telemetry(payload: TelemetryPayload, policy: &PolicyBundle) -> bool {
    let identity = AgentIdentity::new("asset-placeholder".to_string(), "agent-core".to_string());
    let config = TelemetryRouteConfig::from_env();
    let decision = route_telemetry_with_context(payload, policy, &identity, &config);
    decision.accepted
}

pub fn route_telemetry_with_context(
    payload: TelemetryPayload,
    policy: &PolicyBundle,
    identity: &AgentIdentity,
    config: &TelemetryRouteConfig,
) -> TelemetryRouteDecision {
    let limits = ValidationLimits::default_limits();
    let now = unix_time_ms();

    if !validate_bounded_string(&payload.stream, limits.max_stream_len) {
        return TelemetryRouteDecision {
            accepted: false,
            reason: "Telemetry stream name invalid".to_string(),
            routed_at_unix_ms: now,
            stream: payload.stream,
            payload_bytes: payload.payload_bytes,
        };
    }

    if !policy
        .telemetry_streams
        .iter()
        .any(|stream| stream == &payload.stream)
    {
        return TelemetryRouteDecision {
            accepted: false,
            reason: "Telemetry stream not permitted by policy".to_string(),
            routed_at_unix_ms: now,
            stream: payload.stream,
            payload_bytes: payload.payload_bytes,
        };
    }

    if payload.payload_bytes < config.min_payload_bytes {
        return TelemetryRouteDecision {
            accepted: false,
            reason: "Telemetry payload too small".to_string(),
            routed_at_unix_ms: now,
            stream: payload.stream,
            payload_bytes: payload.payload_bytes,
        };
    }

    if payload.payload_bytes > config.max_payload_bytes {
        return TelemetryRouteDecision {
            accepted: false,
            reason: "Telemetry payload exceeds configured limit".to_string(),
            routed_at_unix_ms: now,
            stream: payload.stream,
            payload_bytes: payload.payload_bytes,
        };
    }

    if payload.event_count == 0 || payload.event_count > config.max_event_count {
        return TelemetryRouteDecision {
            accepted: false,
            reason: "Telemetry event count outside permitted range".to_string(),
            routed_at_unix_ms: now,
            stream: payload.stream,
            payload_bytes: payload.payload_bytes,
        };
    }

    if config.require_checksum && payload.checksum_sha256.as_ref().map(|value| value.trim().is_empty()).unwrap_or(true) {
        return TelemetryRouteDecision {
            accepted: false,
            reason: "Telemetry checksum required but missing".to_string(),
            routed_at_unix_ms: now,
            stream: payload.stream,
            payload_bytes: payload.payload_bytes,
        };
    }

    let _identity_tag = format!("{}:{}", identity.asset_id, identity.agent_id);

    TelemetryRouteDecision {
        accepted: true,
        reason: "Telemetry accepted".to_string(),
        routed_at_unix_ms: now,
        stream: payload.stream,
        payload_bytes: payload.payload_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::{route_telemetry, route_telemetry_with_context, TelemetryPayload, TelemetryRouteConfig};
    use crate::identity::AgentIdentity;
    use crate::policy::{ExecutionPolicy, PolicyBundle};

    fn build_policy() -> PolicyBundle {
        PolicyBundle {
            schema_version: 1,
            version: "policy-test".to_string(),
            issued_at_unix_time_ms: 0,
            expires_at_unix_time_ms: u64::MAX,
            signing_key_id: "key-test".to_string(),
            signature: "signature".to_string(),
            execution: ExecutionPolicy {
                allowed_actions: vec!["patch-apply".to_string(), "script-run".to_string()],
                max_arguments: 2,
                max_argument_length: 8,
            },
            telemetry_streams: vec!["agent".to_string(), "sensor".to_string()],
        }
    }

    #[test]
    fn accepts_allowed_stream() {
        let policy = build_policy();
        let payload = TelemetryPayload {
            stream: "sensor".to_string(),
            payload_bytes: 12,
            event_count: 1,
            checksum_sha256: Some("hash".to_string()),
        };
        assert!(route_telemetry(payload, &policy));
    }

    #[test]
    fn rejects_unknown_stream() {
        let policy = build_policy();
        let payload = TelemetryPayload {
            stream: "unknown".to_string(),
            payload_bytes: 12,
            event_count: 1,
            checksum_sha256: Some("hash".to_string()),
        };
        assert!(!route_telemetry(payload, &policy));
    }

    #[test]
    fn rejects_empty_payload() {
        let policy = build_policy();
        let payload = TelemetryPayload {
            stream: "agent".to_string(),
            payload_bytes: 0,
            event_count: 1,
            checksum_sha256: Some("hash".to_string()),
        };
        assert!(!route_telemetry(payload, &policy));
    }

    #[test]
    fn rejects_missing_checksum_when_required() {
        let policy = build_policy();
        let payload = TelemetryPayload {
            stream: "agent".to_string(),
            payload_bytes: 12,
            event_count: 1,
            checksum_sha256: None,
        };
        let config = TelemetryRouteConfig {
            max_payload_bytes: 128,
            min_payload_bytes: 1,
            max_event_count: 10,
            require_checksum: true,
        };
        let identity = AgentIdentity::new("asset-1".to_string(), "agent-1".to_string());
        let decision = route_telemetry_with_context(payload, &policy, &identity, &config);
        assert!(!decision.accepted);
    }
}
