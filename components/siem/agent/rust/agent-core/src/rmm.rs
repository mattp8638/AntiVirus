use std::env;

use crate::policy::PolicyBundle;
use crate::security::{validate_bounded_string, ValidationLimits};
use crate::time::unix_time_ms;

#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    pub command_id: String,
    pub signed_payload: String,
    pub action: String,
    pub arguments: Vec<String>,
    pub requested_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct RmmConfig {
    pub max_payload_len: usize,
    pub max_command_id_len: usize,
    pub max_request_lifetime_ms: u64,
}

impl RmmConfig {
    pub fn from_env() -> Self {
        let limits = ValidationLimits::default_limits();
        let max_payload_len = env::var("RMM_MAX_PAYLOAD_LEN")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(limits.max_payload_len);
        let max_command_id_len = env::var("RMM_MAX_COMMAND_ID_LEN")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(limits.max_command_id_len);
        let max_request_lifetime_ms = env::var("RMM_MAX_REQUEST_LIFETIME_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(300_000);

        Self {
            max_payload_len,
            max_command_id_len,
            max_request_lifetime_ms,
        }
    }
}

#[derive(Debug, Clone)]
struct RmmPendingCommand {
    command_id: String,
    signed_payload: String,
    action: String,
    arguments: Vec<String>,
    expires_at_unix_ms: Option<u64>,
    source: String,
}

pub fn queue_execution_request(policy: &PolicyBundle) -> Option<ExecutionRequest> {
    let config = RmmConfig::from_env();
    let pending = RmmPendingCommand::from_env()?;
    let now = unix_time_ms();

    if !validate_bounded_string(&pending.command_id, config.max_command_id_len) {
        return None;
    }
    if pending.signed_payload.len() > config.max_payload_len {
        return None;
    }
    if !policy.allows_action(&pending.action) {
        return None;
    }
    if pending.arguments.len() > policy.execution.max_arguments {
        return None;
    }
    if pending
        .arguments
        .iter()
        .any(|arg| !validate_bounded_string(arg, policy.execution.max_argument_length))
    {
        return None;
    }

    let expires_at_unix_ms = pending
        .expires_at_unix_ms
        .unwrap_or_else(|| now.saturating_add(config.max_request_lifetime_ms));
    if expires_at_unix_ms <= now {
        return None;
    }

    Some(ExecutionRequest {
        command_id: pending.command_id,
        signed_payload: pending.signed_payload,
        action: pending.action,
        arguments: pending.arguments,
        requested_at_unix_ms: now,
        expires_at_unix_ms,
        source: pending.source,
    })
}

impl RmmPendingCommand {
    fn from_env() -> Option<Self> {
        let command_id = env::var("RMM_COMMAND_ID").ok()?.trim().to_string();
        let signed_payload = env::var("RMM_SIGNED_PAYLOAD").ok()?.trim().to_string();
        let action = env::var("RMM_ACTION").ok()?.trim().to_string();
        let arguments = env::var("RMM_ARGS")
            .ok()
            .map(parse_csv)
            .unwrap_or_default();
        let expires_at_unix_ms = env::var("RMM_EXPIRES_AT_UNIX_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok());
        let source = env::var("RMM_SOURCE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "policy-queue".to_string());

        if command_id.is_empty() || signed_payload.is_empty() || action.is_empty() {
            return None;
        }

        Some(Self {
            command_id,
            signed_payload,
            action,
            arguments,
            expires_at_unix_ms,
            source,
        })
    }
}

fn parse_csv(value: String) -> Vec<String> {
    value
        .split(',')
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect()
}
