use crate::policy::PolicyBundle;
use crate::security::{validate_bounded_string, ValidationLimits};

#[derive(Debug, Clone)]
pub struct SignedCommand {
    pub command_id: String,
    pub signed_payload: String,
    pub action: String,
    pub arguments: Vec<String>,
    pub not_before_unix_time_ms: u64,
    pub not_after_unix_time_ms: u64,
}

pub fn route_command(command: SignedCommand, policy: &PolicyBundle, now_unix_time_ms: u64) -> bool {
    // TODO: Verify signature against trust bundle and enforcement keys.
    let limits = ValidationLimits::default_limits();
    if !validate_bounded_string(&command.command_id, limits.max_command_id_len) {
        return false;
    }
    if !validate_bounded_string(&command.signed_payload, limits.max_payload_len) {
        return false;
    }
    if !validate_bounded_string(&command.action, limits.max_command_id_len) {
        return false;
    }
    if !policy.allows_action(&command.action) {
        return false;
    }
    if command.arguments.len() > policy.execution.max_arguments {
        return false;
    }
    if !command
        .arguments
        .iter()
        .all(|arg| validate_bounded_string(arg, policy.execution.max_argument_length))
    {
        return false;
    }
    if command.not_before_unix_time_ms > command.not_after_unix_time_ms {
        return false;
    }
    if now_unix_time_ms < command.not_before_unix_time_ms
        || now_unix_time_ms > command.not_after_unix_time_ms
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::{route_command, SignedCommand};
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

    fn build_command() -> SignedCommand {
        SignedCommand {
            command_id: "cmd-1".to_string(),
            signed_payload: "signed".to_string(),
            action: "script-run".to_string(),
            arguments: vec!["-v".to_string()],
            not_before_unix_time_ms: 10,
            not_after_unix_time_ms: 20,
        }
    }

    #[test]
    fn accepts_valid_command() {
        let policy = build_policy();
        let command = build_command();
        assert!(route_command(command, &policy, 15));
    }

    #[test]
    fn rejects_disallowed_action() {
        let policy = build_policy();
        let mut command = build_command();
        command.action = "forbidden".to_string();
        assert!(!route_command(command, &policy, 15));
    }

    #[test]
    fn rejects_argument_limit() {
        let policy = build_policy();
        let mut command = build_command();
        command.arguments = vec!["one".to_string(), "two".to_string(), "three".to_string()];
        assert!(!route_command(command, &policy, 15));
    }

    #[test]
    fn rejects_time_window() {
        let policy = build_policy();
        let mut command = build_command();
        command.not_before_unix_time_ms = 30;
        command.not_after_unix_time_ms = 40;
        assert!(!route_command(command, &policy, 20));
    }
}
