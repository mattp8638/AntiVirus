use std::collections::HashSet;
use std::env;
use std::fs;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::security::{validate_bounded_string, ValidationLimits};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    pub allowed_actions: Vec<String>,
    pub max_arguments: usize,
    pub max_argument_length: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub schema_version: u32,
    pub version: String,
    pub issued_at_unix_time_ms: u64,
    pub expires_at_unix_time_ms: u64,
    pub signing_key_id: String,
    pub signature: String,
    pub execution: ExecutionPolicy,
    pub telemetry_streams: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyValidationOptions {
    pub signing_key: Option<String>,
    pub expected_key_id: Option<String>,
    pub allow_unsigned: bool,
}

impl PolicyValidationOptions {
    pub fn from_env() -> Self {
        let signing_key = env::var("AGENT_POLICY_SIGNING_KEY").ok();
        let expected_key_id = env::var("AGENT_POLICY_SIGNING_KEY_ID").ok();
        let allow_unsigned = env::var("AGENT_POLICY_ALLOW_UNSIGNED")
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            signing_key,
            expected_key_id,
            allow_unsigned,
        }
    }
}

impl PolicyBundle {
    pub fn placeholder() -> Self {
        Self {
            schema_version: 1,
            version: "policy-placeholder".to_string(),
            issued_at_unix_time_ms: 0,
            expires_at_unix_time_ms: u64::MAX,
            signing_key_id: "signing-key-placeholder".to_string(),
            signature: "signature-placeholder".to_string(),
            execution: ExecutionPolicy {
                allowed_actions: vec!["script-run".to_string(), "patch-apply".to_string()],
                max_arguments: 8,
                max_argument_length: 256,
            },
            telemetry_streams: vec!["sensor".to_string(), "agent".to_string()],
        }
    }

    pub fn from_env() -> Self {
        if let Ok(path) = env::var("AGENT_POLICY_PATH") {
            if let Ok(raw) = fs::read_to_string(path) {
                if let Ok(policy) = serde_json::from_str::<PolicyBundle>(&raw) {
                    return policy;
                }
            }
        }

        if let Ok(raw) = env::var("AGENT_POLICY_JSON") {
            if let Ok(policy) = serde_json::from_str::<PolicyBundle>(&raw) {
                return policy;
            }
        }

        Self::placeholder()
    }

    pub fn validate(&self, now_unix_time_ms: u64, options: &PolicyValidationOptions) -> bool {
        // Signature validation is enforced when AGENT_POLICY_SIGNING_KEY is set.
        let limits = ValidationLimits::default_limits();
        if self.schema_version == 0 {
            return false;
        }
        if !validate_bounded_string(&self.version, 64) {
            return false;
        }
        if !validate_bounded_string(&self.signing_key_id, 128) {
            return false;
        }
        if !validate_bounded_string(&self.signature, limits.max_payload_len) {
            return false;
        }
        if let Some(expected_key_id) = &options.expected_key_id {
            if &self.signing_key_id != expected_key_id {
                return false;
            }
        }
        if self.issued_at_unix_time_ms > self.expires_at_unix_time_ms {
            return false;
        }
        if now_unix_time_ms < self.issued_at_unix_time_ms
            || now_unix_time_ms > self.expires_at_unix_time_ms
        {
            return false;
        }

        if self.execution.allowed_actions.is_empty()
            || self.execution.max_arguments == 0
            || self.execution.max_argument_length == 0
        {
            return false;
        }

        let mut unique_actions = HashSet::new();
        for action in &self.execution.allowed_actions {
            if !validate_bounded_string(action, limits.max_command_id_len) {
                return false;
            }
            if !is_valid_action_name(action) {
                return false;
            }
            if !unique_actions.insert(action) {
                return false;
            }
        }
        if !is_sorted(&self.execution.allowed_actions) {
            return false;
        }

        if self.telemetry_streams.is_empty() {
            return false;
        }

        let mut unique_streams = HashSet::new();
        for stream in &self.telemetry_streams {
            if !validate_bounded_string(stream, limits.max_stream_len) {
                return false;
            }
            if !unique_streams.insert(stream) {
                return false;
            }
        }
        if !is_sorted(&self.telemetry_streams) {
            return false;
        }

        if let Some(signing_key) = &options.signing_key {
            if !self.verify_signature(signing_key) {
                return false;
            }
        } else if !options.allow_unsigned {
            return false;
        }

        true
    }

    pub fn allows_action(&self, action: &str) -> bool {
        self.execution.allowed_actions.iter().any(|item| item == action)
    }

    fn signing_payload(&self) -> String {
        let mut payload = String::new();
        payload.push_str("schema_version=");
        payload.push_str(&self.schema_version.to_string());
        payload.push_str("|version=");
        payload.push_str(&self.version);
        payload.push_str("|issued_at=");
        payload.push_str(&self.issued_at_unix_time_ms.to_string());
        payload.push_str("|expires_at=");
        payload.push_str(&self.expires_at_unix_time_ms.to_string());
        payload.push_str("|signing_key_id=");
        payload.push_str(&self.signing_key_id);
        payload.push_str("|allowed_actions=");
        payload.push_str(&self.execution.allowed_actions.join(","));
        payload.push_str("|max_arguments=");
        payload.push_str(&self.execution.max_arguments.to_string());
        payload.push_str("|max_argument_length=");
        payload.push_str(&self.execution.max_argument_length.to_string());
        payload.push_str("|telemetry_streams=");
        payload.push_str(&self.telemetry_streams.join(","));
        payload
    }

    fn verify_signature(&self, signing_key: &str) -> bool {
        let payload = self.signing_payload();
        let mut mac = match Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()) {
            Ok(value) => value,
            Err(_) => return false,
        };
        mac.update(payload.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        let expected = BASE64_STANDARD.encode(signature_bytes);
        constant_time_eq(self.signature.as_bytes(), expected.as_bytes())
    }

    pub fn sign_with_key(&mut self, signing_key: &str) -> bool {
        if !self.validate_for_signing() {
            return false;
        }
        let payload = self.signing_payload();
        let mut mac = match Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()) {
            Ok(value) => value,
            Err(_) => return false,
        };
        mac.update(payload.as_bytes());
        let signature_bytes = mac.finalize().into_bytes();
        self.signature = BASE64_STANDARD.encode(signature_bytes);
        true
    }

    fn validate_for_signing(&self) -> bool {
        let limits = ValidationLimits::default_limits();
        if self.schema_version == 0 {
            return false;
        }
        if !validate_bounded_string(&self.version, 64) {
            return false;
        }
        if !validate_bounded_string(&self.signing_key_id, 128) {
            return false;
        }
        if self.issued_at_unix_time_ms > self.expires_at_unix_time_ms {
            return false;
        }
        if self.execution.allowed_actions.is_empty()
            || self.execution.max_arguments == 0
            || self.execution.max_argument_length == 0
        {
            return false;
        }
        let mut unique_actions = HashSet::new();
        for action in &self.execution.allowed_actions {
            if !validate_bounded_string(action, limits.max_command_id_len) {
                return false;
            }
            if !is_valid_action_name(action) {
                return false;
            }
            if !unique_actions.insert(action) {
                return false;
            }
        }
        if !is_sorted(&self.execution.allowed_actions) {
            return false;
        }
        if self.telemetry_streams.is_empty() {
            return false;
        }
        let mut unique_streams = HashSet::new();
        for stream in &self.telemetry_streams {
            if !validate_bounded_string(stream, limits.max_stream_len) {
                return false;
            }
            if !unique_streams.insert(stream) {
                return false;
            }
        }
        if !is_sorted(&self.telemetry_streams) {
            return false;
        }
        true
    }
}

fn is_valid_action_name(action: &str) -> bool {
    action
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch == '-' || ch == '_')
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (lhs, rhs) in left.iter().zip(right.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

fn is_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] <= pair[1])
}

#[cfg(test)]
mod tests {
    use super::{PolicyBundle, PolicyValidationOptions};

    fn build_valid_policy() -> PolicyBundle {
        PolicyBundle {
            schema_version: 1,
            version: "policy-1".to_string(),
            issued_at_unix_time_ms: 0,
            expires_at_unix_time_ms: u64::MAX,
            signing_key_id: "key-1".to_string(),
            signature: "placeholder".to_string(),
            execution: super::ExecutionPolicy {
                allowed_actions: vec!["patch-apply".to_string(), "script-run".to_string()],
                max_arguments: 4,
                max_argument_length: 64,
            },
            telemetry_streams: vec!["agent".to_string(), "sensor".to_string()],
        }
    }

    #[test]
    fn validates_when_unsigned_allowed() {
        let policy = build_valid_policy();
        let options = PolicyValidationOptions {
            signing_key: None,
            expected_key_id: None,
            allow_unsigned: true,
        };
        assert!(policy.validate(1, &options));
    }

    #[test]
    fn rejects_when_unsigned_disallowed() {
        let policy = build_valid_policy();
        let options = PolicyValidationOptions {
            signing_key: None,
            expected_key_id: None,
            allow_unsigned: false,
        };
        assert!(!policy.validate(1, &options));
    }

    #[test]
    fn rejects_unsorted_lists() {
        let mut policy = build_valid_policy();
        policy.execution.allowed_actions = vec!["script-run".to_string(), "patch-apply".to_string()];
        let options = PolicyValidationOptions {
            signing_key: None,
            expected_key_id: None,
            allow_unsigned: true,
        };
        assert!(!policy.validate(1, &options));
    }

    #[test]
    fn validates_with_signature_key() {
        let mut policy = build_valid_policy();
        let signing_key = "unit-test-key";
        assert!(policy.sign_with_key(signing_key));
        let options = PolicyValidationOptions {
            signing_key: Some(signing_key.to_string()),
            expected_key_id: None,
            allow_unsigned: false,
        };
        assert!(policy.validate(1, &options));
    }

    #[test]
    fn rejects_signing_when_unsorted() {
        let mut policy = build_valid_policy();
        policy.execution.allowed_actions = vec!["script-run".to_string(), "patch-apply".to_string()];
        assert!(!policy.sign_with_key("unit-test-key"));
    }

    #[test]
    fn rejects_when_signature_mismatch() {
        let mut policy = build_valid_policy();
        assert!(policy.sign_with_key("unit-test-key"));
        let options = PolicyValidationOptions {
            signing_key: Some("other-key".to_string()),
            expected_key_id: None,
            allow_unsigned: false,
        };
        assert!(!policy.validate(1, &options));
    }
}
