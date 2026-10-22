use std::env;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::time::unix_time_ms;

/// Outcome of a compliance check, including an immutable evidence reference.
#[derive(Debug, Clone)]
pub struct ComplianceResult {
    pub control_id: String,
    pub control_title: String,
    pub passed: bool,
    pub status: ComplianceStatus,
    pub evidence_ref: String,
    pub checked_at_unix_ms: u64,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ComplianceStatus {
    Pass,
    Fail,
    NotApplicable,
}

#[derive(Debug, Clone)]
struct ComplianceCheck {
    id: String,
    title: String,
    description: String,
    kind: ComplianceCheckKind,
}

#[derive(Debug, Clone)]
enum ComplianceCheckKind {
    EnvVarRequired { name: String },
    PathExists { path: PathBuf, must_be_file: bool, must_be_dir: bool },
    NumericMax { name: String, max_value: u64 },
    NumericMin { name: String, min_value: u64 },
}

#[derive(Debug, Clone)]
pub struct ComplianceConfig {
    pub required_env: Vec<String>,
    pub required_paths: Vec<PathBuf>,
    pub max_payload_bytes: Option<u64>,
    pub min_payload_bytes: Option<u64>,
}

impl ComplianceConfig {
    pub fn from_env() -> Self {
        let required_env = env::var("COMPLIANCE_REQUIRED_ENV")
            .ok()
            .map(parse_csv)
            .unwrap_or_else(|| {
                vec![
                    "AGENT_ASSET_ID".to_string(),
                    "AGENT_ID".to_string(),
                    "AGENT_IPC_PIPE".to_string(),
                    "EVIDENCE_PATHS".to_string(),
                ]
            });
        let required_paths = env::var("COMPLIANCE_REQUIRED_PATHS")
            .ok()
            .map(parse_csv)
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect::<Vec<PathBuf>>();
        let max_payload_bytes = env::var("COMPLIANCE_MAX_PAYLOAD_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok());
        let min_payload_bytes = env::var("COMPLIANCE_MIN_PAYLOAD_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok());

        Self {
            required_env,
            required_paths,
            max_payload_bytes,
            min_payload_bytes,
        }
    }
}

pub fn run_self_audit() -> Vec<ComplianceResult> {
    let config = ComplianceConfig::from_env();
    run_self_audit_with_config(&config)
}

pub fn run_self_audit_with_config(config: &ComplianceConfig) -> Vec<ComplianceResult> {
    let checks = build_checks(config);
    let checked_at_unix_ms = unix_time_ms();

    checks
        .into_iter()
        .map(|check| evaluate_check(&check, checked_at_unix_ms))
        .collect()
}

fn build_checks(config: &ComplianceConfig) -> Vec<ComplianceCheck> {
    let mut checks = Vec::new();

    for env_name in &config.required_env {
        checks.push(ComplianceCheck {
            id: format!("CMP-ENV-{}", env_name),
            title: format!("Environment variable {} configured", env_name),
            description: "Required runtime configuration must be present.".to_string(),
            kind: ComplianceCheckKind::EnvVarRequired {
                name: env_name.clone(),
            },
        });
    }

    for path in &config.required_paths {
        checks.push(ComplianceCheck {
            id: format!("CMP-PATH-{}", path.display()),
            title: format!("Required path {} available", path.display()),
            description: "Runtime artefacts should exist for auditability.".to_string(),
            kind: ComplianceCheckKind::PathExists {
                path: path.clone(),
                must_be_file: true,
                must_be_dir: false,
            },
        });
    }

    if let Some(max_value) = config.max_payload_bytes {
        checks.push(ComplianceCheck {
            id: "CMP-MAX-PAYLOAD".to_string(),
            title: "Maximum payload limit enforced".to_string(),
            description: "Payload size limits should be defined to reduce risk.".to_string(),
            kind: ComplianceCheckKind::NumericMax {
                name: "AGENT_MAX_PAYLOAD_BYTES".to_string(),
                max_value,
            },
        });
    }

    if let Some(min_value) = config.min_payload_bytes {
        checks.push(ComplianceCheck {
            id: "CMP-MIN-PAYLOAD".to_string(),
            title: "Minimum payload limit enforced".to_string(),
            description: "Payload limits should avoid underflow or zero values.".to_string(),
            kind: ComplianceCheckKind::NumericMin {
                name: "AGENT_MAX_PAYLOAD_BYTES".to_string(),
                min_value,
            },
        });
    }

    checks
}

fn evaluate_check(check: &ComplianceCheck, checked_at_unix_ms: u64) -> ComplianceResult {
    let mut findings = Vec::new();
    let passed = match &check.kind {
        ComplianceCheckKind::EnvVarRequired { name } => match env::var(name) {
            Ok(value) if !value.trim().is_empty() => true,
            Ok(_) => {
                findings.push(format!("{} is configured but empty.", name));
                false
            }
            Err(_) => {
                findings.push(format!("{} is missing.", name));
                false
            }
        },
        ComplianceCheckKind::PathExists {
            path,
            must_be_file,
            must_be_dir,
        } => match std::fs::metadata(path) {
            Ok(metadata) => {
                if *must_be_file && !metadata.is_file() {
                    findings.push("Path exists but is not a file.".to_string());
                    false
                } else if *must_be_dir && !metadata.is_dir() {
                    findings.push("Path exists but is not a directory.".to_string());
                    false
                } else {
                    true
                }
            }
            Err(_) => {
                findings.push("Required path does not exist.".to_string());
                false
            }
        },
        ComplianceCheckKind::NumericMax { name, max_value } => match env::var(name)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(value) if value <= *max_value => true,
            Some(value) => {
                findings.push(format!("{} exceeds allowed maximum of {} (found {}).", name, max_value, value));
                false
            }
            None => {
                findings.push(format!("{} is missing or invalid.", name));
                false
            }
        },
        ComplianceCheckKind::NumericMin { name, min_value } => match env::var(name)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(value) if value >= *min_value => true,
            Some(value) => {
                findings.push(format!("{} below minimum of {} (found {}).", name, min_value, value));
                false
            }
            None => {
                findings.push(format!("{} is missing or invalid.", name));
                false
            }
        },
    };

    let status = if passed {
        ComplianceStatus::Pass
    } else {
        ComplianceStatus::Fail
    };

    ComplianceResult {
        control_id: check.id.clone(),
        control_title: check.title.clone(),
        passed,
        status,
        evidence_ref: build_evidence_ref(check, checked_at_unix_ms, &findings),
        checked_at_unix_ms,
        findings,
    }
}

fn build_evidence_ref(check: &ComplianceCheck, checked_at_unix_ms: u64, findings: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(check.id.as_bytes());
    hasher.update(check.title.as_bytes());
    hasher.update(check.description.as_bytes());
    hasher.update(checked_at_unix_ms.to_le_bytes());
    for finding in findings {
        hasher.update(finding.as_bytes());
    }
    format!("cmp-{}-{}", check.id, hex_encode(hasher.finalize()))
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join("")
}

fn parse_csv(value: String) -> Vec<String> {
    value
        .split(',')
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect()
}
