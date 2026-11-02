use std::env;
use std::fs::File;
use std::io::{Read, Result as IoResult};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::time::unix_time_ms;

/// Identifies the local agent instance in telemetry and control-plane messages.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub asset_id: String,
    pub agent_id: String,
}

impl AgentIdentity {
    pub fn new(asset_id: String, agent_id: String) -> Self {
        Self { asset_id, agent_id }
    }
}

/// Expected trust anchor with optional pinned hash for integrity verification.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub path: PathBuf,
    pub sha256: Option<String>,
}

/// Runtime trust bundle configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct TrustBundleConfig {
    pub root_dir: PathBuf,
    pub anchors: Vec<TrustAnchor>,
    pub allow_missing: bool,
}

impl TrustBundleConfig {
    pub fn from_env() -> Self {
        let root_dir = env::var("TRUST_BUNDLE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let allow_missing = env::var("TRUST_BUNDLE_ALLOW_MISSING")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let paths = env::var("TRUST_BUNDLE_PATHS").ok().map(parse_csv).unwrap_or_default();
        let hashes = env::var("TRUST_BUNDLE_HASHES").ok().map(parse_csv).unwrap_or_default();

        let anchors = paths
            .into_iter()
            .enumerate()
            .map(|(index, path)| TrustAnchor {
                path: PathBuf::from(path),
                sha256: hashes.get(index).cloned().filter(|value| !value.is_empty()),
            })
            .collect::<Vec<TrustAnchor>>();

        Self {
            root_dir,
            anchors,
            allow_missing,
        }
    }
}

/// Result of verifying trust anchors for device identity and channel security.
#[derive(Debug, Clone)]
pub struct TrustBundleReport {
    pub checked_at_unix_ms: u64,
    pub verified: bool,
    pub anchors: Vec<TrustAnchorStatus>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrustAnchorStatus {
    pub path: String,
    pub exists: bool,
    pub hash_match: Option<bool>,
}

pub fn verify_trust_bundle() -> TrustBundleReport {
    let config = TrustBundleConfig::from_env();
    verify_trust_bundle_with_config(&config)
}

pub fn verify_trust_bundle_with_config(config: &TrustBundleConfig) -> TrustBundleReport {
    let checked_at_unix_ms = unix_time_ms();
    let mut failures = Vec::new();
    let mut anchors = Vec::new();
    let mut verified = true;

    if config.anchors.is_empty() {
        failures.push("No trust anchors configured; set TRUST_BUNDLE_PATHS.".to_string());
        verified = false;
    }

    for anchor in &config.anchors {
        let resolved = resolve_anchor_path(&anchor.path, &config.root_dir);
        let path_display = resolved
            .as_ref()
            .map(|value| value.display().to_string())
            .unwrap_or_else(|| anchor.path.display().to_string());
        let mut status = TrustAnchorStatus {
            path: path_display,
            exists: false,
            hash_match: anchor.sha256.as_ref().map(|_| false),
        };

        let resolved = match resolved {
            Some(value) => value,
            None => {
                failures.push("Trust anchor path outside allowed root.".to_string());
                anchors.push(status);
                verified = false;
                continue;
            }
        };

        match std::fs::metadata(&resolved) {
            Ok(metadata) if metadata.is_file() => {
                status.exists = true;
                match verify_anchor_hash(&resolved, anchor.sha256.as_ref()) {
                    Ok(hash_match) => {
                        status.hash_match = anchor.sha256.as_ref().map(|_| hash_match);
                        if let Some(false) = status.hash_match {
                            failures.push("Trust anchor hash mismatch detected.".to_string());
                            verified = false;
                        }
                    }
                    Err(err) => {
                        failures.push(format!("Failed to hash trust anchor: {}", err));
                        verified = false;
                    }
                }
            }
            Ok(_) => {
                failures.push("Trust anchor path is not a file.".to_string());
                verified = false;
            }
            Err(_) => {
                status.exists = false;
                if !config.allow_missing {
                    failures.push("Trust anchor path does not exist.".to_string());
                    verified = false;
                }
            }
        }

        anchors.push(status);
    }

    TrustBundleReport {
        checked_at_unix_ms,
        verified,
        anchors,
        failures,
    }
}

fn resolve_anchor_path(path: &Path, root_dir: &Path) -> Option<PathBuf> {
    let root = root_dir.canonicalize().ok()?;
    let resolved = if path.is_absolute() {
        path.canonicalize().ok()?
    } else {
        root.join(path).canonicalize().ok()?
    };

    if resolved.starts_with(&root) {
        Some(resolved)
    } else {
        None
    }
}

fn verify_anchor_hash(path: &Path, expected: Option<&String>) -> IoResult<bool> {
    if expected.is_none() {
        return Ok(true);
    }
    let hash = hash_file(path)?;
    Ok(expected
        .map(|value| value.eq_ignore_ascii_case(&hash))
        .unwrap_or(true))
}

fn hash_file(path: &Path) -> IoResult<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 8192];

    loop {
        let read_count = file.read(&mut buffer)?;
        if read_count == 0 {
            break;
        }
        hasher.update(&buffer[..read_count]);
    }

    Ok(hex_encode(hasher.finalize()))
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
