use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::time::unix_time_ms;

#[derive(Debug, Clone)]
pub struct UpdatePlan {
    pub manifest_version: String,
    pub manifest_checksum: String,
    pub channel: String,
    pub staged_at_unix_ms: u64,
    pub stage_dir: PathBuf,
    pub total_bytes: u64,
    pub artifacts: Vec<StagedArtifact>,
    pub rollback: RollbackPlan,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StagedArtifact {
    pub name: String,
    pub source_path: PathBuf,
    pub staged_path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct RollbackPlan {
    pub previous_version: Option<String>,
    pub rollback_available: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct UpdateConfig {
    pub manifest_path: Option<PathBuf>,
    pub manifest_json: Option<String>,
    pub stage_dir: PathBuf,
    pub max_payload_bytes: u64,
    pub max_artifacts: usize,
    pub required_channel: Option<String>,
    pub allow_prerelease: bool,
    pub expected_manifest_sha256: Option<String>,
}

impl UpdateConfig {
    pub fn from_env() -> Self {
        let manifest_path = env::var("UPDATE_MANIFEST_PATH").ok().map(PathBuf::from);
        let manifest_json = env::var("UPDATE_MANIFEST_JSON").ok();
        let stage_dir = env::var("UPDATE_STAGE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./staging"));
        let max_payload_bytes = env::var("UPDATE_MAX_PAYLOAD_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(512 * 1024 * 1024);
        let max_artifacts = env::var("UPDATE_MAX_ARTIFACTS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(32);
        let required_channel = env::var("UPDATE_CHANNEL").ok().filter(|value| !value.trim().is_empty());
        let allow_prerelease = env::var("UPDATE_ALLOW_PRERELEASE")
            .ok()
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let expected_manifest_sha256 = env::var("UPDATE_MANIFEST_SHA256")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Self {
            manifest_path,
            manifest_json,
            stage_dir,
            max_payload_bytes,
            max_artifacts,
            required_channel,
            allow_prerelease,
            expected_manifest_sha256,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    pub version: String,
    pub channel: String,
    pub prerelease: bool,
    pub artifacts: Vec<UpdateArtifact>,
    pub previous_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateArtifact {
    pub name: String,
    pub path: String,
    pub sha256: String,
}

pub fn stage_update() -> UpdatePlan {
    let config = UpdateConfig::from_env();
    stage_update_with_config(&config)
}

pub fn stage_update_with_config(config: &UpdateConfig) -> UpdatePlan {
    let staged_at_unix_ms = unix_time_ms();
    let mut warnings = Vec::new();
    let mut total_bytes = 0_u64;
    let mut artifacts = Vec::new();

    let (manifest, manifest_checksum) = match load_manifest(config) {
        Ok(result) => result,
        Err(err) => {
            warnings.push(format!("Failed to load manifest: {}", err));
            return UpdatePlan {
                manifest_version: "unknown".to_string(),
                manifest_checksum: empty_hash(),
                channel: "unknown".to_string(),
                staged_at_unix_ms,
                stage_dir: config.stage_dir.clone(),
                total_bytes,
                artifacts,
                rollback: RollbackPlan {
                    previous_version: None,
                    rollback_available: false,
                    reason: "Manifest unavailable".to_string(),
                },
                warnings,
            };
        }
    };

    if let Some(expected) = &config.expected_manifest_sha256 {
        if !expected.eq_ignore_ascii_case(&manifest_checksum) {
            warnings.push("Manifest checksum mismatch detected.".to_string());
        }
    }

    if let Some(required_channel) = &config.required_channel {
        if &manifest.channel != required_channel {
            warnings.push("Manifest channel does not match required channel.".to_string());
        }
    }

    if manifest.prerelease && !config.allow_prerelease {
        warnings.push("Prerelease manifest supplied but not permitted.".to_string());
    }

    for artifact in manifest.artifacts.iter().take(config.max_artifacts) {
        match stage_artifact(artifact, config) {
            Ok(staged) => {
                total_bytes = total_bytes.saturating_add(staged.size_bytes);
                if total_bytes > config.max_payload_bytes {
                    warnings.push("Staged payload exceeds maximum allowed size.".to_string());
                    break;
                }
                artifacts.push(staged);
            }
            Err(err) => warnings.push(format!("Artifact {} skipped: {}", artifact.name, err)),
        }
    }

    UpdatePlan {
        manifest_version: manifest.version,
        manifest_checksum,
        channel: manifest.channel,
        staged_at_unix_ms,
        stage_dir: config.stage_dir.clone(),
        total_bytes,
        artifacts,
        rollback: RollbackPlan {
            previous_version: manifest.previous_version,
            rollback_available: true,
            reason: "Rollback metadata prepared".to_string(),
        },
        warnings,
    }
}

fn load_manifest(config: &UpdateConfig) -> Result<(UpdateManifest, String), String> {
    if let Some(raw) = &config.manifest_json {
        let manifest = serde_json::from_str::<UpdateManifest>(raw)
            .map_err(|err| format!("Manifest JSON invalid: {}", err))?;
        let checksum = hash_bytes(raw.as_bytes());
        return Ok((manifest, checksum));
    }

    let path = config
        .manifest_path
        .clone()
        .ok_or_else(|| "UPDATE_MANIFEST_PATH or UPDATE_MANIFEST_JSON required".to_string())?;
    let raw = fs::read_to_string(&path).map_err(|err| format!("Unable to read manifest: {}", err))?;
    let manifest = serde_json::from_str::<UpdateManifest>(&raw)
        .map_err(|err| format!("Manifest JSON invalid: {}", err))?;
    let checksum = hash_bytes(raw.as_bytes());
    Ok((manifest, checksum))
}

fn stage_artifact(artifact: &UpdateArtifact, config: &UpdateConfig) -> Result<StagedArtifact, String> {
    if artifact.name.trim().is_empty() {
        return Err("Artifact name missing".to_string());
    }
    let source_path = Path::new(&artifact.path);
    let resolved = resolve_path(source_path)?;
    let metadata = fs::metadata(&resolved).map_err(|_| "Artifact path not accessible".to_string())?;
    if !metadata.is_file() {
        return Err("Artifact path is not a file".to_string());
    }

    let size_bytes = metadata.len();
    let sha256 = hash_file(&resolved).map_err(|_| "Failed to hash artifact".to_string())?;
    let verified = sha256.eq_ignore_ascii_case(&artifact.sha256);
    if !verified {
        return Err("Artifact hash mismatch".to_string());
    }

    let staged_path = config.stage_dir.join(&artifact.name);
    Ok(StagedArtifact {
        name: artifact.name.clone(),
        source_path: resolved,
        staged_path,
        sha256,
        size_bytes,
        verified,
    })
}

fn resolve_path(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|_| "Unable to resolve artifact path".to_string())
}

fn hash_file(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|_| "Unable to read artifact".to_string())?;
    Ok(hash_bytes(&data))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize())
}

fn empty_hash() -> String {
    hex_encode(Sha256::digest([]))
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join("")
}
