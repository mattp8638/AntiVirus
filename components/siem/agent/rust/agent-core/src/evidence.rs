use std::env;
use std::fs::File;
use std::io::{Read, Result as IoResult};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::time::unix_time_ms;

/// Captured evidence with hashes to support tamper-proofing.
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub sha256: String,
    pub collected_at_unix_ms: u64,
    pub total_bytes: u64,
    pub status: EvidenceStatus,
    pub items: Vec<EvidenceItem>,
    pub notes: Vec<String>,
}

/// Individual evidence artefact stored as part of a collection run.
#[derive(Debug, Clone)]
pub struct EvidenceItem {
    pub item_id: String,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub collected_at_unix_ms: u64,
    pub outcome: EvidenceOutcome,
}

#[derive(Debug, Clone)]
pub enum EvidenceStatus {
    Collected,
    Partial,
    Empty,
}

#[derive(Debug, Clone)]
pub enum EvidenceOutcome {
    Collected,
    Skipped { reason: String },
}

/// Configuration that controls which evidence items are collected and how much data is processed.
#[derive(Debug, Clone)]
pub struct EvidenceConfig {
    pub root_dir: PathBuf,
    pub max_item_bytes: u64,
    pub max_total_bytes: u64,
    pub max_items: usize,
    pub allowed_extensions: Vec<String>,
    pub evidence_paths: Vec<PathBuf>,
}

impl EvidenceConfig {
    pub fn from_env() -> Self {
        let root_dir = env::var("EVIDENCE_ROOT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let max_item_bytes = env::var("EVIDENCE_MAX_ITEM_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(25 * 1024 * 1024);
        let max_total_bytes = env::var("EVIDENCE_MAX_TOTAL_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(100 * 1024 * 1024);
        let max_items = env::var("EVIDENCE_MAX_ITEMS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(128);
        let allowed_extensions = env::var("EVIDENCE_ALLOWED_EXTENSIONS")
            .ok()
            .map(parse_csv)
            .unwrap_or_else(|| vec!["log".into(), "txt".into(), "json".into(), "evtx".into()]);
        let evidence_paths = env::var("EVIDENCE_PATHS")
            .ok()
            .map(parse_csv)
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect::<Vec<PathBuf>>();

        Self {
            root_dir,
            max_item_bytes,
            max_total_bytes,
            max_items,
            allowed_extensions,
            evidence_paths,
        }
    }
}

/// Package evidence according to configuration. In production, EVIDENCE_PATHS should be
/// populated with absolute or root-relative file paths to capture.
pub fn package_evidence() -> EvidenceRecord {
    let config = EvidenceConfig::from_env();
    package_evidence_with_config(&config)
}

pub fn package_evidence_with_config(config: &EvidenceConfig) -> EvidenceRecord {
    let collected_at_unix_ms = unix_time_ms();
    let evidence_id = format!("evd-{}", collected_at_unix_ms);
    let mut notes = Vec::new();

    if config.evidence_paths.is_empty() {
        notes.push("No evidence paths configured; set EVIDENCE_PATHS to collect artefacts.".to_string());
        return EvidenceRecord {
            evidence_id,
            sha256: empty_hash(),
            collected_at_unix_ms,
            total_bytes: 0,
            status: EvidenceStatus::Empty,
            items: Vec::new(),
            notes,
        };
    }

    let mut total_bytes = 0_u64;
    let mut items = Vec::new();
    let mut collected_any = false;

    for (index, path) in config.evidence_paths.iter().enumerate() {
        if items.len() >= config.max_items {
            notes.push("Maximum evidence item count reached.".to_string());
            break;
        }

        match collect_item(path, config, collected_at_unix_ms, index) {
            Ok((item, bytes_written, was_collected)) => {
                total_bytes = total_bytes.saturating_add(bytes_written);
                collected_any |= was_collected;
                items.push(item);
            }
            Err(err) => {
                notes.push(format!("Failed to collect {}: {}", path.display(), err));
                items.push(EvidenceItem {
                    item_id: format!("item-{}", index),
                    path: path.display().to_string(),
                    sha256: empty_hash(),
                    size_bytes: 0,
                    collected_at_unix_ms,
                    outcome: EvidenceOutcome::Skipped {
                        reason: "Collection error".to_string(),
                    },
                });
            }
        }

        if total_bytes >= config.max_total_bytes {
            notes.push("Maximum total evidence size reached.".to_string());
            break;
        }
    }

    let status = if items.is_empty() {
        EvidenceStatus::Empty
    } else if collected_any {
        if notes.is_empty() {
            EvidenceStatus::Collected
        } else {
            EvidenceStatus::Partial
        }
    } else {
        EvidenceStatus::Partial
    };

    EvidenceRecord {
        evidence_id,
        sha256: hash_manifest(&items),
        collected_at_unix_ms,
        total_bytes,
        status,
        items,
        notes,
    }
}

fn collect_item(
    path: &Path,
    config: &EvidenceConfig,
    collected_at_unix_ms: u64,
    index: usize,
) -> IoResult<(EvidenceItem, u64, bool)> {
    let item_id = format!("item-{}", index);
    let resolved = resolve_path(path, &config.root_dir);
    let path_display = resolved.as_ref().map(|value| value.display().to_string()).unwrap_or_else(|| path.display().to_string());

    let resolved = match resolved {
        Some(value) => value,
        None => {
            return Ok((
                EvidenceItem {
                    item_id,
                    path: path_display,
                    sha256: empty_hash(),
                    size_bytes: 0,
                    collected_at_unix_ms,
                    outcome: EvidenceOutcome::Skipped {
                        reason: "Path outside evidence root".to_string(),
                    },
                },
                0,
                false,
            ));
        }
    };

    if !is_extension_allowed(&resolved, &config.allowed_extensions) {
        return Ok((
            EvidenceItem {
                item_id,
                path: path_display,
                sha256: empty_hash(),
                size_bytes: 0,
                collected_at_unix_ms,
                outcome: EvidenceOutcome::Skipped {
                    reason: "Disallowed file extension".to_string(),
                },
            },
            0,
            false,
        ));
    }

    let metadata = std::fs::metadata(&resolved)?;
    if !metadata.is_file() {
        return Ok((
            EvidenceItem {
                item_id,
                path: path_display,
                sha256: empty_hash(),
                size_bytes: 0,
                collected_at_unix_ms,
                outcome: EvidenceOutcome::Skipped {
                    reason: "Not a regular file".to_string(),
                },
            },
            0,
            false,
        ));
    }

    let size_bytes = metadata.len();
    if size_bytes > config.max_item_bytes {
        return Ok((
            EvidenceItem {
                item_id,
                path: path_display,
                sha256: empty_hash(),
                size_bytes,
                collected_at_unix_ms,
                outcome: EvidenceOutcome::Skipped {
                    reason: "File exceeds per-item limit".to_string(),
                },
            },
            0,
            false,
        ));
    }

    let sha256 = hash_file(&resolved)?;
    Ok((
        EvidenceItem {
            item_id,
            path: path_display,
            sha256,
            size_bytes,
            collected_at_unix_ms,
            outcome: EvidenceOutcome::Collected,
        },
        size_bytes,
        true,
    ))
}

fn resolve_path(path: &Path, root: &Path) -> Option<PathBuf> {
    let root = root.canonicalize().ok()?;
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

fn is_extension_allowed(path: &Path, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| allowed.iter().any(|item| item.eq_ignore_ascii_case(ext)))
        .unwrap_or(false)
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

fn hash_manifest(items: &[EvidenceItem]) -> String {
    let mut hasher = Sha256::new();
    for item in items {
        hasher.update(item.item_id.as_bytes());
        hasher.update(item.sha256.as_bytes());
        hasher.update(item.path.as_bytes());
        hasher.update(item.size_bytes.to_le_bytes());
    }
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

fn parse_csv(value: String) -> Vec<String> {
    value
        .split(',')
        .map(|entry| entry.trim().trim_start_matches('.').to_string())
        .filter(|entry| !entry.is_empty())
        .collect()
}
