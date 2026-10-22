use std::path::{Path, PathBuf};

use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};
use serde::Deserialize;
use tokio::fs;
use tracing::{info, warn};

use crate::time::unix_time_ms;

#[derive(Debug, Clone)]
pub struct UplinkConfig {
    pub intake_endpoint: String,
    pub rmm_endpoint: String,
    pub rmm_base_endpoint: String,
    pub rmm_mtls_base_endpoint: String,
    pub patch_endpoint: String,
    pub inventory_base_endpoint: String,
    pub api_key: Option<String>,
    pub queue_dir: PathBuf,
    pub max_items_per_cycle: usize,
}

impl UplinkConfig {
    pub fn from_env() -> Self {
        let intake_endpoint = std::env::var("TAMSIL_UPLINK_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:8001/intake".to_string());
        let rmm_endpoint = std::env::var("TAMSIL_RMM_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:8020/rmm/evidence".to_string());
        let rmm_base_endpoint = std::env::var("TAMSIL_RMM_BASE_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:8020/rmm".to_string());
        let rmm_mtls_base_endpoint = std::env::var("TAMSIL_RMM_MTLS_BASE_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:8020/mtls/rmm".to_string());
        let patch_endpoint = std::env::var("TAMSIL_PSA_PATCH_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:8001/patch-results".to_string());
        let inventory_base_endpoint = std::env::var("TAMSIL_INVENTORY_BASE_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:8020/mtls/inventory".to_string());
        let api_key = std::env::var("TAMSIL_UPLINK_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let queue_dir = std::env::var("RUST_UPLINK_QUEUE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("uplink_queue"));
        let max_items_per_cycle = std::env::var("RUST_UPLINK_MAX_ITEMS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(64);

        Self {
            intake_endpoint,
            rmm_endpoint,
            rmm_base_endpoint,
            rmm_mtls_base_endpoint,
            patch_endpoint,
            inventory_base_endpoint,
            api_key,
            queue_dir,
            max_items_per_cycle,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind")]
enum UplinkQueueItem {
    #[serde(rename = "evidence")]
    Evidence {
        evidence_id: String,
        tenant_id: String,
        asset_id: String,
        source: String,
        #[serde(rename = "type")]
        evidence_type: String,
        related_id: String,
        hash: String,
        storage_uri: String,
        captured_at: String,
    },
    #[serde(rename = "patch")]
    Patch { payload_json: String },
    #[serde(rename = "rmm")]
    Rmm { path: String, payload_json: String },
    #[serde(rename = "mtls_rmm")]
    MtlsRmm { path: String, payload_json: String },
    #[serde(rename = "inventory")]
    Inventory { path: String, payload_json: String },
}

#[derive(Debug, Clone)]
pub struct UplinkSummary {
    pub processed: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub completed_at_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct UplinkWorkerConfig {
    pub interval_secs: u64,
}

impl UplinkWorkerConfig {
    pub fn from_env() -> Self {
        let interval_secs = std::env::var("RUST_UPLINK_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30);
        Self { interval_secs }
    }
}

pub async fn process_uplink_queue() -> UplinkSummary {
    let config = UplinkConfig::from_env();
    process_uplink_queue_with_config(&config).await
}

pub async fn run_uplink_worker() {
    let config = UplinkConfig::from_env();
    let worker = UplinkWorkerConfig::from_env();

    info!(
        interval_secs = worker.interval_secs,
        queue_dir = %config.queue_dir.display(),
        "uplink worker started"
    );

    loop {
        let summary = process_uplink_queue_with_config(&config).await;
        info!(
            processed = summary.processed,
            succeeded = summary.succeeded,
            failed = summary.failed,
            "uplink worker cycle complete"
        );
        tokio::time::sleep(std::time::Duration::from_secs(worker.interval_secs)).await;
    }
}

pub async fn process_uplink_queue_with_config(config: &UplinkConfig) -> UplinkSummary {
    let mut processed = 0;
    let mut succeeded = 0;
    let mut failed = 0;

    let client = build_client(config);
    let mut entries = match fs::read_dir(&config.queue_dir).await {
        Ok(entries) => entries,
        Err(err) => {
            warn!(error = %err, "uplink queue directory not accessible");
            return UplinkSummary {
                processed,
                succeeded,
                failed,
                completed_at_unix_ms: unix_time_ms(),
            };
        }
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        if processed >= config.max_items_per_cycle {
            break;
        }
        let path = entry.path();
        if !is_json_file(&path) {
            continue;
        }

        processed += 1;
        match handle_queue_item(&path, &client, config).await {
            Ok(true) => {
                succeeded += 1;
                if let Err(err) = fs::remove_file(&path).await {
                    warn!(error = %err, path = %path.display(), "failed to delete uplink queue item");
                }
            }
            Ok(false) => {
                failed += 1;
            }
            Err(err) => {
                failed += 1;
                warn!(error = %err, path = %path.display(), "uplink queue item failed");
            }
        }
    }

    UplinkSummary {
        processed,
        succeeded,
        failed,
        completed_at_unix_ms: unix_time_ms(),
    }
}

async fn handle_queue_item(
    path: &Path,
    client: &reqwest::Client,
    config: &UplinkConfig,
) -> Result<bool, String> {
    let raw = fs::read_to_string(path)
        .await
        .map_err(|err| format!("failed to read uplink item: {err}"))?;
    let item: UplinkQueueItem = serde_json::from_str(&raw)
        .map_err(|err| format!("invalid uplink item json: {err}"))?;

    match item {
        UplinkQueueItem::Evidence {
            evidence_id,
            tenant_id,
            asset_id,
            source,
            evidence_type,
            related_id,
            hash,
            storage_uri,
            captured_at: _,
        } => {
            let intake_payload = build_intake_payload(
                &tenant_id,
                &asset_id,
                &source,
                &evidence_id,
                &related_id,
                &hash,
                &storage_uri,
            );
            let intake_ok = post_json(client, &config.intake_endpoint, &intake_payload).await;
            let rmm_payload = build_rmm_payload(
                &tenant_id,
                &asset_id,
                &related_id,
                &hash,
                &storage_uri,
                &evidence_type,
            );
            let rmm_ok = post_json(client, &config.rmm_endpoint, &rmm_payload).await;

            Ok(intake_ok && rmm_ok)
        }
        UplinkQueueItem::Patch { payload_json } => Ok(post_json(client, &config.patch_endpoint, &payload_json).await),
        UplinkQueueItem::Rmm { path, payload_json } => {
            let endpoint = join_endpoint(&config.rmm_base_endpoint, &path);
            Ok(post_json(client, &endpoint, &payload_json).await)
        }
        UplinkQueueItem::MtlsRmm { path, payload_json } => {
            let endpoint = join_endpoint(&config.rmm_mtls_base_endpoint, &path);
            Ok(post_json(client, &endpoint, &payload_json).await)
        }
        UplinkQueueItem::Inventory { path, payload_json } => {
            let endpoint = join_endpoint(&config.inventory_base_endpoint, &path);
            Ok(post_json(client, &endpoint, &payload_json).await)
        }
    }
}

fn build_client(config: &UplinkConfig) -> reqwest::Client {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(USER_AGENT, HeaderValue::from_static("TamsilAgent/1.0"));
    headers.insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
    if let Some(api_key) = &config.api_key {
        if let Ok(value) = HeaderValue::from_str(api_key) {
            headers.insert("X-API-Key", value);
        }
    }

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("failed to build uplink http client")
}

async fn post_json(client: &reqwest::Client, endpoint: &str, payload: &str) -> bool {
    match client.post(endpoint).body(payload.to_string()).send().await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                true
            } else {
                warn!(%status, endpoint, "uplink request returned non-success status");
                false
            }
        }
        Err(err) => {
            warn!(error = %err, endpoint, "uplink request failed");
            false
        }
    }
}

fn build_intake_payload(
    tenant_id: &str,
    asset_id: &str,
    source: &str,
    evidence_id: &str,
    related_id: &str,
    hash: &str,
    storage_uri: &str,
) -> String {
    let asset_id = normalise_fallback(asset_id, source, "agent-local");
    let tenant_id = normalise_fallback(tenant_id, "", "tamsil-agent");
    let linked_object_id = if related_id.is_empty() { evidence_id } else { related_id };
    let immutable_reference = if evidence_id.is_empty() {
        format!("ev-{linked_object_id}")
    } else {
        evidence_id.to_string()
    };

    serde_json::json!({
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "source_type": "finding",
        "source_reference_id": evidence_id,
        "risk_score": 50.0,
        "asset_criticality": "medium",
        "exposure_level": "internal",
        "time_sensitivity": "none",
        "system_recommendation": serde_json::Value::Null,
        "evidence": [{
            "linked_object_type": "finding",
            "linked_object_id": linked_object_id,
            "immutable_reference": immutable_reference,
            "payload": {
                "hash": hash,
                "stored_uri": storage_uri
            }
        }]
    })
    .to_string()
}

fn build_rmm_payload(
    tenant_id: &str,
    asset_id: &str,
    related_id: &str,
    hash: &str,
    storage_uri: &str,
    evidence_type: &str,
) -> String {
    let mut payload = serde_json::json!({
        "asset_id": asset_id,
        "evidence_type": if evidence_type.is_empty() { "agent_evidence" } else { evidence_type },
        "related_entity": "agent",
        "related_id": related_id,
        "storage_uri": storage_uri,
        "hash": hash
    });
    if !tenant_id.trim().is_empty() {
        payload["tenant_id"] = serde_json::Value::String(tenant_id.to_string());
    }
    payload.to_string()
}

fn normalise_fallback(value: &str, alternate: &str, fallback: &str) -> String {
    if value.trim().len() >= 3 {
        value.to_string()
    } else if alternate.trim().len() >= 3 {
        alternate.to_string()
    } else {
        fallback.to_string()
    }
}

fn join_endpoint(base: &str, path: &str) -> String {
    let trimmed_base = base.trim_end_matches('/');
    let trimmed_path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{trimmed_base}{trimmed_path}")
}

fn is_json_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}
