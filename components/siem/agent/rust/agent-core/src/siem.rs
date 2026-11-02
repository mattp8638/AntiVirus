use std::env;

use sha2::{Digest, Sha256};

use crate::security::{validate_bounded_string, ValidationLimits};
use crate::time::unix_time_ms;

/// Normalised telemetry event prepared for SIEM delivery.
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    pub event_id: String,
    pub stream: String,
    pub category: String,
    pub severity: TelemetrySeverity,
    pub timestamp_unix_ms: u64,
    pub message: String,
    pub fields: Vec<TelemetryField>,
}

#[derive(Debug, Clone)]
pub struct TelemetryField {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy)]
pub enum TelemetrySeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Prepared SIEM batch with integrity metadata.
#[derive(Debug, Clone)]
pub struct TelemetryBatch {
    pub batch_id: String,
    pub stream: String,
    pub event_count: usize,
    pub dropped_count: usize,
    pub total_payload_bytes: u64,
    pub checksum_sha256: String,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub stream: String,
    pub max_events: usize,
    pub max_event_bytes: u64,
    pub max_batch_bytes: u64,
    pub max_field_count: usize,
    pub max_field_key_len: usize,
    pub max_field_value_len: usize,
}

impl TelemetryConfig {
    pub fn from_env() -> Self {
        let limits = ValidationLimits::default_limits();
        let stream = env::var("TELEMETRY_STREAM")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "sensor".to_string());
        let max_events = env::var("TELEMETRY_MAX_EVENTS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(512);
        let max_event_bytes = env::var("TELEMETRY_MAX_EVENT_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(16 * 1024);
        let max_batch_bytes = env::var("TELEMETRY_MAX_BATCH_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(512 * 1024);
        let max_field_count = env::var("TELEMETRY_MAX_FIELDS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(32);
        let max_field_key_len = env::var("TELEMETRY_MAX_FIELD_KEY_LEN")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(limits.max_command_id_len);
        let max_field_value_len = env::var("TELEMETRY_MAX_FIELD_VALUE_LEN")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(limits.max_payload_len);

        Self {
            stream,
            max_events,
            max_event_bytes,
            max_batch_bytes,
            max_field_count,
            max_field_key_len,
            max_field_value_len,
        }
    }
}

pub fn prepare_telemetry_batch() -> TelemetryBatch {
    let config = TelemetryConfig::from_env();
    let events = ingest_events_from_env(&config);
    prepare_telemetry_batch_from_events(&events, &config)
}

pub fn prepare_telemetry_batch_from_events(
    events: &[TelemetryEvent],
    config: &TelemetryConfig,
) -> TelemetryBatch {
    let created_at_unix_ms = unix_time_ms();
    let mut accepted = Vec::new();
    let mut dropped_count = 0;
    let mut total_payload_bytes = 0_u64;

    for event in events.iter().take(config.max_events) {
        match sanitise_event(event, config) {
            Some(sanitised) => {
                let size = estimate_event_bytes(&sanitised);
                if size > config.max_event_bytes {
                    dropped_count += 1;
                    continue;
                }
                if total_payload_bytes.saturating_add(size) > config.max_batch_bytes {
                    dropped_count += 1;
                    continue;
                }
                total_payload_bytes = total_payload_bytes.saturating_add(size);
                accepted.push(sanitised);
            }
            None => dropped_count += 1,
        }
    }

    let checksum_sha256 = hash_batch(&accepted);
    TelemetryBatch {
        batch_id: format!("siem-{}-{}", config.stream, created_at_unix_ms),
        stream: config.stream.clone(),
        event_count: accepted.len(),
        dropped_count,
        total_payload_bytes,
        checksum_sha256,
        created_at_unix_ms,
    }
}

fn ingest_events_from_env(config: &TelemetryConfig) -> Vec<TelemetryEvent> {
    let now = unix_time_ms();
    let raw = env::var("TELEMETRY_EVENTS").ok();
    let mut events = Vec::new();

    if let Some(raw) = raw {
        for (index, line) in raw.lines().enumerate() {
            if let Some(event) = parse_event_line(line, index, &config.stream, now) {
                events.push(event);
            }
        }
        return events;
    }

    Vec::new()
}

fn parse_event_line(
    line: &str,
    index: usize,
    stream: &str,
    now: u64,
) -> Option<TelemetryEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split('|');
    let category = parts.next()?.trim();
    let severity_raw = parts.next().unwrap_or("informational").trim();
    let message = parts.next().unwrap_or("").trim();
    let fields_raw = parts.next().unwrap_or("");

    let severity = parse_severity(severity_raw);
    let fields = parse_fields(fields_raw);

    Some(TelemetryEvent {
        event_id: format!("evt-{}-{}", now, index),
        stream: stream.to_string(),
        category: category.to_string(),
        severity,
        timestamp_unix_ms: now,
        message: message.to_string(),
        fields,
    })
}

fn parse_severity(value: &str) -> TelemetrySeverity {
    match value.to_lowercase().as_str() {
        "critical" => TelemetrySeverity::Critical,
        "high" => TelemetrySeverity::High,
        "medium" => TelemetrySeverity::Medium,
        "low" => TelemetrySeverity::Low,
        _ => TelemetrySeverity::Informational,
    }
}

fn parse_fields(value: &str) -> Vec<TelemetryField> {
    value
        .split(';')
        .filter_map(|entry| {
            let mut parts = entry.splitn(2, '=');
            let key = parts.next()?.trim();
            let value = parts.next()?.trim();
            if key.is_empty() || value.is_empty() {
                return None;
            }
            Some(TelemetryField {
                key: key.to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

fn sanitise_event(event: &TelemetryEvent, config: &TelemetryConfig) -> Option<TelemetryEvent> {
    if !validate_bounded_string(&event.event_id, 128) {
        return None;
    }
    if !validate_bounded_string(&event.stream, 64) {
        return None;
    }
    if !validate_bounded_string(&event.category, 128) {
        return None;
    }
    let message = sanitise_text(&event.message, config.max_field_value_len);
    let mut fields = Vec::new();

    for field in event.fields.iter().take(config.max_field_count) {
        if !validate_bounded_string(&field.key, config.max_field_key_len) {
            continue;
        }
        let value = sanitise_text(&field.value, config.max_field_value_len);
        if value.is_empty() {
            continue;
        }
        fields.push(TelemetryField {
            key: field.key.clone(),
            value,
        });
    }

    Some(TelemetryEvent {
        event_id: event.event_id.clone(),
        stream: event.stream.clone(),
        category: event.category.clone(),
        severity: event.severity,
        timestamp_unix_ms: event.timestamp_unix_ms,
        message,
        fields,
    })
}

fn sanitise_text(value: &str, max_len: usize) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

fn estimate_event_bytes(event: &TelemetryEvent) -> u64 {
    let mut total = event.event_id.len()
        + event.stream.len()
        + event.category.len()
        + event.message.len();
    total += event.fields.iter().map(|field| field.key.len() + field.value.len()).sum::<usize>();
    total as u64
}

fn hash_batch(events: &[TelemetryEvent]) -> String {
    let mut hasher = Sha256::new();
    for event in events {
        hasher.update(event.event_id.as_bytes());
        hasher.update(event.stream.as_bytes());
        hasher.update(event.category.as_bytes());
        hasher.update(event.timestamp_unix_ms.to_le_bytes());
        hasher.update(event.message.as_bytes());
        for field in &event.fields {
            hasher.update(field.key.as_bytes());
            hasher.update(field.value.as_bytes());
        }
    }
    hex_encode(hasher.finalize())
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join("")
}
