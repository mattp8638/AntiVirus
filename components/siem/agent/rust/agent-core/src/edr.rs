use std::collections::HashSet;
use std::env;

/// Summary of a detection surfaced by the EDR rules engine.
#[derive(Debug, Clone)]
pub struct DetectionSummary {
    pub detection_id: String,
    pub severity: u8,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub event_id: String,
    pub confidence: u8,
}

/// Runtime configuration for EDR evaluation, sourced from environment variables.
#[derive(Debug, Clone)]
pub struct EdrConfig {
    pub max_detections_per_cycle: usize,
    pub suspicious_ports: Vec<u16>,
    pub sensitive_paths: Vec<String>,
}

impl EdrConfig {
    pub fn from_env() -> Self {
        let max_detections_per_cycle = env::var("EDR_MAX_DETECTIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(64);
        let suspicious_ports = env::var("EDR_SUSPICIOUS_PORTS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .filter_map(|entry| entry.trim().parse::<u16>().ok())
                    .collect::<Vec<u16>>()
            })
            .unwrap_or_else(|| vec![4444, 1337, 3389, 5985, 5986]);
        let sensitive_paths = env::var("EDR_SENSITIVE_PATHS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(|entry| entry.trim().to_string())
                    .filter(|entry| !entry.is_empty())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_else(|| {
                vec![
                    "c:/windows/system32".to_string(),
                    "c:/windows/temp".to_string(),
                    "/etc".to_string(),
                    "/usr/bin".to_string(),
                    "/tmp".to_string(),
                ]
            });

        Self {
            max_detections_per_cycle,
            suspicious_ports,
            sensitive_paths,
        }
    }
}

/// Normalised events emitted by platform sensors for rule evaluation.
#[derive(Debug, Clone)]
pub enum EdrEventKind {
    ProcessStart {
        image_path: String,
        command_line: String,
        parent_image: String,
        is_signed: bool,
    },
    FileWrite {
        path: String,
        size_bytes: u64,
        originating_process: String,
    },
    NetworkConnection {
        destination_ip: String,
        destination_port: u16,
        protocol: String,
        process_name: String,
    },
}

/// Single EDR event with a stable identifier and timestamp for correlation.
#[derive(Debug, Clone)]
pub struct EdrEvent {
    pub event_id: String,
    pub timestamp_unix_ms: u64,
    pub kind: EdrEventKind,
}

#[derive(Debug, Clone)]
struct EdrRule {
    id: String,
    title: String,
    description: String,
    severity: u8,
    matcher: RuleMatcher,
}

#[derive(Debug, Clone)]
enum RuleMatcher {
    ProcessCommandContains(Vec<&'static str>),
    UnsignedExecutionFromDirs(Vec<&'static str>),
    NetworkPortIn(Vec<u16>),
    FileWriteToSensitiveDirs,
}

impl RuleMatcher {
    fn matches(&self, event: &EdrEvent, config: &EdrConfig) -> bool {
        match (self, &event.kind) {
            (RuleMatcher::ProcessCommandContains(tokens), EdrEventKind::ProcessStart { command_line, .. }) => {
                let normalised = normalise_text(command_line);
                tokens.iter().any(|token| normalised.contains(token))
            }
            (RuleMatcher::UnsignedExecutionFromDirs(dirs), EdrEventKind::ProcessStart { image_path, is_signed, .. }) => {
                if *is_signed {
                    return false;
                }
                let path = normalise_path(image_path);
                dirs.iter().any(|dir| path.starts_with(dir))
            }
            (RuleMatcher::NetworkPortIn(ports), EdrEventKind::NetworkConnection { destination_port, .. }) => {
                ports.contains(destination_port)
            }
            (RuleMatcher::FileWriteToSensitiveDirs, EdrEventKind::FileWrite { path, .. }) => {
                let normalised = normalise_path(path);
                config
                    .sensitive_paths
                    .iter()
                    .map(|entry| normalise_path(entry))
                    .any(|entry| normalised.starts_with(&entry))
            }
            _ => false,
        }
    }
}

/// Evaluate rules using a temporary sample event set (to be replaced by live telemetry).
pub fn evaluate_rules() -> Vec<DetectionSummary> {
    let config = EdrConfig::from_env();
    let events = sample_events();
    evaluate_rules_for_events(&events, &config)
}

pub fn evaluate_rules_for_events(events: &[EdrEvent], config: &EdrConfig) -> Vec<DetectionSummary> {
    let rules = build_rules(config);
    let mut detections = Vec::new();
    let mut seen = HashSet::new();

    for event in events {
        for rule in &rules {
            if !rule.matcher.matches(event, config) {
                continue;
            }

            let detection_id = format!("det-{}-{}", rule.id, event.event_id);
            if !seen.insert(detection_id.clone()) {
                continue;
            }

            detections.push(DetectionSummary {
                detection_id,
                severity: rule.severity,
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                description: rule.description.clone(),
                event_id: event.event_id.clone(),
                confidence: calculate_confidence(rule, event),
            });

            if detections.len() >= config.max_detections_per_cycle {
                return detections;
            }
        }
    }

    detections
}

fn build_rules(config: &EdrConfig) -> Vec<EdrRule> {
    let mut rules = Vec::new();

    rules.push(EdrRule {
        id: "EDR-PSH-ENC".to_string(),
        title: "Encoded PowerShell invocation".to_string(),
        description: "Process command line includes encoded PowerShell flags indicative of obfuscation."
            .to_string(),
        severity: 8,
        matcher: RuleMatcher::ProcessCommandContains(vec!["powershell", "-enc", "-encodedcommand"]),
    });

    rules.push(EdrRule {
        id: "EDR-TEMP-UNSIGNED".to_string(),
        title: "Unsigned execution from temporary directory".to_string(),
        description: "Unsigned binary launched from common temporary locations.".to_string(),
        severity: 7,
        matcher: RuleMatcher::UnsignedExecutionFromDirs(vec!["c:/windows/temp", "c:/users", "/tmp", "/var/tmp"]),
    });

    rules.push(EdrRule {
        id: "EDR-SUSP-PORT".to_string(),
        title: "Outbound connection to suspicious port".to_string(),
        description: "Network connection targeting ports commonly abused for remote access or C2."
            .to_string(),
        severity: 6,
        matcher: RuleMatcher::NetworkPortIn(config.suspicious_ports.clone()),
    });

    rules.push(EdrRule {
        id: "EDR-SENSITIVE-WRITE".to_string(),
        title: "Sensitive path file write".to_string(),
        description: "Process writing to system-sensitive directories.".to_string(),
        severity: 5,
        matcher: RuleMatcher::FileWriteToSensitiveDirs,
    });

    rules
}

fn calculate_confidence(rule: &EdrRule, event: &EdrEvent) -> u8 {
    match (&rule.matcher, &event.kind) {
        (RuleMatcher::ProcessCommandContains(_), EdrEventKind::ProcessStart { command_line, .. }) => {
            if normalise_text(command_line).contains("-encodedcommand") {
                85
            } else {
                70
            }
        }
        (RuleMatcher::UnsignedExecutionFromDirs(_), EdrEventKind::ProcessStart { is_signed, .. }) => {
            if *is_signed { 30 } else { 80 }
        }
        (RuleMatcher::NetworkPortIn(_), EdrEventKind::NetworkConnection { destination_port, .. }) => {
            if *destination_port == 4444 { 75 } else { 60 }
        }
        (RuleMatcher::FileWriteToSensitiveDirs, EdrEventKind::FileWrite { .. }) => 55,
        _ => 40,
    }
}

fn sample_events() -> Vec<EdrEvent> {
    vec![
        EdrEvent {
            event_id: "evt-psh-001".to_string(),
            timestamp_unix_ms: 1_700_000_000_000,
            kind: EdrEventKind::ProcessStart {
                image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
                command_line: "powershell.exe -NoP -Enc aGVsbG8=".to_string(),
                parent_image: "C:\\Windows\\explorer.exe".to_string(),
                is_signed: true,
            },
        },
        EdrEvent {
            event_id: "evt-net-002".to_string(),
            timestamp_unix_ms: 1_700_000_010_000,
            kind: EdrEventKind::NetworkConnection {
                destination_ip: "203.0.113.10".to_string(),
                destination_port: 4444,
                protocol: "tcp".to_string(),
                process_name: "svchost.exe".to_string(),
            },
        },
        EdrEvent {
            event_id: "evt-file-003".to_string(),
            timestamp_unix_ms: 1_700_000_020_000,
            kind: EdrEventKind::FileWrite {
                path: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
                size_bytes: 512,
                originating_process: "notepad.exe".to_string(),
            },
        },
    ]
}

fn normalise_path(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .to_lowercase()
        .trim_end_matches('/')
        .to_string()
}

fn normalise_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .to_lowercase()
}
