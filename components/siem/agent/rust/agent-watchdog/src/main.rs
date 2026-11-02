use std::env;
use std::time::Duration;

use tokio::signal;
use tracing::{info, warn};

#[derive(Debug, Clone)]
struct WatchdogConfig {
    interval_secs: u64,
    grace_misses: u32,
    max_restart_attempts: u32,
    runbook_url: Option<String>,
}

impl WatchdogConfig {
    fn from_env() -> Self {
        let interval_secs = env::var("WATCHDOG_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(15);
        let grace_misses = env::var("WATCHDOG_GRACE_MISSES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(3);
        let max_restart_attempts = env::var("WATCHDOG_MAX_RESTART_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(3);
        let runbook_url = env::var("WATCHDOG_RUNBOOK_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Self {
            interval_secs,
            grace_misses,
            max_restart_attempts,
            runbook_url,
        }
    }
}

#[derive(Debug, Clone)]
struct HealthProbe {
    consecutive_failures: u32,
    restart_attempts: u32,
    last_status: Option<HealthStatus>,
}

#[derive(Debug, Clone)]
enum HealthStatus {
    Healthy,
    Degraded { reason: String },
    Unreachable { reason: String },
}

impl HealthProbe {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            restart_attempts: 0,
            last_status: None,
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    info!("agent watchdog starting");

    let config = WatchdogConfig::from_env();
    let mut probe = HealthProbe::new();

    info!(
        interval_secs = config.interval_secs,
        grace_misses = config.grace_misses,
        max_restart_attempts = config.max_restart_attempts,
        "watchdog configuration loaded"
    );

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("shutdown signal received");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(config.interval_secs)) => {
                let status = check_agent_core_health();
                handle_status(&mut probe, &config, status);
            }
        }
    }

    info!("agent watchdog stopping");
}

fn check_agent_core_health() -> HealthStatus {
    let mode = env::var("WATCHDOG_HEALTH_MODE")
        .ok()
        .unwrap_or_else(|| "healthy".to_string())
        .to_lowercase();

    match mode.as_str() {
        "degraded" => HealthStatus::Degraded {
            reason: "Agent core heartbeat delayed".to_string(),
        },
        "unreachable" => HealthStatus::Unreachable {
            reason: "Agent core heartbeat missing".to_string(),
        },
        _ => HealthStatus::Healthy,
    }
}

fn handle_status(probe: &mut HealthProbe, config: &WatchdogConfig, status: HealthStatus) {
    probe.last_status = Some(status.clone());

    match status {
        HealthStatus::Healthy => {
            probe.consecutive_failures = 0;
            info!("watchdog heartbeat healthy");
        }
        HealthStatus::Degraded { reason } => {
            probe.consecutive_failures = probe.consecutive_failures.saturating_add(1);
            warn!(
                failures = probe.consecutive_failures,
                reason = %reason,
                "watchdog detected degraded state"
            );
            maybe_restart_agent_core(probe, config, "Degraded state");
        }
        HealthStatus::Unreachable { reason } => {
            probe.consecutive_failures = probe.consecutive_failures.saturating_add(1);
            warn!(
                failures = probe.consecutive_failures,
                reason = %reason,
                "watchdog detected unreachable state"
            );
            maybe_restart_agent_core(probe, config, "Unreachable state");
        }
    }
}

fn maybe_restart_agent_core(probe: &mut HealthProbe, config: &WatchdogConfig, reason: &str) {
    if probe.consecutive_failures <= config.grace_misses {
        return;
    }
    if probe.restart_attempts >= config.max_restart_attempts {
        warn!(
            reason,
            runbook = config.runbook_url.as_deref().unwrap_or("not-configured"),
            "restart limit reached; escalation required"
        );
        return;
    }

    probe.restart_attempts = probe.restart_attempts.saturating_add(1);
    info!(
        attempt = probe.restart_attempts,
        reason,
        "issuing agent-core restart request (placeholder)"
    );
}
