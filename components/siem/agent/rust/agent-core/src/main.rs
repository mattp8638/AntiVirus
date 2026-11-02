use std::time::Duration;

use tokio::signal;
use tracing::{info, warn};

mod command_router;
mod compliance;
mod config;
mod edr;
mod evidence;
mod identity;
mod ipc;
mod ipc_router;
mod ipc_validation;
mod pipeline;
mod policy;
mod proto;
mod rate_limit;
mod rmm;
mod security;
mod service_registry;
mod siem;
mod telemetry_router;
mod time;
mod uplink;
mod update;
mod vulnerability;

use crate::command_router::{route_command, SignedCommand};
use crate::compliance::run_self_audit;
use crate::config::CoreConfig;
use crate::edr::evaluate_rules;
use crate::identity::{verify_trust_bundle, AgentIdentity};
use crate::ipc::IpcServer;
use crate::pipeline::PipelineStatus;
use crate::policy::PolicyBundle;
use crate::rate_limit::RateLimiter;
use crate::rmm::queue_execution_request;
use crate::service_registry::{ServiceDescriptor, ServiceRegistry};
use crate::siem::prepare_telemetry_batch;
use crate::telemetry_router::{route_telemetry, TelemetryPayload};
use crate::time::unix_time_ms;
use crate::uplink::{process_uplink_queue, run_uplink_worker};
use crate::vulnerability::assess_exposure;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let config = CoreConfig::from_env();
    let identity = AgentIdentity::new(config.asset_id.clone(), config.agent_id.clone());

    info!(asset_id = %identity.asset_id, agent_id = %identity.agent_id, "agent core starting");

    let trust_report = verify_trust_bundle();
    if !trust_report.verified {
        warn!("trust bundle verification failed; refusing to start services");
        return;
    }

    let policy = PolicyBundle::from_env();
    let policy_now = unix_time_ms();
    let validation_options = crate::policy::PolicyValidationOptions::from_env();
    if !policy.validate(policy_now, &validation_options) {
        warn!("policy validation failed; refusing to start services");
        return;
    }

    let rate_limiter = RateLimiter::new(600);
    let ipc_server = IpcServer::new(
        config.ipc_pipe_name.clone(),
        config.max_payload_bytes,
        rate_limiter,
        policy.clone(),
    );
    ipc_server.start();

    let mut registry = ServiceRegistry::new();
    registry.register(ServiceDescriptor {
        name: "agent-sensor".to_string(),
        version: "0.1.0".to_string(),
        ipc_endpoint: "sensor-pipe".to_string(),
    });
    registry.register(ServiceDescriptor {
        name: "agent-exec".to_string(),
        version: "0.1.0".to_string(),
        ipc_endpoint: "exec-pipe".to_string(),
    });

    let _compliance_results = run_self_audit();
    let _detections = evaluate_rules();
    let _execution_request = queue_execution_request(&policy);
    let _telemetry_batch = prepare_telemetry_batch();
    let _vulnerability_findings = assess_exposure();

    let _telemetry_routed = route_telemetry(TelemetryPayload {
        stream: "sensor".to_string(),
        payload_bytes: 1,
        event_count: 1,
        checksum_sha256: Some("checksum-placeholder".to_string()),
    }, &policy);
    let _uplink_summary = process_uplink_queue().await;
    tokio::spawn(run_uplink_worker());
    let _command_routed = route_command(SignedCommand {
        command_id: "cmd-placeholder".to_string(),
        signed_payload: "payload-placeholder".to_string(),
        action: "script-run".to_string(),
        arguments: vec!["-version".to_string()],
        not_before_unix_time_ms: unix_time_ms().saturating_sub(1_000),
        not_after_unix_time_ms: unix_time_ms().saturating_add(60_000),
    }, &policy, unix_time_ms());

    let mut pipeline_status = PipelineStatus::new();
    pipeline_status.mark_edr_ready();
    pipeline_status.mark_siem_ready();
    pipeline_status.mark_rmm_ready();
    pipeline_status.mark_vulnerability_ready();
    info!(ready = pipeline_status.is_fully_ready(), "pipeline status initialised");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("shutdown signal received");
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                info!("heartbeat tick");
            }
        }
    }

    info!("agent core stopping");
}
