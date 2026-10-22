//! TamsilCMS Sentinel EDR Agent
//!
//! Reports to TamsilCMS SIEM platform backend

use std::time::Duration;
use tokio::time;
use tracing::{info, error};
use serde::{Deserialize, Serialize};

mod api_client;
mod config;

use api_client::SIEMClient;
use config::AgentConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentInfo {
    agent_id: String,
    hostname: String,
    os_version: String,
    ip_address: String,
    agent_version: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    info!("TamsilCMS Sentinel EDR Agent v1.0.0");
    info!("Connecting to SIEM platform...");

    // Load configuration
    let config = AgentConfig::load("config.json")?;
    info!("Configuration loaded: SIEM endpoint = {}", config.siem_endpoint);

    // Initialize SIEM client
    let client = SIEMClient::new(&config.siem_endpoint, &config.api_key)?;
    
    // Register agent with SIEM
    let agent_info = get_agent_info()?;
    client.register_agent(&agent_info).await?;
    info!("Agent registered with SIEM successfully");

    // Start agent
    run_agent(config, client).await?;

    Ok(())
}

async fn run_agent(
    config: AgentConfig,
    client: SIEMClient,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting Sentinel EDR Agent");

    let mut interval = time::interval(Duration::from_secs(config.reporting_interval_secs));

    loop {
        interval.tick().await;

        // Collect events (ETW, process, file, network)
        let events = collect_events().await;

        // Send to SIEM backend
        if !events.is_empty() {
            match client.send_events(&events).await {
                Ok(_) => info!("Sent {} events to SIEM", events.len()),
                Err(e) => error!("Failed to send events: {}", e),
            }
        }

        // Check for commands from SIEM
        match client.get_commands().await {
            Ok(commands) => {
                for cmd in commands {
                    info!("Received command: {:?}", cmd);
                    // Execute command (scan, isolate, etc.)
                }
            }
            Err(e) => error!("Failed to get commands: {}", e),
        }
    }
}

async fn collect_events() -> Vec<serde_json::Value> {
    // Collect from:
    // - ETW (Event Tracing for Windows)
    // - Process creation/termination
    // - File operations
    // - Network connections
    // - Registry modifications
    Vec::new()
}

fn get_agent_info() -> Result<AgentInfo, Box<dyn std::error::Error>> {
    use std::process::Command;

    let hostname = hostname::get()?
        .to_string_lossy()
        .to_string();

    let os_version = if cfg!(target_os = "windows") {
        let output = Command::new("cmd")
            .args(&["/C", "ver"])
            .output()?;
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        "Unknown".to_string()
    };

    let ip_address = local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string());

    let agent_id = format!("{}-{}", hostname, uuid::Uuid::new_v4());

    Ok(AgentInfo {
        agent_id,
        hostname,
        os_version,
        ip_address,
        agent_version: "1.0.0".to_string(),
    })
}
