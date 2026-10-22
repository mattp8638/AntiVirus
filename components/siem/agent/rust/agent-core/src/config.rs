use std::env;

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct CoreConfig {
    pub asset_id: String,
    pub agent_id: String,
    pub ipc_pipe_name: String,
    pub max_payload_bytes: usize,
}

impl CoreConfig {
    pub fn placeholder() -> Self {
        Self {
            asset_id: "asset-placeholder".to_string(),
            agent_id: "agent-core".to_string(),
            ipc_pipe_name: r"\\.\pipe\tamsil_agent_pipe".to_string(),
            max_payload_bytes: 1024 * 1024,
        }
    }

    pub fn from_env() -> Self {
        let placeholder = Self::placeholder();
        let asset_id = env::var("AGENT_ASSET_ID").unwrap_or(placeholder.asset_id);
        let agent_id = env::var("AGENT_ID").unwrap_or(placeholder.agent_id);
        let ipc_pipe_name = env::var("AGENT_IPC_PIPE").unwrap_or(placeholder.ipc_pipe_name);
        let max_payload_bytes = env::var("AGENT_MAX_PAYLOAD_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(placeholder.max_payload_bytes);

        Self {
            asset_id,
            agent_id,
            ipc_pipe_name,
            max_payload_bytes,
        }
    }
}
