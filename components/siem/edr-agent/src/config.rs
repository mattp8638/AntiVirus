//! Agent Configuration

use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub siem_endpoint: String,
    pub api_key: String,
    pub reporting_interval_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            siem_endpoint: "http://localhost:8000".to_string(),
            api_key: "your-api-key-here".to_string(),
            reporting_interval_secs: 10,
        }
    }
}

impl AgentConfig {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if let Ok(contents) = fs::read_to_string(path) {
            let config: AgentConfig = serde_json::from_str(&contents)?;
            Ok(config)
        } else {
            let config = Self::default();
            let json = serde_json::to_string_pretty(&config)?;
            fs::write(path, json)?;
            Ok(config)
        }
    }
}
