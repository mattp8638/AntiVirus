//! SIEM Backend API Client

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct SIEMClient {
    client: Client,
    endpoint: String,
    api_key: String,
}

impl SIEMClient {
    pub fn new(endpoint: &str, api_key: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            endpoint: endpoint.to_string(),
            api_key: api_key.to_string(),
        })
    }

    pub async fn register_agent(
        &self,
        agent_info: &super::AgentInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/v1/edr/agents/register", self.endpoint);
        
        let response = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(agent_info)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Registration failed: {}", response.status()).into())
        }
    }

    pub async fn send_events(
        &self,
        events: &[serde_json::Value],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/api/v1/edr/events", self.endpoint);
        
        let response = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(events)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Failed to send events: {}", response.status()).into())
        }
    }

    pub async fn get_commands(
        &self,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v1/edr/commands", self.endpoint);
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;

        if response.status().is_success() {
            let commands = response.json().await?;
            Ok(commands)
        } else {
            Ok(Vec::new())
        }
    }
}
