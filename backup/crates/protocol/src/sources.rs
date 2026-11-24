//! Backups of things that are not disks: Kubernetes clusters
//! (docs/design/kubernetes.md) and SaaS tenants (docs/design/saas.md). Their
//! credentials are sealed in the browser to the machine that runs the jobs;
//! the server stores and forwards only the sealed form.

use serde::{Deserialize, Serialize};

/// A cluster reached through its API server with a service account token.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct K8sCluster {
    /// Its name in images (machine `k8s:<name>`).
    pub name: String,
    /// https://host:6443
    pub api_server: String,
    /// The cluster's CA certificate (PEM).
    #[serde(default)]
    pub ca_pem: String,
    pub namespaces: Vec<String>,
    /// Container image of fenrir-backup for the pods that read and write
    /// volumes (empty: resources only, no volume data).
    #[serde(default)]
    pub volume_image: String,
}

/// A SaaS tenant: the service and the non-secret parts of the customer's app.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaasTenant {
    /// "m365", "google" or "salesforce".
    pub service: String,
    pub tenant: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub domain_url: String,
    #[serde(default)]
    pub admin: String,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub objects: Vec<String>,
    #[serde(default = "yes")]
    pub mail: bool,
    #[serde(default = "yes")]
    pub files: bool,
}

fn yes() -> bool {
    true
}

pub const SAAS_SERVICES: &[&str] = &["m365", "google", "salesforce"];

impl SaasTenant {
    pub fn validate(&self) -> Result<(), String> {
        if !SAAS_SERVICES.contains(&self.service.as_str()) {
            return Err("the service is m365, google or salesforce".into());
        }
        if self.tenant.trim().is_empty() {
            return Err("give the tenant (directory, domain or org name)".into());
        }
        match self.service.as_str() {
            "m365" if self.client_id.trim().is_empty() => Err("give the app's client ID".into()),
            "google" if self.admin.trim().is_empty() => {
                Err("give an administrator's address to list users as".into())
            }
            "salesforce"
                if !self.domain_url.starts_with("https://") || self.client_id.trim().is_empty() =>
            {
                Err("give the My Domain URL (https://...) and the consumer key".into())
            }
            _ => Ok(()),
        }
    }
}

impl K8sCluster {
    pub fn validate(&self) -> Result<(), String> {
        let ok_name = !self.name.is_empty()
            && self
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
        if !ok_name {
            return Err("the cluster name may have letters, digits, -, _ and .".into());
        }
        if !self.api_server.starts_with("https://") {
            return Err("the API server is an https:// address".into());
        }
        if self.namespaces.is_empty() {
            return Err("name the namespaces to back up".into());
        }
        Ok(())
    }
}
