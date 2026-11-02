use std::sync::{Arc, Mutex};

use crate::ipc_validation::{validate_payload_size, validate_proto_envelope, validate_schema_version, EnvelopeMeta};
use crate::ipc_router::route_proto_envelope;
use crate::policy::PolicyBundle;
use crate::rate_limit::RateLimiter;

pub const IPC_SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub struct IpcServer {
    pub pipe_name: String,
    pub max_payload_bytes: usize,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    pub policy: Arc<PolicyBundle>,
}

impl IpcServer {
    pub fn new(
        pipe_name: String,
        max_payload_bytes: usize,
        rate_limiter: RateLimiter,
        policy: PolicyBundle,
    ) -> Self {
        Self {
            pipe_name,
            max_payload_bytes,
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            policy: Arc::new(policy),
        }
    }

    pub fn validate_envelope(&self, envelope: &EnvelopeMeta) -> bool {
        if !validate_schema_version(envelope.schema_version, IPC_SCHEMA_VERSION) {
            return false;
        }

        if !validate_payload_size(envelope.payload_bytes, self.max_payload_bytes) {
            return false;
        }

        let mut limiter = self.rate_limiter.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        limiter.allow()
    }

    pub fn start(&self) {
        // TODO: Bind to named pipe, accept only authorised clients, and decode protobuf messages.
        // TODO: Validate schema version, size, and required fields before routing.
    }

    pub fn validate_proto(&self, envelope: &crate::proto::agent_ipc::Envelope) -> bool {
        validate_proto_envelope(envelope, IPC_SCHEMA_VERSION, self.max_payload_bytes)
    }

    pub fn handle_proto(&self, envelope: &crate::proto::agent_ipc::Envelope) -> bool {
        if !self.validate_proto(envelope) {
            return false;
        }
        let now_unix_time_ms = crate::time::unix_time_ms();
        route_proto_envelope(envelope, &self.policy, now_unix_time_ms)
    }
}
