#[derive(Debug, Clone)]
pub struct EnvelopeMeta {
    pub schema_version: u32,
    pub payload_bytes: usize,
}

pub fn validate_schema_version(schema_version: u32, expected: u32) -> bool {
    schema_version == expected
}

pub fn validate_payload_size(payload_bytes: usize, max_payload_bytes: usize) -> bool {
    payload_bytes <= max_payload_bytes
}

pub fn validate_proto_envelope(
    envelope: &crate::proto::agent_ipc::Envelope,
    expected_version: u32,
    max_payload_bytes: usize,
) -> bool {
    let schema_ok = validate_schema_version(envelope.schema_version, expected_version);
    let payload_ok = envelope.payload.is_some();
    let encoded_len = prost::Message::encoded_len(envelope);
    let size_ok = validate_payload_size(encoded_len, max_payload_bytes);
    schema_ok && payload_ok && size_ok
}

#[cfg(test)]
mod tests {
    use super::{validate_payload_size, validate_proto_envelope, validate_schema_version};

    #[test]
    fn validates_schema_version() {
        assert!(validate_schema_version(1, 1));
        assert!(!validate_schema_version(2, 1));
    }

    #[test]
    fn validates_payload_size() {
        assert!(validate_payload_size(10, 100));
        assert!(!validate_payload_size(101, 100));
    }

    #[test]
    fn validates_proto_envelope() {
        let envelope = crate::proto::agent_ipc::Envelope {
            schema_version: 1,
            asset_id: "asset".to_string(),
            agent_id: "agent".to_string(),
            unix_time_ms: 1,
            payload: Some(crate::proto::agent_ipc::envelope::Payload::HealthHeartbeat(
                crate::proto::agent_ipc::HealthHeartbeat {
                    service_name: "agent-core".to_string(),
                    unix_time_ms: 1,
                },
            )),
        };

        assert!(validate_proto_envelope(&envelope, 1, 1024));
        assert!(!validate_proto_envelope(&envelope, 2, 1024));
        assert!(!validate_proto_envelope(&envelope, 1, 1));
    }
}
