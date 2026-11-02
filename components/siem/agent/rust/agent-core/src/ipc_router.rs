use crate::command_router::{route_command, SignedCommand};
use crate::policy::PolicyBundle;
use crate::telemetry_router::{route_telemetry, TelemetryPayload};

pub fn route_proto_envelope(
    envelope: &crate::proto::agent_ipc::Envelope,
    policy: &PolicyBundle,
    now_unix_time_ms: u64,
) -> bool {
    match &envelope.payload {
        Some(crate::proto::agent_ipc::envelope::Payload::ExecutionCommand(command)) => {
            route_command(SignedCommand {
                command_id: command.command_id.clone(),
                signed_payload: command.signed_blob.clone(),
                action: command.action.clone(),
                arguments: command.arguments.clone(),
                not_before_unix_time_ms: command.not_before_unix_time_ms,
                not_after_unix_time_ms: command.not_after_unix_time_ms,
            }, policy, now_unix_time_ms)
        }
        Some(crate::proto::agent_ipc::envelope::Payload::SensorEvent(_)) => {
            route_telemetry(TelemetryPayload {
                stream: "sensor".to_string(),
                payload_bytes: prost::Message::encoded_len(envelope),
                event_count: 1,
                checksum_sha256: None,
            }, policy)
        }
        Some(crate::proto::agent_ipc::envelope::Payload::ExecutionResult(_))
        | Some(crate::proto::agent_ipc::envelope::Payload::EvidencePackage(_))
        | Some(crate::proto::agent_ipc::envelope::Payload::ComplianceAssertion(_))
        | Some(crate::proto::agent_ipc::envelope::Payload::HealthHeartbeat(_)) => {
            route_telemetry(TelemetryPayload {
                stream: "agent".to_string(),
                payload_bytes: prost::Message::encoded_len(envelope),
                event_count: 1,
                checksum_sha256: None,
            }, policy)
        }
        None => false,
    }
}
