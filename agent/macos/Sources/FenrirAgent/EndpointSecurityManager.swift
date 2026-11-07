import Foundation
import EndpointSecurity
import FenrirAuditToken

/// Pure ES sensor: intercepts kernel events and delegates all logic to RealtimeProtectionBroker.
class EndpointSecurityManager {
    private var client: OpaquePointer?
    private let broker: RealtimeProtectionBroker

    init(broker: RealtimeProtectionBroker) {
        self.broker = broker
    }

    func start() -> Bool {
        let res = es_new_client(&client) { [broker] client, message in
            Self.handleMessage(client: client, message: message, broker: broker)
        }

        guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client = client else {
            print("[ESManager] Failed to create ES client. Did you grant the entitlement and Full Disk Access?")
            return false
        }

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN
        ]

        guard es_subscribe(client, events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            es_delete_client(client)
            self.client = nil
            print("[ESManager] Failed to subscribe to ES events.")
            return false
        }

        print("[ESManager] Successfully subscribed to Endpoint Security events.")
        return true
    }

    func stop() {
        if let client = client {
            es_unsubscribe_all(client)
            es_delete_client(client)
            self.client = nil
        }
    }

    // MARK: - Private

    private static func handleMessage(client: OpaquePointer, message: UnsafePointer<es_message_t>,
                                      broker: RealtimeProtectionBroker) {
        let event = message.pointee
        guard event.action_type == ES_ACTION_TYPE_AUTH else { return }
        switch event.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            let target = event.event.exec.target.pointee
            let path = String(cString: target.executable.pointee.path.data)
            let decision = broker.handleExec(executablePath: path, pid: fenrir_audit_pid(target.audit_token))
            es_respond_auth_result(client, message, decision == .allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)
        case ES_EVENT_TYPE_AUTH_OPEN:
            let open = event.event.open
            let path = String(cString: open.file.pointee.path.data)
            let pid = fenrir_audit_pid(event.process.pointee.audit_token)
            let decision = broker.handleFileOpen(filePath: path, pid: pid, isWrite: (open.fflag & FWRITE) != 0)
            let flags = decision == .allow ? UInt32(bitPattern: open.fflag) : 0
            es_respond_flags_result(client, message, flags, false)
        default:
            es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }
}
