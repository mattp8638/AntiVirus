import Foundation
import EndpointSecurity

enum ProtectionVerdict: Equatable {
    case allow
    case block(reason: String)
}

class RealtimeProtectionBroker {
    private let config: AgentConfig
    private let scanEngine: ScanEngine
    private let processInventory: ProcessInventory
    private let telemetryQueue: TelemetryQueueStore

    /// Per-process write extension diversity tracker for ransomware heuristics.
    private var fileExtensionWriteCounts: [pid_t: [String: Int]] = [:]
    private let heuristicLock = NSLock()

    init(config: AgentConfig, scanEngine: ScanEngine, processInventory: ProcessInventory, telemetryQueue: TelemetryQueueStore) {
        self.config = config
        self.scanEngine = scanEngine
        self.processInventory = processInventory
        self.telemetryQueue = telemetryQueue
    }

    // MARK: - Event Handling

    func handleExec(executablePath: String, pid: pid_t) -> ProtectionVerdict {
        // Maintain inventory
        processInventory.add(ProcessRecord(pid: pid, executablePath: executablePath, startTime: Date()))

        // YARA scan
        let result = scanEngine.scanFile(at: executablePath)
        if result.matched {
            let reason = "YARA match: \(result.matchedRules.joined(separator: ", "))"
            print("[Broker] Blocking exec \(executablePath): \(reason)")
            emitTelemetry(eventType: "ProcessStart", payload: [
                "eventType": "ProcessStart",
                "processName": (executablePath as NSString).lastPathComponent,
                "pid": pid,
                "commandLine": executablePath,
                "blocked": true,
                "blockReason": reason
            ])
            return .block(reason: reason)
        }

        emitTelemetry(eventType: "ProcessStart", payload: [
            "eventType": "ProcessStart",
            "processName": (executablePath as NSString).lastPathComponent,
            "pid": pid,
            "commandLine": executablePath
        ])
        return .allow
    }

    func handleFileOpen(filePath: String, pid: pid_t, isWrite: Bool) -> ProtectionVerdict {
        // Persistence mechanism protection
        let persistencePaths = [
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "/System/Library/LaunchDaemons"
        ]
        let inPersistencePath = persistencePaths.contains { filePath.hasPrefix($0) }

        if isWrite && inPersistencePath {
            let processPath = processInventory.get(pid: pid)?.executablePath ?? "unknown"
            let reason = "Write to macOS persistence path: \(filePath)"
            print("[Broker] BLOCKING \(reason) by PID \(pid) (\(processPath))")
            emitTelemetry(eventType: "FileWrite", payload: [
                "eventType": "FileWrite",
                "processName": (processPath as NSString).lastPathComponent,
                "pid": pid,
                "filePath": filePath,
                "blocked": true,
                "blockReason": reason
            ])
            return .block(reason: reason)
        }

        // Ransomware heuristic
        if isWrite {
            heuristicLock.lock()
            if fileExtensionWriteCounts[pid] == nil { fileExtensionWriteCounts[pid] = [:] }
            let isRansomware = scanEngine.checkRansomwareHeuristic(
                pid: pid,
                filePath: filePath,
                knownWrites: &fileExtensionWriteCounts[pid]!
            )
            heuristicLock.unlock()

            if isRansomware {
                let reason = "Ransomware heuristic triggered: too many unique file extension writes"
                print("[Broker] BLOCKING PID \(pid): \(reason)")
                emitTelemetry(eventType: "FileWrite", payload: [
                    "eventType": "FileWrite",
                    "processName": processInventory.get(pid: pid)?.executablePath ?? "unknown",
                    "pid": pid,
                    "filePath": filePath,
                    "blocked": true,
                    "blockReason": reason
                ])
                return .block(reason: reason)
            }

            emitTelemetry(eventType: "FileWrite", payload: [
                "eventType": "FileWrite",
                "processName": ((processInventory.get(pid: pid)?.executablePath ?? "unknown") as NSString).lastPathComponent,
                "pid": pid,
                "filePath": filePath
            ])
        }

        return .allow
    }

    // MARK: - Telemetry

    private func emitTelemetry(eventType: String, payload: [String: Any]) {
        let envelope: [String: Any] = [
            "eventId": UUID().uuidString,
            "deviceId": config.deviceId,
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "eventType": eventType,
            "payload": payload
        ]
        telemetryQueue.enqueue(envelope)
    }

    func flushAll() {
        telemetryQueue.flush()
    }
}
