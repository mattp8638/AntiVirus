#pragma once

#include <stdexcept>
#include <string>
#include <vector>

#include "AgentState.h"
#include "PolicySnapshot.h"
#include "TelemetryRecord.h"
#include "ThreatIntelligence.h"

namespace antivirus::agent {

struct EnrollmentResult {
  std::wstring deviceId;
  std::wstring issuedAt;
  std::wstring commandChannelUrl;
  PolicySnapshot policy;
};

struct HeartbeatResult {
  std::wstring receivedAt;
  std::wstring effectivePolicyRevision;
  int commandsPending{0};
};

struct PolicyCheckInResult {
  std::wstring retrievedAt;
  bool changed{false};
  PolicySnapshot policy;
};

struct TelemetryBatchResult {
  std::wstring receivedAt;
  int accepted{0};
  int totalStored{0};
};

struct RemoteCommand {
  std::wstring commandId;
  std::wstring type;
  std::wstring issuedBy;
  std::wstring createdAt;
  std::wstring updatedAt;
  std::wstring targetPath;
  std::wstring recordId;
  std::wstring payloadJson;
};

struct CommandPollResult {
  std::wstring polledAt;
  std::vector<RemoteCommand> items;
};

struct ControlPlaneUpdateOffer {
  std::wstring packageId;
  std::wstring packageType;
  std::wstring targetVersion;
  std::wstring manifestPath;
  bool mandatory{false};
};

struct UpdateCheckResult {
  std::wstring checkedAt;
  std::vector<ControlPlaneUpdateOffer> items;
};

struct SignatureRuleDelta {
  std::wstring scope;
  std::wstring code;
  std::wstring message;
  std::wstring tacticId;
  std::wstring techniqueId;
  int score{0};
  std::vector<std::wstring> patterns;
};

struct SignatureDeltaResult {
  std::wstring checkedAt;
  std::wstring signatureVersion;
  std::wstring yaraVersion;
  std::vector<SignatureRuleDelta> signatures;
  std::vector<std::wstring> yaraRules;
  std::vector<ThreatIntelRecord> threatIntelRecords;
};

class DeviceIdentityRejectedError final : public std::runtime_error {
 public:
  explicit DeviceIdentityRejectedError(const std::string& message) : std::runtime_error(message) {}
};

struct MlModelManifest {
  std::wstring version;
  std::wstring sha256;
  long long size{0};
};

class ControlPlaneClient {
 public:
  explicit ControlPlaneClient(std::wstring baseUrl);

  // enrollmentToken comes from the console (Deploy agents); without one the device lands in Unassigned.
  EnrollmentResult Enroll(const AgentState& state, const std::wstring& enrollmentToken = {}) const;
  // metricsJson: the RMM health object (CPU, memory, disks...) or empty.
  HeartbeatResult SendHeartbeat(const AgentState& state, const std::string& metricsJson = "") const;
  // 'Request support' from the agent window; returns the ticket number. bodyJson: {summary, details, user, contact}.
  std::wstring SubmitSupportRequest(const AgentState& state, const std::string& bodyJson) const;
  // ws(s)://.../api/v1/devices/<id>/realtime and the device key that authenticates it.
  std::wstring RealtimeUrl(const AgentState& state) const;
  static std::wstring DeviceApiKey(const AgentState& state);
  PolicyCheckInResult CheckInPolicy(const AgentState& state) const;
  TelemetryBatchResult SendTelemetryBatch(const AgentState& state, const std::vector<TelemetryRecord>& records) const;
  // types: optional comma-separated command types to fetch (servers without the filter return everything).
  CommandPollResult PollPendingCommands(const AgentState& state, int limit = 10, const std::wstring& types = L"") const;
  // Uploads a forensic/support bundle for a command (before it is completed); returns the artifact id.
  std::wstring UploadCommandArtifact(const AgentState& state, const std::wstring& commandId, const std::wstring& filename,
                                     const std::string& data) const;
  void CompleteCommand(const AgentState& state, const std::wstring& commandId, const std::wstring& status,
                       const std::wstring& resultJson) const;
  UpdateCheckResult CheckForUpdates(const AgentState& state, const std::wstring& signaturesVersion = L"",
                                    const std::wstring& channel = L"") const;
  SignatureDeltaResult FetchSignatureDelta(const std::wstring& currentSignatureVersion = L"",
                                           const std::wstring& currentYaraVersion = L"",
                                           const std::wstring& signatureFeedToken = L"") const;
  // Static ML model: manifest {version, sha256, size} and the FGBT binary.
  MlModelManifest FetchMlModelManifest(const AgentState& state) const;
  std::vector<unsigned char> DownloadMlModel(const AgentState& state) const;

 private:
  std::wstring baseUrl_;
};

}  // namespace antivirus::agent
