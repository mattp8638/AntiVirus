#pragma once

#include <filesystem>
#include <string>

#include "AgentConfig.h"

namespace antivirus::agent {

struct HardeningStatus {
  bool registryConfigured{false};
  bool uninstallProtectionEnabled{false};
  bool runtimePathsProtected{false};
  bool runtimePathsTrusted{false};
  bool installPathProtected{false};
  bool serviceControlProtected{false};
  bool elamDriverPresent{false};
  bool elamCertificateInstalled{false};
  bool launchProtectedConfigured{false};
  std::wstring uninstallTokenHash;
  std::wstring elamDriverPath;
  std::wstring statusMessage;
};

class HardeningManager {
 public:
  HardeningManager(const AgentConfig& config, std::filesystem::path installRoot);

  bool ApplyPostInstallHardening(const std::wstring& uninstallToken, std::wstring* errorMessage = nullptr) const;
  // locked = true: administrators can start, query and re-permission the service but not stop,
  // reconfigure or delete it (services.msc, Stop-Service, sc stop are refused). Fenrir's own
  // --install/--repair/--upgrade/--uninstall unlock it first (uninstall needs the uninstall token).
  bool ApplyServiceControlProtection(const std::wstring& serviceName, SC_HANDLE serviceHandle = nullptr,
                                     std::wstring* errorMessage = nullptr, bool locked = true) const;
  bool ApplyProtectedServiceRegistration(const std::wstring& serviceName, SC_HANDLE serviceHandle,
                                         const std::filesystem::path& elamDriverPath,
                                         std::wstring* errorMessage = nullptr) const;
  // Policy (modules.tamper): serviceLocked = tamper.enabled && protectServiceAndFiles;
  // uninstallTokenRequired = tamper.enabled && uninstallRequiresToken.
  bool ApplyTamperPolicy(bool serviceLocked, bool uninstallTokenRequired, std::wstring* errorMessage = nullptr) const;
  // edr.credentialProtection: LSA protection (RunAsPPL, needs a restart) and no cleartext WDigest credentials.
  // Only values Fenrir set are reverted when the setting is turned off. rebootRequired is set when LSA
  // protection changes.
  bool ApplyCredentialHardening(bool enable, bool* rebootRequired, std::wstring* errorMessage = nullptr) const;
  bool ValidateUninstallAuthorization(const std::wstring& uninstallToken, std::wstring* errorMessage = nullptr) const;
  HardeningStatus QueryStatus(const std::wstring& serviceName = L"FenrirAgent") const;

 private:
  AgentConfig config_;
  std::filesystem::path installRoot_;
};

}  // namespace antivirus::agent
