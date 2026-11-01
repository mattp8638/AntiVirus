#pragma once

#include <string>

namespace antivirus::agent {

// Connection details the cloud releases for one amt.wsman command (never stored on disk).
struct AmtCredential {
  std::wstring host;
  int port{16992};  // 16992 HTTP, 16993 TLS
  bool tlsInsecure{false};
  std::wstring username;
  std::wstring password;
};

// Runs the cloud's amt.wsman command: POSTs each {"requests":[{"name","body"}]} WS-Management body to the Intel AMT
// engine with HTTP Digest authentication and returns {"responses":[{"name","status","body"}|{"name","status":0,"error"}]}.
// Only the AMT ports 16992/16993 are used, so the credential cannot be sent to another service.
std::string RunAmtWsman(const std::string& payloadUtf8, const AmtCredential& credential);

}  // namespace antivirus::agent
