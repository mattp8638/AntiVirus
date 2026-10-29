#include <windows.h>
#include <winhttp.h>

#include "AmtWsman.h"

#include <stdexcept>
#include <vector>

#include "ExtendedPolicy.h"
#include "StringUtils.h"

namespace antivirus::agent {
namespace {

constexpr std::size_t kMaxRequests = 10;
constexpr std::size_t kMaxBody = 256 * 1024;

std::string JsonEscape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 16);
  for (const char ch : value) {
    switch (ch) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(ch) < 0x20) {
          char escaped[8];
          wsprintfA(escaped, "\\u%04x", static_cast<unsigned char>(ch));
          out += escaped;
        } else {
          out += ch;
        }
    }
  }
  return out;
}

struct Handle {
  HINTERNET h{nullptr};
  ~Handle() {
    if (h) WinHttpCloseHandle(h);
  }
};

std::string ReadBody(HINTERNET request) {
  std::string body;
  for (;;) {
    DWORD available = 0;
    if (!WinHttpQueryDataAvailable(request, &available) || available == 0) break;
    std::vector<char> chunk(available);
    DWORD read = 0;
    if (!WinHttpReadData(request, chunk.data(), available, &read) || read == 0) break;
    if (body.size() < kMaxBody) body.append(chunk.data(), std::min<std::size_t>(read, kMaxBody - body.size()));
  }
  return body;
}

DWORD Status(HINTERNET request) {
  DWORD status = 0, size = sizeof(status);
  WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                      WINHTTP_NO_HEADER_INDEX);
  return status;
}

// One WS-Management call; on a 401 challenge it answers with Digest credentials and sends again.
bool Post(HINTERNET connection, const AmtCredential& credential, const std::string& body, DWORD* status, std::string* response,
          std::string* error) {
  Handle request{WinHttpOpenRequest(connection, L"POST", L"/wsman", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                    credential.port == 16993 ? WINHTTP_FLAG_SECURE : 0)};
  if (!request.h) {
    *error = "could not create the request (" + std::to_string(GetLastError()) + ")";
    return false;
  }
  if (credential.port == 16993 && credential.tlsInsecure) {
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(request.h, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
  }
  const wchar_t* headers = L"Content-Type: application/soap+xml;charset=UTF-8\r\n";
  for (int attempt = 0; attempt < 2; ++attempt) {
    if (!WinHttpSendRequest(request.h, headers, static_cast<DWORD>(-1L), const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
                            static_cast<DWORD>(body.size()), 0) ||
        !WinHttpReceiveResponse(request.h, nullptr)) {
      *error = "AMT did not answer (" + std::to_string(GetLastError()) + ")";
      return false;
    }
    *status = Status(request.h);
    *response = ReadBody(request.h);
    if (*status != 401 || attempt == 1) break;
    DWORD supported = 0, first = 0, target = 0;
    if (!WinHttpQueryAuthSchemes(request.h, &supported, &first, &target) || !(supported & WINHTTP_AUTH_SCHEME_DIGEST) ||
        !WinHttpSetCredentials(request.h, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_DIGEST, credential.username.c_str(),
                               credential.password.c_str(), nullptr)) {
      break;  // reported as 401
    }
  }
  return true;
}

}  // namespace

std::string RunAmtWsman(const std::string& payloadUtf8, const AmtCredential& credential) {
  if (credential.port != 16992 && credential.port != 16993) {
    throw std::runtime_error("Intel AMT listens on 16992 or 16993 only");
  }
  const auto parsed = json::Parse(payloadUtf8);
  const auto* requests = parsed ? parsed->Get("requests") : nullptr;
  const auto* list = requests ? std::get_if<json::Array>(&requests->v) : nullptr;
  if (list == nullptr || list->empty() || list->size() > kMaxRequests) {
    throw std::runtime_error("amt.wsman needs between 1 and 10 requests");
  }
  Handle session{WinHttpOpen(L"Fenrir-AMT/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
  if (!session.h) throw std::runtime_error("WinHTTP could not start");
  WinHttpSetTimeouts(session.h, 10000, 10000, 20000, 20000);
  Handle connection{WinHttpConnect(session.h, credential.host.c_str(), static_cast<INTERNET_PORT>(credential.port), 0)};
  if (!connection.h) throw std::runtime_error("Could not open a connection to the AMT address");
  std::string out = "{\"responses\":[";
  bool firstItem = true;
  for (const auto& item : *list) {
    const auto name = item.Get("name") ? item.Get("name")->String().value_or("") : "";
    const auto body = item.Get("body") ? item.Get("body")->String().value_or("") : "";
    DWORD status = 0;
    std::string response, error;
    const bool ok = Post(connection.h, credential, body, &status, &response, &error);
    out += std::string(firstItem ? "" : ",") + "{\"name\":\"" + JsonEscape(name) + "\",";
    firstItem = false;
    if (!ok) {
      out += "\"status\":0,\"error\":\"" + JsonEscape(error) + "\"}";
      break;
    }
    out += "\"status\":" + std::to_string(status) + ",\"body\":\"" + JsonEscape(response) + "\"}";
  }
  return out + "]}";
}

}  // namespace antivirus::agent
