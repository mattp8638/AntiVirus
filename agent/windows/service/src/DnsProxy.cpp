#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winhttp.h>

#include "DnsProxy.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace antivirus::agent::dnsproxy {
namespace {

constexpr int kWorkers = 8;
constexpr std::size_t kQueueLimit = 512;
constexpr long long kCloudBackoffSeconds = 15;
constexpr long long kNetworkRefreshSeconds = 60;

long long NowSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string Narrow(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), size, nullptr, nullptr);
  return out;
}

struct WinsockScope {
  WinsockScope() { ok = WSAStartup(MAKEWORD(2, 2), &data) == 0; }
  ~WinsockScope() { if (ok) WSACleanup(); }
  WSADATA data{};
  bool ok{false};
};

bool ParseAddress(const std::string& address, unsigned short port, sockaddr_storage* out, int* length) {
  std::memset(out, 0, sizeof(*out));
  auto* v4 = reinterpret_cast<sockaddr_in*>(out);
  if (inet_pton(AF_INET, address.c_str(), &v4->sin_addr) == 1) {
    v4->sin_family = AF_INET;
    v4->sin_port = htons(port);
    *length = sizeof(sockaddr_in);
    return true;
  }
  auto* v6 = reinterpret_cast<sockaddr_in6*>(out);
  if (inet_pton(AF_INET6, address.c_str(), &v6->sin6_addr) == 1) {
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(port);
    *length = sizeof(sockaddr_in6);
    return true;
  }
  return false;
}

void SetTimeouts(SOCKET s, DWORD ms) {
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
}

bool RecvAll(SOCKET s, unsigned char* buffer, int length) {
  int done = 0;
  while (done < length) {
    const int n = recv(s, reinterpret_cast<char*>(buffer + done), length - done, 0);
    if (n <= 0) return false;
    done += n;
  }
  return true;
}

bool SendAll(SOCKET s, const unsigned char* buffer, int length) {
  int done = 0;
  while (done < length) {
    const int n = send(s, reinterpret_cast<const char*>(buffer + done), length - done, 0);
    if (n <= 0) return false;
    done += n;
  }
  return true;
}

// One query to one DNS server over UDP (or TCP), with the reply's ID checked.
bool Exchange(const sockaddr_storage& server, int length, const Bytes& query, bool tcp, Bytes* reply) {
  const SOCKET s = socket(server.ss_family, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP);
  if (s == INVALID_SOCKET) return false;
  SetTimeouts(s, tcp ? 4000 : 2000);
  bool ok = false;
  Bytes buffer(65535);
  if (tcp) {
    if (connect(s, reinterpret_cast<const sockaddr*>(&server), length) == 0) {
      unsigned char size[2]{static_cast<unsigned char>(query.size() >> 8), static_cast<unsigned char>(query.size() & 0xFF)};
      unsigned char back[2]{};
      if (SendAll(s, size, 2) && SendAll(s, query.data(), static_cast<int>(query.size())) && RecvAll(s, back, 2)) {
        const int n = (back[0] << 8) | back[1];
        if (n >= 12 && RecvAll(s, buffer.data(), n)) {
          buffer.resize(static_cast<std::size_t>(n));
          ok = true;
        }
      }
    }
  } else if (sendto(s, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0,
                    reinterpret_cast<const sockaddr*>(&server), length) != SOCKET_ERROR) {
    const int n = recv(s, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0);
    if (n >= 12) {
      buffer.resize(static_cast<std::size_t>(n));
      ok = true;
    }
  }
  closesocket(s);
  if (!ok || buffer[0] != query[0] || buffer[1] != query[1]) return false;
  *reply = std::move(buffer);
  return true;
}

void AddSuffix(std::vector<std::string>* out, const std::wstring& value) {
  std::wstring item;
  for (const wchar_t c : value + L",") {
    if (c == L',' || c == L' ' || c == L';') {
      const auto clean = Normalise(Narrow(item));
      if (!clean.empty() && std::find(out->begin(), out->end(), clean) == out->end()) out->push_back(clean);
      item.clear();
    } else {
      item += c;
    }
  }
}

std::wstring RegistryString(const wchar_t* key, const wchar_t* name) {
  wchar_t buffer[2048]{};
  DWORD size = sizeof(buffer);
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key, name, RRF_RT_REG_SZ, nullptr, buffer, &size) != ERROR_SUCCESS) return {};
  return buffer;
}

}  // namespace

Proxy::Proxy(Options options) : options_(std::move(options)) {
  options_.cacheMinutes = std::clamp(options_.cacheMinutes, 1, 1440);
}

Proxy::~Proxy() { Stop(); }

bool Proxy::Start(std::string* error) {
  if (started_) return true;
  URL_COMPONENTS parts{};
  parts.dwStructSize = sizeof(parts);
  parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = static_cast<DWORD>(-1);
  if (options_.dohUrl.empty() || !WinHttpCrackUrl(options_.dohUrl.c_str(), 0, 0, &parts)) {
    if (error) *error = "the device has no valid DNS-over-HTTPS address yet";
    return false;
  }
  dohHost_.assign(parts.lpszHostName, parts.dwHostNameLength);
  dohPath_.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
  if (parts.dwExtraInfoLength > 0) dohPath_.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
  dohPort_ = parts.nPort;
  dohSecure_ = parts.nScheme == INTERNET_SCHEME_HTTPS;
  // The Fenrir server's own name is always resolved by the network's DNS: through the proxy it would loop.
  options_.localDomains.push_back(Normalise(Narrow(dohHost_)));

  static WinsockScope winsock;
  if (!winsock.ok) {
    if (error) *error = "Winsock could not start";
    return false;
  }
  session_ = WinHttpOpen(L"FenrirDnsProxy/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (session_ == nullptr) {
    session_ = WinHttpOpen(L"FenrirDnsProxy/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  }
  if (session_ == nullptr) {
    if (error) *error = "WinHTTP could not start (error " + std::to_string(GetLastError()) + ")";
    return false;
  }
  WinHttpSetTimeouts(session_, 3000, 3000, 4000, 4000);
  connection_ = WinHttpConnect(session_, dohHost_.c_str(), dohPort_, 0);
  if (connection_ == nullptr) {
    if (error) *error = "WinHTTP could not prepare the connection (error " + std::to_string(GetLastError()) + ")";
    Stop();
    return false;
  }

  sockaddr_storage address{};
  int length = 0;
  if (!ParseAddress(options_.listenAddress, options_.port, &address, &length)) {
    if (error) *error = "bad listen address";
    Stop();
    return false;
  }
  const BOOL exclusive = TRUE;
  const SOCKET udp = socket(address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
  const SOCKET tcp = socket(address.ss_family, SOCK_STREAM, IPPROTO_TCP);
  udp_ = udp;
  tcp_ = tcp;
  if (udp == INVALID_SOCKET || tcp == INVALID_SOCKET) {
    if (error) *error = "cannot create sockets (error " + std::to_string(WSAGetLastError()) + ")";
    Stop();
    return false;
  }
  setsockopt(udp, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
  setsockopt(tcp, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
  // A client that went away makes the next recvfrom fail with WSAECONNRESET on Windows; turn that off.
  DWORD noReset = FALSE, returned = 0;
  WSAIoctl(udp, _WSAIOW(IOC_VENDOR, 12), &noReset, sizeof(noReset), nullptr, 0, &returned, nullptr, nullptr);
  if (bind(udp, reinterpret_cast<sockaddr*>(&address), length) == SOCKET_ERROR ||
      bind(tcp, reinterpret_cast<sockaddr*>(&address), length) == SOCKET_ERROR || listen(tcp, 64) == SOCKET_ERROR) {
    if (error) {
      *error = options_.listenAddress + ":" + std::to_string(options_.port) + " is not available (error " +
               std::to_string(WSAGetLastError()) + "); another DNS service may be using it";
    }
    Stop();
    return false;
  }
  stopping_ = false;
  started_ = true;
  for (int i = 0; i < kWorkers; ++i) workers_.emplace_back([this] { WorkerLoop(); });
  udpThread_ = std::thread([this] { UdpLoop(); });
  tcpThread_ = std::thread([this] { TcpLoop(); });
  return true;
}

void Proxy::Stop() {
  stopping_ = true;
  if (udp_ != ~std::uintptr_t{0}) closesocket(static_cast<SOCKET>(udp_));
  if (tcp_ != ~std::uintptr_t{0}) closesocket(static_cast<SOCKET>(tcp_));
  udp_ = tcp_ = ~std::uintptr_t{0};
  {
    std::lock_guard lock(clientsMutex_);
    for (const auto client : tcpClients_) shutdown(static_cast<SOCKET>(client), SD_BOTH);
  }
  queueReady_.notify_all();
  if (udpThread_.joinable()) udpThread_.join();
  if (tcpThread_.joinable()) tcpThread_.join();
  for (auto& worker : workers_) {
    if (worker.joinable()) worker.join();
  }
  workers_.clear();
  {
    std::lock_guard lock(queueMutex_);
    queue_.clear();
  }
  if (connection_ != nullptr) WinHttpCloseHandle(connection_);
  if (session_ != nullptr) WinHttpCloseHandle(session_);
  connection_ = session_ = nullptr;
  started_ = false;
}

bool Proxy::Enqueue(std::function<void()> task) {
  {
    std::lock_guard lock(queueMutex_);
    if (stopping_ || queue_.size() >= kQueueLimit) return false;
    queue_.push_back(std::move(task));
  }
  queueReady_.notify_one();
  return true;
}

void Proxy::WorkerLoop() {
  for (;;) {
    std::function<void()> task;
    {
      std::unique_lock lock(queueMutex_);
      queueReady_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
      if (stopping_) return;
      task = std::move(queue_.front());
      queue_.pop_front();
    }
    task();
  }
}

void Proxy::UdpLoop() {
  const auto udp = static_cast<SOCKET>(udp_);
  std::vector<unsigned char> buffer(4096);
  while (!stopping_) {
    sockaddr_storage from{};
    int fromLength = sizeof(from);
    const int n = recvfrom(udp, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                           reinterpret_cast<sockaddr*>(&from), &fromLength);
    if (n == SOCKET_ERROR) {
      if (stopping_) return;
      continue;
    }
    if (n < 12) continue;
    Bytes query(buffer.begin(), buffer.begin() + n);
    Enqueue([this, udp, query = std::move(query), from, fromLength] {
      const auto reply = Resolve(query, false);
      if (!reply.empty() && !stopping_) {
        sendto(udp, reinterpret_cast<const char*>(reply.data()), static_cast<int>(reply.size()), 0,
               reinterpret_cast<const sockaddr*>(&from), fromLength);
      }
    });
  }
}

void Proxy::TcpLoop() {
  const auto tcp = static_cast<SOCKET>(tcp_);
  while (!stopping_) {
    const SOCKET client = accept(tcp, nullptr, nullptr);
    if (client == INVALID_SOCKET) {
      if (stopping_) return;
      continue;
    }
    SetTimeouts(client, 10000);
    {
      std::lock_guard lock(clientsMutex_);
      tcpClients_.push_back(client);
    }
    if (!Enqueue([this, client] { ServeTcp(client); })) {
      std::lock_guard lock(clientsMutex_);
      tcpClients_.erase(std::remove(tcpClients_.begin(), tcpClients_.end(), client), tcpClients_.end());
      closesocket(client);
    }
  }
}

void Proxy::ServeTcp(std::uintptr_t handle) {
  const auto client = static_cast<SOCKET>(handle);
  for (int served = 0; served < 32 && !stopping_; ++served) {
    unsigned char size[2]{};
    if (!RecvAll(client, size, 2)) break;
    const int length = (size[0] << 8) | size[1];
    if (length < 12) break;
    Bytes query(static_cast<std::size_t>(length));
    if (!RecvAll(client, query.data(), length)) break;
    const auto reply = Resolve(query, true);
    if (reply.empty()) break;
    const unsigned char out[2]{static_cast<unsigned char>(reply.size() >> 8), static_cast<unsigned char>(reply.size() & 0xFF)};
    if (!SendAll(client, out, 2) || !SendAll(client, reply.data(), static_cast<int>(reply.size()))) break;
  }
  {
    std::lock_guard lock(clientsMutex_);
    tcpClients_.erase(std::remove(tcpClients_.begin(), tcpClients_.end(), handle), tcpClients_.end());
  }
  closesocket(client);
}

Bytes Proxy::Resolve(const Bytes& query, bool overTcp) {
  const auto finish = [&](Bytes reply) { return overTcp ? reply : TruncateForUdp(reply, query); };
  const auto count = [this](long long Stats::*field) {
    std::lock_guard lock(statsMutex_);
    ++(stats_.*field);
  };
  const auto question = ParseQuestion(query);
  if (!question) return ErrorReply(query, kFormErr);
  count(&Stats::queries);
  const auto& name = question->name;
  if (name == kHealthName) return ErrorReply(query, kNxDomain);

  Bytes reply;
  if (IsLocal(name)) {
    if (AskNetwork(query, overTcp, &reply)) {
      count(&Stats::network);
      return finish(reply);
    }
    count(&Stats::failures);
    return ErrorReply(query, kServFail);
  }
  if (const auto reason = verdicts_.Blocked(name)) {
    count(&Stats::cachedBlocks);
    ReportCachedBlock(name, *reason);
    return BlockedReply(query, *question);
  }
  if (const auto cached = answers_.Get(name, question->type)) return finish(WithId(*cached, query));

  CloudAnswer answer;
  if (NowSeconds() >= cloudDownUntil_ && AskCloud(query, &answer)) {
    count(&Stats::cloud);
    if (answer.action == "block") {
      verdicts_.Block(name, answer.reason.empty() ? "blocked by policy" : answer.reason, std::chrono::minutes(options_.cacheMinutes));
    } else {
      verdicts_.Allow(name);
      answers_.Put(name, question->type, answer.reply, MinAnswerTtl(answer.reply));
    }
    return finish(WithId(answer.reply, query));
  }
  if (options_.failClosed) {
    count(&Stats::refused);
    return ErrorReply(query, kRefused);
  }
  if (AskNetwork(query, overTcp, &reply)) {
    count(&Stats::fallback);
    return finish(reply);
  }
  count(&Stats::failures);
  return ErrorReply(query, kServFail);
}

bool Proxy::AskCloud(const Bytes& query, CloudAnswer* answer) {
  if (connection_ == nullptr) return false;
  const auto request = WinHttpOpenRequest(connection_, L"POST", dohPath_.c_str(), nullptr, WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES, dohSecure_ ? WINHTTP_FLAG_SECURE : 0);
  if (request == nullptr) return false;
  std::wstring headers = L"Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n";
  if (!options_.apiKey.empty()) headers += L"X-Device-Api-Key: " + options_.apiKey + L"\r\n";
  bool ok = false;
  if (WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1), const_cast<unsigned char*>(query.data()),
                         static_cast<DWORD>(query.size()), static_cast<DWORD>(query.size()), 0) &&
      WinHttpReceiveResponse(request, nullptr)) {
    DWORD status = 0, size = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                        WINHTTP_NO_HEADER_INDEX);
    if (status == 200) {
      Bytes body;
      for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available) || available == 0) break;
        const auto offset = body.size();
        if (offset + available > 65535) break;
        body.resize(offset + available);
        DWORD read = 0;
        if (!WinHttpReadData(request, body.data() + offset, available, &read)) break;
        body.resize(offset + read);
      }
      const auto header = [&](const wchar_t* name) {
        wchar_t value[256]{};
        DWORD length = sizeof(value);
        return WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, name, value, &length, WINHTTP_NO_HEADER_INDEX) ? Narrow(value)
                                                                                                                 : std::string();
      };
      if (body.size() >= 12 && body[0] == query[0] && body[1] == query[1]) {
        answer->reply = std::move(body);
        answer->action = header(L"X-Fenrir-Dns-Action");
        answer->reason = header(L"X-Fenrir-Dns-Reason");
        ok = true;
      }
    }
  }
  WinHttpCloseHandle(request);
  if (!ok) cloudDownUntil_ = NowSeconds() + kCloudBackoffSeconds;  // don't make every lookup wait on a dead link
  return ok;
}

bool Proxy::AskNetwork(const Bytes& query, bool overTcp, Bytes* reply) {
  const auto info = Network();
  int tried = 0;
  for (const auto& raw : info.servers) {
    if (++tried > 3) break;
    sockaddr_storage server{};
    std::memcpy(&server, raw.data(), std::min(raw.size(), sizeof(server)));
    const int length = server.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    if (Exchange(server, length, query, false, reply)) {
      if (overTcp && IsTruncated(*reply)) {
        Bytes full;
        if (Exchange(server, length, query, true, &full)) *reply = std::move(full);
      }
      return true;
    }
  }
  return false;
}

bool Proxy::IsLocal(const std::string& name) {
  if (IsLocalOnlyName(name) || IsPrivateReverseName(name) || MatchesSuffix(name, options_.localDomains)) return true;
  return MatchesSuffix(name, Network().suffixes);
}

Proxy::NetworkInfo Proxy::Network() {
  std::lock_guard lock(networkMutex_);
  if (network_.at != 0 && NowSeconds() - network_.at < kNetworkRefreshSeconds) return network_;
  NetworkInfo info;
  info.at = NowSeconds();
  ULONG size = 32 * 1024;
  std::vector<unsigned char> buffer;
  ULONG result = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
    buffer.resize(size);
    result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  }
  std::vector<std::vector<unsigned char>> withGateway, others;
  if (result == NO_ERROR) {
    sockaddr_storage self{};
    int selfLength = 0;
    ParseAddress(options_.listenAddress, 53, &self, &selfLength);
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter != nullptr; adapter = adapter->Next) {
      if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
      if (adapter->DnsSuffix != nullptr) AddSuffix(&info.suffixes, adapter->DnsSuffix);
      auto& target = adapter->FirstGatewayAddress != nullptr ? withGateway : others;
      for (auto* dns = adapter->FirstDnsServerAddress; dns != nullptr; dns = dns->Next) {
        const auto* address = dns->Address.lpSockaddr;
        if (address == nullptr) continue;
        sockaddr_storage server{};
        std::memcpy(&server, address, std::min<std::size_t>(dns->Address.iSockaddrLength, sizeof(server)));
        if (server.ss_family == AF_INET) {
          auto* v4 = reinterpret_cast<sockaddr_in*>(&server);
          if (v4->sin_addr.s_addr == reinterpret_cast<sockaddr_in*>(&self)->sin_addr.s_addr) continue;
          v4->sin_port = htons(53);
        } else if (server.ss_family == AF_INET6) {
          auto* v6 = reinterpret_cast<sockaddr_in6*>(&server);
          // fec0:0:0:ffff::1-3 are Windows' placeholders when no IPv6 DNS server is configured.
          if (v6->sin6_addr.s6_addr[0] == 0xfe && (v6->sin6_addr.s6_addr[1] & 0xc0) == 0xc0) continue;
          v6->sin6_port = htons(53);
        } else {
          continue;
        }
        std::vector<unsigned char> raw(reinterpret_cast<unsigned char*>(&server), reinterpret_cast<unsigned char*>(&server) + sizeof(server));
        if (std::find(withGateway.begin(), withGateway.end(), raw) == withGateway.end() &&
            std::find(others.begin(), others.end(), raw) == others.end()) {
          target.push_back(raw);
        }
      }
    }
  }
  info.servers = withGateway;
  info.servers.insert(info.servers.end(), others.begin(), others.end());
  wchar_t domain[256]{};
  DWORD domainLength = 256;
  if (GetComputerNameExW(ComputerNameDnsDomain, domain, &domainLength)) AddSuffix(&info.suffixes, domain);
  const wchar_t* tcpip = L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
  AddSuffix(&info.suffixes, RegistryString(tcpip, L"SearchList"));
  AddSuffix(&info.suffixes, RegistryString(tcpip, L"Domain"));
  AddSuffix(&info.suffixes, RegistryString(tcpip, L"NV Domain"));
  AddSuffix(&info.suffixes, RegistryString(L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"SearchList"));
  network_ = info;
  return info;
}

void Proxy::ReportCachedBlock(const std::string& domain, const std::string& reason) {
  if (!options_.onCachedBlock) return;
  {
    std::lock_guard lock(reportMutex_);
    const auto now = NowSeconds();
    auto& last = reported_[domain];
    if (last != 0 && now - last < 600) return;
    last = now;
    if (reported_.size() > 5000) reported_.clear();
  }
  options_.onCachedBlock(domain, reason);
}

Stats Proxy::Snapshot() const {
  std::lock_guard lock(statsMutex_);
  return stats_;
}

bool Probe(const std::string& address, unsigned short port, int timeoutMs) {
  static WinsockScope winsock;
  if (!winsock.ok) return false;
  sockaddr_storage server{};
  int length = 0;
  if (!ParseAddress(address, port, &server, &length)) return false;
  Bytes query{0x46, 0x4E, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
  std::string name = kHealthName;
  std::size_t start = 0;
  while (start < name.size()) {
    auto dot = name.find('.', start);
    if (dot == std::string::npos) dot = name.size();
    query.push_back(static_cast<unsigned char>(dot - start));
    query.insert(query.end(), name.begin() + static_cast<std::ptrdiff_t>(start), name.begin() + static_cast<std::ptrdiff_t>(dot));
    start = dot + 1;
  }
  query.insert(query.end(), {0, 0, 1, 0, 1});
  const SOCKET s = socket(server.ss_family, SOCK_DGRAM, IPPROTO_UDP);
  if (s == INVALID_SOCKET) return false;
  SetTimeouts(s, static_cast<DWORD>(timeoutMs));
  bool ok = false;
  if (sendto(s, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0, reinterpret_cast<sockaddr*>(&server), length) !=
      SOCKET_ERROR) {
    unsigned char reply[512]{};
    const int n = recv(s, reinterpret_cast<char*>(reply), sizeof(reply), 0);
    ok = n >= 12 && reply[0] == 0x46 && reply[1] == 0x4E && (reply[2] & 0x80) != 0;
  }
  closesocket(s);
  return ok;
}

bool IsDomainControllerOrDnsServer() {
  using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOEXW*);
  if (const auto ntdll = GetModuleHandleW(L"ntdll.dll")) {
    if (const auto getVersion = reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")))) {
      OSVERSIONINFOEXW version{};
      version.dwOSVersionInfoSize = sizeof(version);
      if (getVersion(&version) == 0 && version.wProductType == VER_NT_DOMAIN_CONTROLLER) return true;
    }
  }
  bool dnsServer = false;
  if (const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)) {
    if (const auto service = OpenServiceW(manager, L"DNS", SERVICE_QUERY_STATUS)) {
      SERVICE_STATUS status{};
      dnsServer = QueryServiceStatus(service, &status) && status.dwCurrentState != SERVICE_STOPPED;
      CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
  }
  return dnsServer;
}

}  // namespace antivirus::agent::dnsproxy
