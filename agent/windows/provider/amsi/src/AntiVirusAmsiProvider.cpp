#include "AntiVirusAmsiProvider.h"

#include <windows.h>
#include <unknwn.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../../../service/include/AmsiScanEngine.h"
#include "../../../service/include/AgentConfig.h"
#include "../../../service/include/LocalStateStore.h"
#include "../../../service/include/LocalControlChannel.h"
#include "../../../service/include/StringUtils.h"
#include "../../../service/include/TelemetryQueueStore.h"

namespace antivirus::agent {
namespace {

const IID kIidAmsiStream = {0x3e47f2e5, 0x81d4, 0x4d3b, {0x89, 0x7f, 0x54, 0x50, 0x96, 0x77, 0x03, 0x73}};
const IID kIidAntimalwareProvider = {0xb2cabfe3, 0xfe04, 0x42b1, {0xa5, 0xdf, 0x08, 0xd4, 0x83, 0xd4, 0xd1, 0x25}};
const IID kIidAntimalwareProvider2 = {0x7c1e6570, 0x3f73, 0x4e0f, {0x8a, 0xd4, 0x98, 0xb9, 0x4c, 0xd3, 0x29, 0x0f}};
const IID kIidClassFactory = {0x00000001, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

HMODULE g_providerModuleHandle = nullptr;
std::atomic_ulong g_activeObjects{0};
std::atomic_ulong g_serverLocks{0};

std::wstring ProviderDisplayName() {
  return L"AntiVirus AMSI Provider";
}

std::wstring GuidToString(const GUID& guid) {
  wchar_t buffer[64] = {};
  const auto written = StringFromGUID2(guid, buffer, 64);
  return written > 1 ? std::wstring(buffer, written - 1) : std::wstring();
}

std::vector<unsigned char> ReadStreamContent(IAmsiStream* stream, std::size_t limitBytes = 1024 * 1024) {
  std::vector<unsigned char> result;
  if (stream == nullptr) {
    return result;
  }

  ULONGLONG contentSize = 0;
  ULONG returnedBytes = 0;
  if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(contentSize),
                                  reinterpret_cast<unsigned char*>(&contentSize), &returnedBytes))) {
    contentSize = 0;
  }

  const auto bytesToRead = static_cast<ULONG>(std::min<ULONGLONG>(contentSize, limitBytes));
  result.resize(bytesToRead);
  if (bytesToRead == 0) {
    return result;
  }

  ULONG readBytes = 0;
  if (FAILED(stream->Read(0, bytesToRead, result.data(), &readBytes))) {
    result.clear();
    return result;
  }

  result.resize(readBytes);
  return result;
}

std::wstring ReadWideAttribute(IAmsiStream* stream, AMSI_ATTRIBUTE attribute) {
  if (stream == nullptr) {
    return {};
  }

  std::vector<wchar_t> buffer(512, L'\0');
  ULONG returnedBytes = 0;
  const auto hr = stream->GetAttribute(attribute, static_cast<ULONG>(buffer.size() * sizeof(wchar_t)),
                                       reinterpret_cast<unsigned char*>(buffer.data()), &returnedBytes);
  if (FAILED(hr) || returnedBytes == 0) {
    return {};
  }

  const auto characters = std::min<std::size_t>(buffer.size(), returnedBytes / sizeof(wchar_t));
  return std::wstring(buffer.data(), characters == 0 ? 0 : characters - 1);
}

std::uint64_t ReadSessionAttribute(IAmsiStream* stream) {
  if (stream == nullptr) {
    return 0;
  }

  ULONGLONG sessionId = 0;
  ULONG returnedBytes = 0;
  if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_SESSION, sizeof(sessionId),
                                  reinterpret_cast<unsigned char*>(&sessionId), &returnedBytes))) {
    return 0;
  }

  return static_cast<std::uint64_t>(sessionId);
}

bool ReadQuietAttribute(IAmsiStream* stream) {
  if (stream == nullptr) {
    return false;
  }

  ULONG quiet = 0;
  ULONG returnedBytes = 0;
  if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_QUIET, sizeof(quiet), reinterpret_cast<unsigned char*>(&quiet),
                                  &returnedBytes))) {
    return false;
  }

  return quiet != 0;
}

// Hands one record to the service over the local control pipe. Never blocks a script for long:
// gives up after a short wait if the service is busy or not running.
void SubmitTelemetryToService(const TelemetryRecord& record) {
  if (WaitNamedPipeW(kFenrirLocalControlPipeName, 250) == FALSE) {
    return;
  }
  const HANDLE pipe = CreateFileW(kFenrirLocalControlPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                  SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) {
    return;
  }
  DWORD mode = PIPE_READMODE_MESSAGE;
  SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
  const std::string request = "{\"type\":\"amsi.telemetry.submit\",\"recordId\":\"" + EscapeJsonString(record.eventType) +
                              "\",\"targetPath\":\"" + EscapeJsonString(record.summary.substr(0, 1000)) +
                              "\",\"payloadJson\":\"" + EscapeJsonString(record.payloadJson) + "\"}";
  DWORD written = 0;
  if (request.size() < 60 * 1024 &&
      WriteFile(pipe, request.data(), static_cast<DWORD>(request.size()), &written, nullptr) != FALSE) {
    char reply[512];
    DWORD read = 0;
    ReadFile(pipe, reply, sizeof(reply), &read, nullptr);  // wait for the service to take it
  }
  CloseHandle(pipe);
}

bool WorthForwarding(const TelemetryRecord& record) {
  // Findings and blocks only: routine "allowed" decisions are not worth a pipe round trip per script.
  return record.eventType == L"scan.finding" || record.payloadJson.find(L"\"blocked\":true") != std::wstring::npos;
}

void QueueTelemetry(const AgentConfig& config, const std::vector<TelemetryRecord>& records) {
  if (records.empty()) {
    return;
  }

  // Same queue database the service uploads from. Elevated hosts can write it directly; ordinary
  // user processes cannot (it is protected), so their findings go through the service instead.
  try {
    TelemetryQueueStore queueStore(config.runtimeDatabasePath, config.telemetryQueuePath);
    queueStore.Append(records);
    return;
  } catch (...) {
  }
  for (const auto& record : records) {
    if (WorthForwarding(record)) {
      SubmitTelemetryToService(record);
    }
  }
}

class AntiVirusAmsiProvider final : public IAntimalwareProvider2 {
 public:
  explicit AntiVirusAmsiProvider(HMODULE moduleHandle) : refCount_(1), moduleHandle_(moduleHandle) { ++g_activeObjects; }

  ~AntiVirusAmsiProvider() { --g_activeObjects; }

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override {
    if (object == nullptr) {
      return E_POINTER;
    }

    *object = nullptr;
    if (InlineIsEqualGUID(riid, IID_IUnknown) || InlineIsEqualGUID(riid, kIidAntimalwareProvider) ||
        InlineIsEqualGUID(riid, kIidAntimalwareProvider2)) {
      *object = static_cast<IAntimalwareProvider2*>(this);
      AddRef();
      return S_OK;
    }

    return E_NOINTERFACE;
  }

  ULONG STDMETHODCALLTYPE AddRef() override { return ++refCount_; }

  ULONG STDMETHODCALLTYPE Release() override {
    const auto remaining = --refCount_;
    if (remaining == 0) {
      delete this;
    }
    return remaining;
  }

  HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) override {
    if (result == nullptr) {
      return E_POINTER;
    }

    *result = AMSI_RESULT_NOT_DETECTED;
    const AgentConfig config = LoadAgentConfigForModule(moduleHandle_);
    LocalStateStore stateStore(config.stateFilePath);
    const auto state = stateStore.LoadOrCreate();

    AmsiContentRequest request{
        .source = AmsiContentSource::Stream,
        .deviceId = state.deviceId,
        .appName = ReadWideAttribute(stream, AMSI_ATTRIBUTE_APP_NAME),
        .contentName = ReadWideAttribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME),
        .sessionId = ReadSessionAttribute(stream),
        .quiet = ReadQuietAttribute(stream),
        .content = ReadStreamContent(stream)};

    const auto outcome = InspectAmsiContent(request, state.policy, config);
    QueueTelemetry(config, outcome.telemetry);
    *result = outcome.blocked ? AMSI_RESULT_DETECTED : AMSI_RESULT_NOT_DETECTED;
    return S_OK;
  }

  void STDMETHODCALLTYPE CloseSession(ULONGLONG) override {}

  HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* displayName) override {
    if (displayName == nullptr) {
      return E_POINTER;
    }

    const auto value = ProviderDisplayName();
    const auto bytes = (value.size() + 1) * sizeof(wchar_t);
    auto* buffer = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
    if (buffer == nullptr) {
      return E_OUTOFMEMORY;
    }

    wcscpy_s(buffer, value.size() + 1, value.c_str());
    *displayName = buffer;
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE Notify(PVOID buffer, ULONG length, LPCWSTR contentName, LPCWSTR appName,
                                   AMSI_RESULT* result) override {
    if (result == nullptr) {
      return E_POINTER;
    }

    *result = AMSI_RESULT_NOT_DETECTED;
    const AgentConfig config = LoadAgentConfigForModule(moduleHandle_);
    LocalStateStore stateStore(config.stateFilePath);
    const auto state = stateStore.LoadOrCreate();

    std::vector<unsigned char> content(length, 0);
    if (buffer != nullptr && length != 0) {
      std::memcpy(content.data(), buffer, length);
    }

    AmsiContentRequest request{
        .source = AmsiContentSource::Notify,
        .deviceId = state.deviceId,
        .appName = appName == nullptr ? std::wstring() : std::wstring(appName),
        .contentName = contentName == nullptr ? std::wstring() : std::wstring(contentName),
        .sessionId = 0,
        .quiet = false,
        .content = std::move(content)};

    const auto outcome = InspectAmsiContent(request, state.policy, config);
    QueueTelemetry(config, outcome.telemetry);
    *result = outcome.blocked ? AMSI_RESULT_DETECTED : AMSI_RESULT_NOT_DETECTED;
    return S_OK;
  }

 private:
  std::atomic_ulong refCount_;
  HMODULE moduleHandle_{nullptr};
};

class AntiVirusAmsiProviderClassFactory final : public IClassFactory {
 public:
  explicit AntiVirusAmsiProviderClassFactory(HMODULE moduleHandle) : refCount_(1), moduleHandle_(moduleHandle) {}

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override {
    if (object == nullptr) {
      return E_POINTER;
    }

    *object = nullptr;
    if (InlineIsEqualGUID(riid, IID_IUnknown) || InlineIsEqualGUID(riid, kIidClassFactory)) {
      *object = static_cast<IClassFactory*>(this);
      AddRef();
      return S_OK;
    }

    return E_NOINTERFACE;
  }

  ULONG STDMETHODCALLTYPE AddRef() override { return ++refCount_; }

  ULONG STDMETHODCALLTYPE Release() override {
    const auto remaining = --refCount_;
    if (remaining == 0) {
      delete this;
    }
    return remaining;
  }

  HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID riid, void** object) override {
    if (outer != nullptr) {
      return CLASS_E_NOAGGREGATION;
    }

    auto* provider = new (std::nothrow) AntiVirusAmsiProvider(moduleHandle_);
    if (provider == nullptr) {
      return E_OUTOFMEMORY;
    }

    const auto hr = provider->QueryInterface(riid, object);
    provider->Release();
    return hr;
  }

  HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
    if (lock) {
      ++g_serverLocks;
    } else {
      --g_serverLocks;
    }
    return S_OK;
  }

 private:
  std::atomic_ulong refCount_;
  HMODULE moduleHandle_{nullptr};
};

}  // namespace

const CLSID CLSID_AntiVirusAmsiProvider = {0x7ee9f29e, 0x3e5b, 0x4d44, {0x9b, 0x48, 0x33, 0xa2, 0x5f, 0x0d, 0x2c, 0x61}};

HRESULT CreateAntiVirusAmsiProviderForTesting(HMODULE moduleHandle, IAntimalwareProvider2** provider) {
  if (provider == nullptr) {
    return E_POINTER;
  }

  *provider = new (std::nothrow) AntiVirusAmsiProvider(moduleHandle == nullptr ? g_providerModuleHandle : moduleHandle);
  return *provider == nullptr ? E_OUTOFMEMORY : S_OK;
}

HRESULT CreateAntiVirusAmsiProviderClassFactory(REFIID riid, void** object) {
  auto* factory = new (std::nothrow) AntiVirusAmsiProviderClassFactory(g_providerModuleHandle);
  if (factory == nullptr) {
    return E_OUTOFMEMORY;
  }

  const auto hr = factory->QueryInterface(riid, object);
  factory->Release();
  return hr;
}

void SetAntiVirusAmsiProviderModuleHandle(HMODULE moduleHandle) {
  g_providerModuleHandle = moduleHandle;
}

bool CanAntiVirusAmsiProviderUnloadNow() {
  return g_activeObjects.load() == 0 && g_serverLocks.load() == 0;
}

std::wstring AntiVirusAmsiProviderClsidString() {
  return GuidToString(CLSID_AntiVirusAmsiProvider);
}

}  // namespace antivirus::agent
