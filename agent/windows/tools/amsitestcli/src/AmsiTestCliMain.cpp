#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "../../../provider/amsi/include/AmsiInterop.h"
#include "../../../provider/amsi/include/AntiVirusAmsiProvider.h"

namespace {

const IID kIidAmsiStream = {0x3e47f2e5, 0x81d4, 0x4d3b, {0x89, 0x7f, 0x54, 0x50, 0x96, 0x77, 0x03, 0x73}};

struct CliOptions {
  bool notifyMode{false};
  bool json{false};
  bool helpRequested{false};
  std::wstring appName{L"PowerShell"};
  std::wstring contentName{};
  std::wstring text{};
  std::filesystem::path path{};
};

void PrintUsage() {
  std::wcout << L"Usage: antivirus-amsitestcli.exe [--notify|--stream] [--json] [--app <name>] [--content-name <name>] [--text <content>|--path <file>]" << std::endl;
}

bool ParseOptions(int argc, wchar_t* argv[], CliOptions& options) {
  for (int index = 1; index < argc; ++index) {
    const std::wstring argument = argv[index];

    if (argument == L"--help") {
      options.helpRequested = true;
      PrintUsage();
      return false;
    }
    if (argument == L"--json") {
      options.json = true;
      continue;
    }
    if (argument == L"--notify") {
      options.notifyMode = true;
      continue;
    }
    if (argument == L"--stream") {
      options.notifyMode = false;
      continue;
    }
    if (argument == L"--app" && index + 1 < argc) {
      options.appName = argv[++index];
      continue;
    }
    if (argument == L"--content-name" && index + 1 < argc) {
      options.contentName = argv[++index];
      continue;
    }
    if (argument == L"--text" && index + 1 < argc) {
      options.text = argv[++index];
      continue;
    }
    if (argument == L"--path" && index + 1 < argc) {
      options.path = argv[++index];
      continue;
    }

    std::wcerr << L"Unknown option: " << argument << std::endl;
    return false;
  }

  if (options.text.empty() && options.path.empty()) {
    std::wcerr << L"Either --text or --path is required." << std::endl;
    return false;
  }

  return true;
}

std::vector<unsigned char> LoadContent(const CliOptions& options) {
  if (!options.text.empty()) {
    const auto bytes = reinterpret_cast<const unsigned char*>(options.text.data());
    return std::vector<unsigned char>(bytes, bytes + (options.text.size() * sizeof(wchar_t)));
  }

  std::ifstream input(options.path, std::ios::binary);
  return std::vector<unsigned char>(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

class FakeAmsiStream final : public IAmsiStream {
 public:
  FakeAmsiStream(std::wstring appName, std::wstring contentName, std::vector<unsigned char> content)
      : refCount_(1), appName_(std::move(appName)), contentName_(std::move(contentName)), content_(std::move(content)) {}

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) override {
    if (object == nullptr) {
      return E_POINTER;
    }

    *object = nullptr;
    if (InlineIsEqualGUID(riid, IID_IUnknown) ||
        InlineIsEqualGUID(riid, kIidAmsiStream)) {
      *object = static_cast<IAmsiStream*>(this);
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

  HRESULT STDMETHODCALLTYPE GetAttribute(AMSI_ATTRIBUTE attribute, ULONG dataSize, unsigned char* data,
                                         ULONG* retData) override {
    if (retData == nullptr) {
      return E_POINTER;
    }

    *retData = 0;
    switch (attribute) {
      case AMSI_ATTRIBUTE_APP_NAME: {
        const auto bytes = static_cast<ULONG>((appName_.size() + 1) * sizeof(wchar_t));
        *retData = bytes;
        if (data == nullptr || dataSize < bytes) {
          return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
        std::memcpy(data, appName_.c_str(), bytes);
        return S_OK;
      }
      case AMSI_ATTRIBUTE_CONTENT_NAME: {
        const auto bytes = static_cast<ULONG>((contentName_.size() + 1) * sizeof(wchar_t));
        *retData = bytes;
        if (data == nullptr || dataSize < bytes) {
          return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
        std::memcpy(data, contentName_.c_str(), bytes);
        return S_OK;
      }
      case AMSI_ATTRIBUTE_CONTENT_SIZE: {
        ULONGLONG value = content_.size();
        *retData = sizeof(value);
        if (data == nullptr || dataSize < sizeof(value)) {
          return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
        std::memcpy(data, &value, sizeof(value));
        return S_OK;
      }
      case AMSI_ATTRIBUTE_SESSION: {
        ULONGLONG value = 77;
        *retData = sizeof(value);
        if (data == nullptr || dataSize < sizeof(value)) {
          return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
        std::memcpy(data, &value, sizeof(value));
        return S_OK;
      }
      default:
        return E_NOTIMPL;
    }
  }

  HRESULT STDMETHODCALLTYPE Read(ULONGLONG position, ULONG size, unsigned char* buffer, ULONG* readSize) override {
    if (buffer == nullptr || readSize == nullptr) {
      return E_POINTER;
    }

    if (position >= content_.size()) {
      *readSize = 0;
      return S_OK;
    }

    const auto remaining = content_.size() - static_cast<std::size_t>(position);
    const auto bytesToRead = static_cast<ULONG>(std::min<std::size_t>(remaining, size));
    std::memcpy(buffer, content_.data() + position, bytesToRead);
    *readSize = bytesToRead;
    return S_OK;
  }

 private:
  std::atomic_ulong refCount_;
  std::wstring appName_;
  std::wstring contentName_;
  std::vector<unsigned char> content_;
};

void PrintResult(bool json, AMSI_RESULT result, const std::wstring& appName, const std::wstring& contentName) {
  const auto blocked = AmsiResultIsMalware(result);
  if (json) {
    std::wcout << L"{\"appName\":\"" << appName << L"\",\"contentName\":\"" << contentName
               << L"\",\"result\":" << result << L",\"blocked\":" << (blocked ? L"true" : L"false") << L"}"
               << std::endl;
    return;
  }

  std::wcout << L"AMSI result " << result << (blocked ? L" (blocked)" : L" (allowed)") << L" for " << appName
             << L" -> " << contentName << std::endl;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  CliOptions options;
  if (!ParseOptions(argc, argv, options)) {
    return options.helpRequested ? 0 : 1;
  }

  const auto content = LoadContent(options);
  const auto contentName = options.contentName.empty()
                               ? (options.path.empty() ? std::wstring(L"memory://cli") : options.path.wstring())
                               : options.contentName;

  IAntimalwareProvider2* provider = nullptr;
  if (FAILED(antivirus::agent::CreateAntiVirusAmsiProviderForTesting(GetModuleHandleW(nullptr), &provider)) ||
      provider == nullptr) {
    std::wcerr << L"Unable to create the AMSI provider instance." << std::endl;
    return 1;
  }

  AMSI_RESULT result = AMSI_RESULT_NOT_DETECTED;
  HRESULT hr = S_OK;
  if (options.notifyMode) {
    hr = provider->Notify(content.empty() ? nullptr : const_cast<unsigned char*>(content.data()),
                          static_cast<ULONG>(content.size()), contentName.c_str(), options.appName.c_str(), &result);
  } else {
    auto* stream = new FakeAmsiStream(options.appName, contentName, content);
    hr = provider->Scan(stream, &result);
    stream->Release();
  }

  provider->Release();

  if (FAILED(hr)) {
    std::wcerr << L"AMSI provider invocation failed with HRESULT 0x" << std::hex << hr << std::endl;
    return 1;
  }

  PrintResult(options.json, result, options.appName, contentName);
  return AmsiResultIsMalware(result) ? 2 : 0;
}
