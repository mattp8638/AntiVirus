#include "ProcessEtwSensor.h"

#include <windows.h>
#include <evntrace.h>
#include <sddl.h>
#include <tdh.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../../../service/include/StringUtils.h"

namespace antivirus::agent {
namespace {

constexpr GUID kKernelProcessProviderGuid = {
    0x22fb2cd6,
    0x0e7b,
    0x422b,
    {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16},
};

constexpr ULONGLONG kKernelProcessKeyword = 0x10ULL;
constexpr ULONGLONG kKernelImageKeyword = 0x40ULL;
constexpr ULONGLONG kKernelThreadKeyword = 0x20ULL;
constexpr USHORT kThreadStartEventId = 3;
constexpr USHORT kProcessStartEventId = 1;
constexpr USHORT kProcessStopEventId = 2;
constexpr USHORT kImageLoadEventId = 5;
constexpr USHORT kInTypeUnicodeString = 1;
constexpr USHORT kInTypeAnsiString = 2;
constexpr USHORT kInTypeInt8 = 3;
constexpr USHORT kInTypeUint8 = 4;
constexpr USHORT kInTypeInt16 = 5;
constexpr USHORT kInTypeUint16 = 6;
constexpr USHORT kInTypeInt32 = 7;
constexpr USHORT kInTypeUint32 = 8;
constexpr USHORT kInTypeInt64 = 9;
constexpr USHORT kInTypeUint64 = 10;
constexpr USHORT kInTypeBoolean = 13;
constexpr USHORT kInTypePointer = 16;
constexpr USHORT kInTypeFileTime = 17;
constexpr USHORT kInTypeSid = 19;
constexpr USHORT kInTypeHexInt32 = 20;
constexpr USHORT kInTypeHexInt64 = 21;

struct EtwPropertyValue {
  USHORT inType{0};
  USHORT outType{0};
  std::wstring value;
};

using PropertyMap = std::unordered_map<std::wstring, EtwPropertyValue>;

struct ProcessRuntimeContext {
  std::wstring imagePath;
  std::wstring userSid;
  std::wstring integrityLevel;
  std::wstring sessionId;
  std::wstring signer;
};

std::wstring ToLowerCopy(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
  return value;
}

std::wstring TrimTrailingNulls(std::wstring value) {
  while (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }

  return value;
}

template <typename T>
std::optional<T> ReadLittleEndian(const BYTE* data, const ULONG dataSize) {
  if (data == nullptr || dataSize < sizeof(T)) {
    return std::nullopt;
  }

  T value{};
  std::memcpy(&value, data, sizeof(T));
  return value;
}

std::wstring BytesToHex(const BYTE* data, const ULONG dataSize) {
  std::wstringstream stream;
  stream << std::hex << std::setfill(L'0');

  for (ULONG index = 0; index < dataSize; ++index) {
    stream << std::setw(2) << static_cast<unsigned int>(data[index]);
  }

  return stream.str();
}

std::wstring FileTimeToUtcString(const ULONGLONG rawValue) {
  if (rawValue == 0) {
    return {};
  }

  FILETIME fileTime{};
  fileTime.dwLowDateTime = static_cast<DWORD>(rawValue & 0xffffffffULL);
  fileTime.dwHighDateTime = static_cast<DWORD>((rawValue >> 32U) & 0xffffffffULL);

  SYSTEMTIME systemTime{};
  if (FileTimeToSystemTime(&fileTime, &systemTime) == FALSE) {
    return {};
  }

  wchar_t buffer[32] = {};
  swprintf(buffer, 32, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", systemTime.wYear, systemTime.wMonth,
           systemTime.wDay, systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds);
  return std::wstring(buffer);
}

std::wstring SidToString(PSID sid) {
  if (sid == nullptr || IsValidSid(sid) == FALSE) {
    return {};
  }

  LPWSTR stringSid = nullptr;
  if (ConvertSidToStringSidW(sid, &stringSid) == FALSE || stringSid == nullptr) {
    return {};
  }

  const std::wstring result(stringSid);
  LocalFree(stringSid);
  return result;
}

std::wstring FormatIntegrityLevel(const DWORD integrityRid) {
  if (integrityRid >= SECURITY_MANDATORY_SYSTEM_RID) {
    return L"system";
  }

  if (integrityRid >= SECURITY_MANDATORY_HIGH_RID) {
    return L"high";
  }

  if (integrityRid >= SECURITY_MANDATORY_MEDIUM_RID) {
    return L"medium";
  }

  if (integrityRid >= SECURITY_MANDATORY_LOW_RID) {
    return L"low";
  }

  return L"untrusted";
}

std::wstring QuerySignerSubject(const std::wstring& path) {
  if (path.empty()) {
    return {};
  }

  HCERTSTORE certStore = nullptr;
  HCRYPTMSG cryptMessage = nullptr;
  PCCERT_CONTEXT certificate = nullptr;
  DWORD encoding = 0;
  DWORD contentType = 0;
  DWORD formatType = 0;

  if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                       CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType, &formatType, &certStore,
                       &cryptMessage, nullptr) == FALSE) {
    return {};
  }

  DWORD signerInfoSize = 0;
  if (CryptMsgGetParam(cryptMessage, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) == FALSE) {
    if (cryptMessage != nullptr) {
      CryptMsgClose(cryptMessage);
    }
    if (certStore != nullptr) {
      CertCloseStore(certStore, 0);
    }
    return {};
  }

  std::vector<BYTE> signerInfoBuffer(signerInfoSize);
  if (CryptMsgGetParam(cryptMessage, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuffer.data(), &signerInfoSize) == FALSE) {
    if (cryptMessage != nullptr) {
      CryptMsgClose(cryptMessage);
    }
    if (certStore != nullptr) {
      CertCloseStore(certStore, 0);
    }
    return {};
  }

  const auto* signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(signerInfoBuffer.data());
  CERT_INFO certificateInfo{};
  certificateInfo.Issuer = signerInfo->Issuer;
  certificateInfo.SerialNumber = signerInfo->SerialNumber;

  certificate = CertFindCertificateInStore(certStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                           CERT_FIND_SUBJECT_CERT, &certificateInfo, nullptr);

  std::wstring subject;
  if (certificate != nullptr) {
    const auto subjectLength =
        CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (subjectLength > 1) {
      subject.resize(subjectLength - 1);
      CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject.data(), subjectLength);
    }
  }

  if (certificate != nullptr) {
    CertFreeCertificateContext(certificate);
  }
  if (cryptMessage != nullptr) {
    CryptMsgClose(cryptMessage);
  }
  if (certStore != nullptr) {
    CertCloseStore(certStore, 0);
  }

  return subject;
}

std::wstring QueryProcessImagePath(const DWORD pid) {
  if (pid == 0) {
    return {};
  }

  const HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return {};
  }

  std::wstring pathBuffer(4096, L'\0');
  DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
  if (QueryFullProcessImageNameW(processHandle, 0, pathBuffer.data(), &pathLength) == FALSE) {
    CloseHandle(processHandle);
    return {};
  }

  CloseHandle(processHandle);
  pathBuffer.resize(pathLength);
  return pathBuffer;
}

ProcessRuntimeContext QueryProcessRuntimeContext(const DWORD pid) {
  ProcessRuntimeContext context{};
  if (pid == 0) {
    return context;
  }

  context.imagePath = QueryProcessImagePath(pid);
  if (!context.imagePath.empty()) {
    context.signer = QuerySignerSubject(context.imagePath);
  }

  DWORD sessionId = 0;
  if (ProcessIdToSessionId(pid, &sessionId) != FALSE) {
    context.sessionId = std::to_wstring(sessionId);
  }

  const HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (processHandle == nullptr) {
    return context;
  }

  HANDLE tokenHandle = nullptr;
  if (OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) != FALSE && tokenHandle != nullptr) {
    DWORD tokenSize = 0;
    GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &tokenSize);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && tokenSize > 0) {
      std::vector<BYTE> tokenUserBuffer(tokenSize);
      if (GetTokenInformation(tokenHandle, TokenUser, tokenUserBuffer.data(), tokenSize, &tokenSize) != FALSE) {
        const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenUserBuffer.data());
        context.userSid = SidToString(tokenUser->User.Sid);
      }
    }

    tokenSize = 0;
    GetTokenInformation(tokenHandle, TokenIntegrityLevel, nullptr, 0, &tokenSize);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && tokenSize > 0) {
      std::vector<BYTE> integrityBuffer(tokenSize);
      if (GetTokenInformation(tokenHandle, TokenIntegrityLevel, integrityBuffer.data(), tokenSize, &tokenSize) != FALSE) {
        const auto* tokenLabel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrityBuffer.data());
        auto* sid = tokenLabel->Label.Sid;
        if (sid != nullptr) {
          const auto subAuthorityCount = *GetSidSubAuthorityCount(sid);
          if (subAuthorityCount > 0) {
            const auto integrityRid = *GetSidSubAuthority(sid, subAuthorityCount - 1);
            context.integrityLevel = FormatIntegrityLevel(integrityRid);
          }
        }
      }
    }

    CloseHandle(tokenHandle);
  }

  CloseHandle(processHandle);
  return context;
}

std::wstring FormatEtwPropertyValue(const BYTE* data, const ULONG dataSize, const USHORT inType) {
  if (data == nullptr || dataSize == 0) {
    return {};
  }

  switch (inType) {
    case kInTypeUnicodeString: {
      const auto* value = reinterpret_cast<const wchar_t*>(data);
      return TrimTrailingNulls(std::wstring(value, dataSize / sizeof(wchar_t)));
    }
    case kInTypeAnsiString: {
      const auto* value = reinterpret_cast<const char*>(data);
      std::string ansi(value, value + dataSize);
      while (!ansi.empty() && ansi.back() == '\0') {
        ansi.pop_back();
      }
      return Utf8ToWide(ansi);
    }
    case kInTypeInt8:
      return std::to_wstring(static_cast<long long>(*reinterpret_cast<const int8_t*>(data)));
    case kInTypeUint8:
      return std::to_wstring(static_cast<unsigned long long>(*reinterpret_cast<const uint8_t*>(data)));
    case kInTypeInt16:
      return std::to_wstring(static_cast<long long>(*reinterpret_cast<const int16_t*>(data)));
    case kInTypeUint16:
      return std::to_wstring(static_cast<unsigned long long>(*reinterpret_cast<const uint16_t*>(data)));
    case kInTypeInt32:
      return std::to_wstring(static_cast<long long>(*reinterpret_cast<const int32_t*>(data)));
    case kInTypeUint32:
      return std::to_wstring(static_cast<unsigned long long>(*reinterpret_cast<const uint32_t*>(data)));
    case kInTypeInt64:
      return std::to_wstring(static_cast<long long>(*reinterpret_cast<const int64_t*>(data)));
    case kInTypeUint64:
      return std::to_wstring(static_cast<unsigned long long>(*reinterpret_cast<const uint64_t*>(data)));
    case kInTypeHexInt32: {
      std::wstringstream stream;
      stream << L"0x" << std::hex << static_cast<unsigned long long>(*reinterpret_cast<const uint32_t*>(data));
      return stream.str();
    }
    case kInTypeHexInt64:
    case kInTypePointer: {
      std::wstringstream stream;
      stream << L"0x" << std::hex << static_cast<unsigned long long>(*reinterpret_cast<const uint64_t*>(data));
      return stream.str();
    }
    case kInTypeBoolean:
      return (*reinterpret_cast<const uint32_t*>(data) == 0U) ? L"false" : L"true";
    case kInTypeFileTime: {
      const auto fileTimeValue = ReadLittleEndian<ULONGLONG>(data, dataSize);
      return fileTimeValue.has_value() ? FileTimeToUtcString(*fileTimeValue) : std::wstring{};
    }
    case kInTypeSid:
      return SidToString(reinterpret_cast<PSID>(const_cast<BYTE*>(data)));
    default:
      return BytesToHex(data, dataSize);
  }
}

std::vector<std::wstring> ExtractEtwPropertyNames(const EVENT_RECORD& eventRecord) {
  auto* mutableRecord = const_cast<EVENT_RECORD*>(&eventRecord);
  ULONG bufferSize = 0;
  if (TdhGetEventInformation(mutableRecord, 0, nullptr, nullptr, &bufferSize) != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0) {
    return {};
  }
  std::vector<BYTE> buffer(bufferSize);
  auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());
  if (TdhGetEventInformation(mutableRecord, 0, nullptr, info, &bufferSize) != ERROR_SUCCESS) {
    return {};
  }
  std::vector<std::wstring> names;
  for (ULONG index = 0; index < info->TopLevelPropertyCount; ++index) {
    names.emplace_back(reinterpret_cast<const wchar_t*>(buffer.data() + info->EventPropertyInfoArray[index].NameOffset));
  }
  return names;
}

PropertyMap ExtractEtwProperties(const EVENT_RECORD& eventRecord) {
  auto* mutableRecord = const_cast<EVENT_RECORD*>(&eventRecord);
  ULONG bufferSize = 0;
  auto status = TdhGetEventInformation(mutableRecord, 0, nullptr, nullptr, &bufferSize);
  if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0) {
    return {};
  }

  std::vector<BYTE> eventInfoBuffer(bufferSize);
  auto* eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(eventInfoBuffer.data());
  status = TdhGetEventInformation(mutableRecord, 0, nullptr, eventInfo, &bufferSize);
  if (status != ERROR_SUCCESS) {
    return {};
  }

  PropertyMap properties;
  properties.reserve(eventInfo->TopLevelPropertyCount);

  for (ULONG index = 0; index < eventInfo->TopLevelPropertyCount; ++index) {
    const auto& propertyInfo = eventInfo->EventPropertyInfoArray[index];
    if ((propertyInfo.Flags & PropertyStruct) != 0) {
      continue;
    }

    const auto* propertyName = reinterpret_cast<const wchar_t*>(eventInfoBuffer.data() + propertyInfo.NameOffset);
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG propertySize = 0;
    status = TdhGetPropertySize(mutableRecord, 0, nullptr, 1, &descriptor, &propertySize);
    if (status != ERROR_SUCCESS || propertySize == 0) {
      continue;
    }

    std::vector<BYTE> propertyBuffer(propertySize);
    status = TdhGetProperty(mutableRecord, 0, nullptr, 1, &descriptor, propertySize, propertyBuffer.data());
    if (status != ERROR_SUCCESS) {
      continue;
    }

    properties.insert_or_assign(
        ToLowerCopy(propertyName),
        EtwPropertyValue{
            .inType = propertyInfo.nonStructType.InType,
            .outType = propertyInfo.nonStructType.OutType,
            .value = FormatEtwPropertyValue(propertyBuffer.data(), propertySize, propertyInfo.nonStructType.InType)});
  }

  return properties;
}

std::wstring ReadFirstProperty(const PropertyMap& properties, const std::initializer_list<std::wstring_view> names) {
  for (const auto name : names) {
    const auto iterator = properties.find(ToLowerCopy(std::wstring(name)));
    if (iterator != properties.end() && !iterator->second.value.empty()) {
      return iterator->second.value;
    }
  }

  return {};
}

DWORD ParseDword(const std::wstring& value) {
  if (value.empty()) {
    return 0;
  }

  try {
    return static_cast<DWORD>(std::stoul(value, nullptr, 0));
  } catch (...) {
    return 0;
  }
}

ULONGLONG ParseUlonglong(const std::wstring& value) {
  if (value.empty()) {
    return 0;
  }

  try {
    return std::stoull(value, nullptr, 0);
  } catch (...) {
    return 0;
  }
}

std::wstring BaseNameFromPath(const std::wstring& pathValue) {
  if (pathValue.empty()) {
    return {};
  }

  std::error_code error;
  const auto fileName = std::filesystem::path(pathValue).filename();
  if (error) {
    return pathValue;
  }

  const auto value = fileName.wstring();
  return value.empty() ? pathValue : value;
}

bool IsInterestingProcess(const std::wstring& imageName) {
  const auto lowerImageName = ToLowerCopy(imageName);
  static const std::array<const wchar_t*, 12> interestingProcesses = {
      L"powershell.exe", L"pwsh.exe",      L"cmd.exe",      L"wscript.exe",
      L"cscript.exe",    L"mshta.exe",     L"rundll32.exe", L"regsvr32.exe",
      L"winword.exe",    L"excel.exe",     L"outlook.exe",  L"onenote.exe",
  };

  return std::any_of(interestingProcesses.begin(), interestingProcesses.end(),
                     [&lowerImageName](const auto* candidate) { return lowerImageName == candidate; });
}

bool StartsWithInsensitive(const std::wstring& value, const std::wstring& prefix) {
  const auto lowerValue = ToLowerCopy(value);
  const auto lowerPrefix = ToLowerCopy(prefix);
  return lowerValue.rfind(lowerPrefix, 0) == 0;
}

bool IsSystemPath(const std::wstring& pathValue) {
  if (pathValue.empty()) {
    return false;
  }

  return StartsWithInsensitive(pathValue, LR"(c:\windows\)") ||
         StartsWithInsensitive(pathValue, LR"(c:\program files\)") ||
         StartsWithInsensitive(pathValue, LR"(c:\program files (x86)\)");
}

bool ShouldEmitImageLoad(const EtwProcessContext& processContext, const std::wstring& modulePath,
                         const std::wstring& signer) {
  if (IsInterestingProcess(processContext.imageName)) {
    return true;
  }

  if (!IsSystemPath(modulePath)) {
    return true;
  }

  const auto lowerSigner = ToLowerCopy(signer);
  return lowerSigner.empty() || lowerSigner.find(L"microsoft") == std::wstring::npos;
}

std::wstring EventTimestampToUtc(const EVENT_RECORD& eventRecord) {
  const auto timestamp = FileTimeToUtcString(static_cast<ULONGLONG>(eventRecord.EventHeader.TimeStamp.QuadPart));
  return timestamp.empty() ? CurrentUtcTimestamp() : timestamp;
}

std::wstring BuildProcessStartPayload(const EtwProcessContext& context, const USHORT eventVersion) {
  return std::wstring(L"{\"pid\":") + std::to_wstring(context.pid) + L",\"parentPid\":" +
         std::to_wstring(context.parentPid) + L",\"imageName\":\"" + Utf8ToWide(EscapeJsonString(context.imageName)) +
         L"\",\"imagePath\":\"" + Utf8ToWide(EscapeJsonString(context.imagePath)) + L"\",\"parentImageName\":\"" +
         Utf8ToWide(EscapeJsonString(context.parentImageName)) + L"\",\"parentImagePath\":\"" +
         Utf8ToWide(EscapeJsonString(context.parentImagePath)) + L"\",\"commandLine\":\"" +
         Utf8ToWide(EscapeJsonString(context.commandLine)) + L"\",\"userSid\":\"" +
         Utf8ToWide(EscapeJsonString(context.userSid)) + L"\",\"integrityLevel\":\"" +
         Utf8ToWide(EscapeJsonString(context.integrityLevel)) + L"\",\"sessionId\":\"" +
         Utf8ToWide(EscapeJsonString(context.sessionId)) + L"\",\"signer\":\"" +
         Utf8ToWide(EscapeJsonString(context.signer)) + L"\",\"eventVersion\":" + std::to_wstring(eventVersion) + L"}";
}

std::wstring BuildProcessExitPayload(const EtwProcessContext& context, const DWORD exitCode, const USHORT eventVersion) {
  return std::wstring(L"{\"pid\":") + std::to_wstring(context.pid) + L",\"parentPid\":" +
         std::to_wstring(context.parentPid) + L",\"imageName\":\"" + Utf8ToWide(EscapeJsonString(context.imageName)) +
         L"\",\"imagePath\":\"" + Utf8ToWide(EscapeJsonString(context.imagePath)) + L"\",\"commandLine\":\"" +
         Utf8ToWide(EscapeJsonString(context.commandLine)) + L"\",\"userSid\":\"" +
         Utf8ToWide(EscapeJsonString(context.userSid)) + L"\",\"integrityLevel\":\"" +
         Utf8ToWide(EscapeJsonString(context.integrityLevel)) + L"\",\"sessionId\":\"" +
         Utf8ToWide(EscapeJsonString(context.sessionId)) + L"\",\"signer\":\"" +
         Utf8ToWide(EscapeJsonString(context.signer)) + L"\",\"exitCode\":" + std::to_wstring(exitCode) +
         L",\"eventVersion\":" + std::to_wstring(eventVersion) + L"}";
}

std::wstring BuildImageLoadPayload(const EtwProcessContext& processContext, const std::wstring& modulePath,
                                   const std::wstring& signer, const std::wstring& imageBase,
                                   const std::wstring& imageSize, const USHORT eventVersion) {
  return std::wstring(L"{\"pid\":") + std::to_wstring(processContext.pid) + L",\"imageName\":\"" +
         Utf8ToWide(EscapeJsonString(BaseNameFromPath(modulePath))) + L"\",\"imagePath\":\"" +
         Utf8ToWide(EscapeJsonString(modulePath)) + L"\",\"processImageName\":\"" +
         Utf8ToWide(EscapeJsonString(processContext.imageName)) + L"\",\"processImagePath\":\"" +
         Utf8ToWide(EscapeJsonString(processContext.imagePath)) + L"\",\"sessionId\":\"" +
         Utf8ToWide(EscapeJsonString(processContext.sessionId)) + L"\",\"signer\":\"" +
         Utf8ToWide(EscapeJsonString(signer)) + L"\",\"imageBase\":\"" +
         Utf8ToWide(EscapeJsonString(imageBase)) + L"\",\"imageSize\":\"" +
         Utf8ToWide(EscapeJsonString(imageSize)) + L"\",\"eventVersion\":" + std::to_wstring(eventVersion) + L"}";
}

}  // namespace

ProcessEtwSensor::ProcessEtwSensor(AgentConfig config) : config_(std::move(config)) {
  stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

ProcessEtwSensor::~ProcessEtwSensor() {
  Stop();
  if (stopEvent_ != nullptr) {
    CloseHandle(stopEvent_);
    stopEvent_ = nullptr;
  }
}

void ProcessEtwSensor::Start() {
  if (stopEvent_ == nullptr || workerThread_ != nullptr) {
    return;
  }

  ResetEvent(stopEvent_);
  sessionName_ = std::wstring(L"AntiVirusProcessEtw-") + GenerateGuidString();

  const auto propertiesBufferSize =
      static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + ((sessionName_.size() + 1) * sizeof(wchar_t)));
  std::vector<BYTE> propertiesBuffer(propertiesBufferSize, 0);
  auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertiesBuffer.data());
  properties->Wnode.BufferSize = propertiesBufferSize;
  properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  auto* loggerName = reinterpret_cast<wchar_t*>(propertiesBuffer.data() + properties->LoggerNameOffset);
  wcsncpy_s(loggerName, sessionName_.size() + 1, sessionName_.c_str(), _TRUNCATE);

  auto status = StartTraceW(&sessionHandle_, sessionName_.c_str(), properties);
  if (status != ERROR_SUCCESS) {
    const auto summary =
        status == ERROR_ACCESS_DENIED
            ? L"The ETW process sensor could not start its real-time session because the host lacks kernel trace privileges."
            : L"The ETW process sensor could not start its real-time session.";
    QueueStateEvent(L"process.etw.failed", summary,
                    std::wstring(L"{\"error\":") + std::to_wstring(status) + L"}");
    sessionHandle_ = 0;
    return;
  }

  ENABLE_TRACE_PARAMETERS enableParameters{};
  enableParameters.Version = ENABLE_TRACE_PARAMETERS_VERSION;

  status = EnableTraceEx2(sessionHandle_, &kKernelProcessProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                          TRACE_LEVEL_INFORMATION,
                          kKernelProcessKeyword | kKernelImageKeyword | (remoteThreadHandler_ ? kKernelThreadKeyword : 0ULL), 0, 0,
                          &enableParameters);
  if (status != ERROR_SUCCESS) {
    QueueStateEvent(L"process.etw.failed",
                    L"The ETW process sensor could not enable kernel process and image providers.",
                    std::wstring(L"{\"error\":") + std::to_wstring(status) + L"}");
    StopControllerSession();
    return;
  }

  EVENT_TRACE_LOGFILEW logFile{};
  logFile.LoggerName = sessionName_.data();
  logFile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
  logFile.EventRecordCallback = &ProcessEtwSensor::EventRecordCallback;
  logFile.Context = this;

  traceHandle_ = OpenTraceW(&logFile);
  if (traceHandle_ == INVALID_PROCESSTRACE_HANDLE) {
    const auto error = GetLastError();
    QueueStateEvent(L"process.etw.failed",
                    L"The ETW process sensor could not open a real-time consumer handle for its session.",
                    std::wstring(L"{\"error\":") + std::to_wstring(error) + L"}");
    traceHandle_ = 0;
    StopControllerSession();
    return;
  }

  workerThread_ = CreateThread(nullptr, 0, &ProcessEtwSensor::ThreadEntry, this, 0, nullptr);
  if (workerThread_ == nullptr) {
    const auto error = GetLastError();
    QueueStateEvent(L"process.etw.failed", L"The ETW process sensor could not start its consumer thread.",
                    std::wstring(L"{\"error\":") + std::to_wstring(error) + L"}");
    CloseTrace(traceHandle_);
    traceHandle_ = 0;
    StopControllerSession();
    return;
  }

  active_.store(true);
  QueueStateEvent(L"process.etw.started", L"The ETW process sensor started a real-time kernel event session.",
                  std::wstring(L"{\"sessionName\":\"") + Utf8ToWide(EscapeJsonString(sessionName_)) + L"\"}");
}

void ProcessEtwSensor::Stop() {
  if (stopEvent_ != nullptr) {
    SetEvent(stopEvent_);
  }

  if (traceHandle_ != 0) {
    CloseTrace(traceHandle_);
    traceHandle_ = 0;
  }

  if (workerThread_ != nullptr) {
    WaitForSingleObject(workerThread_, 5'000);
    CloseHandle(workerThread_);
    workerThread_ = nullptr;
  }

  StopControllerSession();
}

bool ProcessEtwSensor::IsActive() const {
  return active_.load();
}

void ProcessEtwSensor::SetDeviceId(std::wstring deviceId) {
  const std::scoped_lock lock(stateMutex_);
  deviceId_ = std::move(deviceId);
}

std::vector<TelemetryRecord> ProcessEtwSensor::DrainTelemetry() {
  const std::scoped_lock lock(telemetryMutex_);
  auto telemetry = pendingTelemetry_;
  pendingTelemetry_.clear();
  return telemetry;
}

DWORD WINAPI ProcessEtwSensor::ThreadEntry(LPVOID context) {
  auto* sensor = reinterpret_cast<ProcessEtwSensor*>(context);
  sensor->RunTraceLoop();
  return 0;
}

VOID WINAPI ProcessEtwSensor::EventRecordCallback(EVENT_RECORD* eventRecord) {
  if (eventRecord == nullptr || eventRecord->UserContext == nullptr) {
    return;
  }

  auto* sensor = reinterpret_cast<ProcessEtwSensor*>(eventRecord->UserContext);
  sensor->HandleEventRecord(*eventRecord);
}

void ProcessEtwSensor::RunTraceLoop() {
  TRACEHANDLE traceHandle = 0;
  {
    const std::scoped_lock lock(stateMutex_);
    traceHandle = traceHandle_;
  }

  if (traceHandle == 0) {
    active_.store(false);
    return;
  }

  const auto status = ProcessTrace(&traceHandle, 1, nullptr, nullptr);
  active_.store(false);

  if (WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0) {
    QueueStateEvent(L"process.etw.stopped", L"The ETW process sensor stopped its real-time session.",
                    std::wstring(L"{\"sessionName\":\"") + Utf8ToWide(EscapeJsonString(sessionName_)) + L"\"}");
    return;
  }

  QueueStateEvent(L"process.etw.failed", L"The ETW process sensor stopped unexpectedly.",
                  std::wstring(L"{\"error\":") + std::to_wstring(status) + L",\"sessionName\":\"" +
                      Utf8ToWide(EscapeJsonString(sessionName_)) + L"\"}");
}

// ThreadStart is logged in the context of the thread that created the new thread, so a header process ID that
// differs from the payload's ProcessID means one process started a thread inside another (code injection).
// This runs for every thread start, so the common path reads four bytes and returns.
void ProcessEtwSensor::HandleThreadStart(const EVENT_RECORD& eventRecord) {
  if (!remoteThreadHandler_ || eventRecord.UserDataLength < 8) return;
  if (threadLayout_ == 0) {
    const auto properties = ExtractEtwPropertyNames(eventRecord);
    threadLayout_ = properties.size() >= 2 && _wcsicmp(properties[0].c_str(), L"ProcessID") == 0 &&
                            _wcsicmp(properties[1].c_str(), L"ThreadID") == 0
                        ? 1
                        : -1;
  }
  if (threadLayout_ != 1) return;
  DWORD target = 0;
  memcpy(&target, eventRecord.UserData, sizeof(target));
  const DWORD source = eventRecord.EventHeader.ProcessId;
  if (source == target || source <= 4 || target <= 4) return;
  EtwProcessContext creator;
  {
    const std::scoped_lock lock(stateMutex_);
    const auto it = activeProcesses_.find(source);
    if (it == activeProcesses_.end()) return;
    creator = it->second;
  }
  try {
    for (const auto& record : remoteThreadHandler_(creator, target)) QueueTelemetry(record);
  } catch (...) {
  }
}

void ProcessEtwSensor::SetRemoteThreadHandler(RemoteThreadHandler handler) {
  const std::scoped_lock lock(stateMutex_);
  remoteThreadHandler_ = std::move(handler);
}

void ProcessEtwSensor::HandleEventRecord(const EVENT_RECORD& eventRecord) {
  if (eventRecord.EventHeader.ProviderId != kKernelProcessProviderGuid) {
    return;
  }

  const auto eventId = eventRecord.EventHeader.EventDescriptor.Id;
  if (eventId == kThreadStartEventId) {
    HandleThreadStart(eventRecord);
    return;
  }
  if (eventId != kProcessStartEventId && eventId != kProcessStopEventId && eventId != kImageLoadEventId) {
    return;
  }

  const auto properties = ExtractEtwProperties(eventRecord);
  if (eventId == kProcessStartEventId) {
    EtwProcessContext context{};
    context.pid = ParseDword(ReadFirstProperty(properties, {L"processid", L"processidnew", L"pid"}));
    context.parentPid = ParseDword(ReadFirstProperty(properties, {L"parentprocessid", L"parentpid"}));
    context.imageName =
        ReadFirstProperty(properties, {L"imagename", L"imagefilename", L"processname", L"applicationid"});
    context.commandLine = ReadFirstProperty(properties, {L"commandline"});
    context.sessionId = ReadFirstProperty(properties, {L"sessionid"});
    context.startedAt = EventTimestampToUtc(eventRecord);

    const auto runtime = QueryProcessRuntimeContext(context.pid);
    context.imagePath = runtime.imagePath;
    context.userSid = runtime.userSid;
    context.integrityLevel = runtime.integrityLevel;
    if (context.sessionId.empty()) {
      context.sessionId = runtime.sessionId;
    }
    context.signer = runtime.signer;

    if (context.imageName.empty()) {
      context.imageName = BaseNameFromPath(context.imagePath);
    }

    std::wstring parentImagePath;
    std::wstring parentImageName;
    {
      const std::scoped_lock lock(stateMutex_);
      const auto parentIterator = activeProcesses_.find(context.parentPid);
      if (parentIterator != activeProcesses_.end()) {
        parentImagePath = parentIterator->second.imagePath;
        parentImageName = parentIterator->second.imageName;
      }
    }

    if (parentImagePath.empty()) {
      parentImagePath = QueryProcessImagePath(context.parentPid);
    }

    if (parentImageName.empty()) {
      parentImageName = BaseNameFromPath(parentImagePath);
    }

    context.parentImagePath = parentImagePath;
    context.parentImageName = parentImageName;

    {
      const std::scoped_lock lock(stateMutex_);
      activeProcesses_.insert_or_assign(context.pid, context);
    }

    std::wstringstream summary;
    summary << L"Process " << (context.imageName.empty() ? L"(unknown)" : context.imageName) << L" started with PID "
            << context.pid;
    if (context.parentPid != 0) {
      summary << L" under PID " << context.parentPid;
      if (!context.parentImageName.empty()) {
        summary << L" (" << context.parentImageName << L")";
      }
    }
    if (!context.sessionId.empty()) {
      summary << L" in session " << context.sessionId;
    }
    summary << L".";

    QueueTelemetry(TelemetryRecord{
        .eventId = GenerateGuidString(),
        .eventType = L"process.started",
        .source = L"process-etw",
        .summary = summary.str(),
        .occurredAt = context.startedAt,
        .payloadJson = BuildProcessStartPayload(context, eventRecord.EventHeader.EventDescriptor.Version),
    });

    ProcessStartHandler handler;
    {
      const std::scoped_lock lock(stateMutex_);
      handler = processStartHandler_;
    }
    if (handler) {
      try {
        for (const auto& record : handler(context)) {
          QueueTelemetry(record);
        }
      } catch (...) {
        // Enforcement must never take down the sensor thread.
      }
    }
    return;
  }

  if (eventId == kProcessStopEventId) {
    const auto pid = ParseDword(ReadFirstProperty(properties, {L"processid", L"pid"}));
    const auto exitCode = ParseDword(ReadFirstProperty(properties, {L"exitstatus", L"exitcode"}));

    EtwProcessContext context{};
    {
      const std::scoped_lock lock(stateMutex_);
      const auto iterator = activeProcesses_.find(pid);
      if (iterator != activeProcesses_.end()) {
        context = iterator->second;
        activeProcesses_.erase(iterator);
      }
    }

    if (context.pid == 0) {
      context.pid = pid;
      context.imagePath = QueryProcessImagePath(pid);
      context.imageName = BaseNameFromPath(context.imagePath);
    }

    std::wstringstream summary;
    summary << L"Process " << (context.imageName.empty() ? L"(unknown)" : context.imageName) << L" exited with PID "
            << context.pid << L" and exit code " << exitCode << L".";

    QueueTelemetry(TelemetryRecord{
        .eventId = GenerateGuidString(),
        .eventType = L"process.exited",
        .source = L"process-etw",
        .summary = summary.str(),
        .occurredAt = EventTimestampToUtc(eventRecord),
        .payloadJson = BuildProcessExitPayload(context, exitCode, eventRecord.EventHeader.EventDescriptor.Version),
    });
    return;
  }

  const auto pid = ParseDword(ReadFirstProperty(properties, {L"processid", L"pid"}));
  const auto modulePath =
      ReadFirstProperty(properties, {L"imagename", L"imagefilename", L"filename", L"filepath", L"loadedimage"});
  if (modulePath.empty()) {
    return;
  }

  EtwProcessContext processContext{};
  {
    const std::scoped_lock lock(stateMutex_);
    const auto iterator = activeProcesses_.find(pid);
    if (iterator != activeProcesses_.end()) {
      processContext = iterator->second;
    }
  }

  if (processContext.pid == 0) {
    processContext.pid = pid;
    processContext.imagePath = QueryProcessImagePath(pid);
    processContext.imageName = BaseNameFromPath(processContext.imagePath);
    processContext.sessionId = QueryProcessRuntimeContext(pid).sessionId;
  }

  const auto imageBase = ReadFirstProperty(properties, {L"imagebase", L"defaultbase"});
  const auto imageSize = ReadFirstProperty(properties, {L"imagesize"});
  const auto signer = QuerySignerSubject(modulePath);
  if (!ShouldEmitImageLoad(processContext, modulePath, signer)) {
    return;
  }

  std::wstringstream summary;
  summary << L"Image " << BaseNameFromPath(modulePath) << L" loaded into "
          << (processContext.imageName.empty() ? L"(unknown)" : processContext.imageName) << L" (PID "
          << processContext.pid << L").";

  QueueTelemetry(TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = L"image.loaded",
      .source = L"process-etw",
      .summary = summary.str(),
      .occurredAt = EventTimestampToUtc(eventRecord),
      .payloadJson = BuildImageLoadPayload(processContext, modulePath, signer, imageBase, imageSize,
                                           eventRecord.EventHeader.EventDescriptor.Version),
  });
}

void ProcessEtwSensor::SetProcessStartHandler(ProcessStartHandler handler) {
  const std::scoped_lock lock(stateMutex_);
  processStartHandler_ = std::move(handler);
}

void ProcessEtwSensor::QueueTelemetry(const TelemetryRecord& record) {
  const std::scoped_lock lock(telemetryMutex_);
  pendingTelemetry_.push_back(record);
}

void ProcessEtwSensor::QueueStateEvent(const std::wstring& eventType, const std::wstring& summary,
                                       const std::wstring& payloadJson) {
  QueueTelemetry(TelemetryRecord{
      .eventId = GenerateGuidString(),
      .eventType = eventType,
      .source = L"process-etw",
      .summary = summary,
      .occurredAt = CurrentUtcTimestamp(),
      .payloadJson = payloadJson,
  });
}

void ProcessEtwSensor::StopControllerSession() {
  if (sessionHandle_ == 0 || sessionName_.empty()) {
    return;
  }

  const auto propertiesBufferSize =
      static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + ((sessionName_.size() + 1) * sizeof(wchar_t)));
  std::vector<BYTE> propertiesBuffer(propertiesBufferSize, 0);
  auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertiesBuffer.data());
  properties->Wnode.BufferSize = propertiesBufferSize;
  properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

  auto* loggerName = reinterpret_cast<wchar_t*>(propertiesBuffer.data() + properties->LoggerNameOffset);
  wcsncpy_s(loggerName, sessionName_.size() + 1, sessionName_.c_str(), _TRUNCATE);

  ControlTraceW(sessionHandle_, sessionName_.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
  sessionHandle_ = 0;
}

}  // namespace antivirus::agent
