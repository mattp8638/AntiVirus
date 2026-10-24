#include "StringUtils.h"

#include <Windows.h>
#include <objbase.h>  // Explicit COM GUID declarations for lean Windows headers

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace antivirus::agent {

std::string WideToUtf8(const std::wstring& value) {
  if (value.empty()) {
    return {};
  }

  const auto requiredBytes =
      WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  std::string result(requiredBytes, '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), requiredBytes, nullptr,
                      nullptr);
  return result;
}

std::wstring Utf8ToWide(const std::string& value) {
  if (value.empty()) {
    return {};
  }

  const auto requiredWideChars =
      MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
  std::wstring result(requiredWideChars, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), requiredWideChars);
  return result;
}

std::wstring ReadEnvironmentVariable(const wchar_t* name) {
  if (const auto* value = _wgetenv(name); value != nullptr) {
    return std::wstring(value);
  }

  return {};
}

std::string EscapeJsonString(const std::wstring& value) {
  const auto utf8 = WideToUtf8(value);
  std::string escaped;
  escaped.reserve(utf8.size());

  for (const auto ch : utf8) {
    switch (ch) {
      case '\\':
        escaped += "\\\\";
        break;
      case '"':
        escaped += "\\\"";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        escaped.push_back(ch);
        break;
    }
  }

  return escaped;
}

std::string TrimCopy(std::string value) {
  value.erase(value.begin(),
              std::find_if(value.begin(), value.end(), [](unsigned char ch) { return !std::isspace(ch); }));
  value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(),
              value.end());
  return value;
}

std::wstring CurrentUtcTimestamp() {
  SYSTEMTIME systemTime{};
  GetSystemTime(&systemTime);

  wchar_t buffer[32] = {};
  swprintf(buffer, 32, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", systemTime.wYear, systemTime.wMonth,
           systemTime.wDay, systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds);
  return std::wstring(buffer);
}

std::wstring GenerateGuidString() {
  GUID guid{};
  if (CoCreateGuid(&guid) != S_OK) {
    return L"00000000-0000-0000-0000-000000000000";
  }

  wchar_t buffer[64] = {};
  const auto written = StringFromGUID2(guid, buffer, 64);
  if (written <= 1) {
    return L"00000000-0000-0000-0000-000000000000";
  }

  std::wstring value(buffer, written - 1);
  if (!value.empty() && value.front() == L'{' && value.back() == L'}') {
    value = value.substr(1, value.size() - 2);
  }

  return value;
}

}  // namespace antivirus::agent
