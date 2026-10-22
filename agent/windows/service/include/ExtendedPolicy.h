#pragma once

// Settings from Fenrir Cloud's policy "modules" object that the original
// PolicySnapshot does not carry: attack surface rules, application control,
// device control, ML sensitivity and ransomware options. Kept separate so the
// runtime database schema does not change; the raw JSON is cached on disk.

#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "BehaviorRules.h"

namespace antivirus::agent {

namespace json {

struct Value;
using Object = std::map<std::string, Value>;
using Array = std::vector<Value>;

struct Value {
  std::variant<std::monostate, bool, double, std::string, Array, Object> v;

  bool IsObject() const { return std::holds_alternative<Object>(v); }
  const Value* Get(const std::string& key) const;
  std::optional<bool> Bool() const;
  std::optional<double> Number() const;
  std::optional<std::string> String() const;
  std::vector<std::string> Strings() const;
};

// Strict RFC 8259 parser with depth/size limits. Returns nullopt on malformed input.
std::optional<Value> Parse(const std::string& text);

}  // namespace json

struct DeviceControlSettings {
  bool enabled{false};
  std::wstring usbStorage{L"allow"};   // allow | audit | read-only | block
  std::wstring opticalMedia{L"allow"};  // allow | read-only | block
  std::wstring mtpDevices{L"allow"};    // allow | read-only | block
  std::wstring bluetoothFileTransfer{L"allow"};
  std::wstring printing{L"allow"};
  bool encryptedUsbOnly{false};
  std::vector<std::wstring> usbAllowedIds;
};

struct ExtendedPolicy {
  bool present{false};  // false until a cloud policy with modules has been received
  std::wstring mlSensitivity{L"balanced"};
  behavior::BehaviorPolicy behavior;
  DeviceControlSettings deviceControl;
  bool ransomwareEnabled{true};
  bool canaryFiles{true};
  bool scriptExecution{true};      // modules.response.scriptExecution
  bool remoteAccessEnabled{true};  // modules.remoteAccess.enabled

  static ExtendedPolicy Parse(const std::string& modulesJson);
};

std::wstring Utf8ToWideString(const std::string& value);

}  // namespace antivirus::agent
