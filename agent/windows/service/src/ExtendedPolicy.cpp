#include "ExtendedPolicy.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>

namespace antivirus::agent {
namespace json {
namespace {

class Parser {
 public:
  explicit Parser(const std::string& text) : s_(text) {}

  std::optional<Value> Run() {
    auto value = ParseValue(0);
    SkipWs();
    if (!value || pos_ != s_.size()) return std::nullopt;
    return value;
  }

 private:
  static constexpr int kMaxDepth = 64;

  void SkipWs() {
    while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\n' || s_[pos_] == '\r' || s_[pos_] == '\t')) ++pos_;
  }

  bool Consume(const char* literal) {
    std::size_t i = 0;
    while (literal[i] != '\0') {
      if (pos_ + i >= s_.size() || s_[pos_ + i] != literal[i]) return false;
      ++i;
    }
    pos_ += i;
    return true;
  }

  static void AppendUtf8(std::string& out, unsigned cp) {
    if (cp < 0x80) {
      out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  std::optional<unsigned> Hex4() {
    if (pos_ + 4 > s_.size()) return std::nullopt;
    unsigned value = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = s_[pos_++];
      value <<= 4;
      if (c >= '0' && c <= '9') value |= static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') value |= static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') value |= static_cast<unsigned>(c - 'A' + 10);
      else return std::nullopt;
    }
    return value;
  }

  std::optional<std::string> ParseString() {
    if (pos_ >= s_.size() || s_[pos_] != '"') return std::nullopt;
    ++pos_;
    std::string out;
    while (pos_ < s_.size()) {
      const char c = s_[pos_++];
      if (c == '"') return out;
      if (static_cast<unsigned char>(c) < 0x20) return std::nullopt;
      if (c != '\\') {
        out.push_back(c);
        continue;
      }
      if (pos_ >= s_.size()) return std::nullopt;
      const char e = s_[pos_++];
      switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          auto cp = Hex4();
          if (!cp) return std::nullopt;
          if (*cp >= 0xD800 && *cp <= 0xDBFF && Consume("\\u")) {
            const auto low = Hex4();
            if (!low || *low < 0xDC00 || *low > 0xDFFF) return std::nullopt;
            cp = 0x10000 + ((*cp - 0xD800) << 10) + (*low - 0xDC00);
          }
          AppendUtf8(out, *cp);
          break;
        }
        default:
          return std::nullopt;
      }
    }
    return std::nullopt;
  }

  std::optional<Value> ParseValue(int depth) {
    if (depth > kMaxDepth) return std::nullopt;
    SkipWs();
    if (pos_ >= s_.size()) return std::nullopt;
    const char c = s_[pos_];
    if (c == '{') {
      ++pos_;
      Object obj;
      SkipWs();
      if (pos_ < s_.size() && s_[pos_] == '}') {
        ++pos_;
        return Value{std::move(obj)};
      }
      while (true) {
        SkipWs();
        auto key = ParseString();
        if (!key) return std::nullopt;
        SkipWs();
        if (pos_ >= s_.size() || s_[pos_++] != ':') return std::nullopt;
        auto value = ParseValue(depth + 1);
        if (!value) return std::nullopt;
        obj.insert_or_assign(std::move(*key), std::move(*value));
        SkipWs();
        if (pos_ < s_.size() && s_[pos_] == ',') {
          ++pos_;
          continue;
        }
        if (pos_ < s_.size() && s_[pos_] == '}') {
          ++pos_;
          return Value{std::move(obj)};
        }
        return std::nullopt;
      }
    }
    if (c == '[') {
      ++pos_;
      Array arr;
      SkipWs();
      if (pos_ < s_.size() && s_[pos_] == ']') {
        ++pos_;
        return Value{std::move(arr)};
      }
      while (true) {
        auto value = ParseValue(depth + 1);
        if (!value) return std::nullopt;
        arr.push_back(std::move(*value));
        SkipWs();
        if (pos_ < s_.size() && s_[pos_] == ',') {
          ++pos_;
          continue;
        }
        if (pos_ < s_.size() && s_[pos_] == ']') {
          ++pos_;
          return Value{std::move(arr)};
        }
        return std::nullopt;
      }
    }
    if (c == '"') {
      auto str = ParseString();
      if (!str) return std::nullopt;
      return Value{std::move(*str)};
    }
    if (Consume("true")) return Value{true};
    if (Consume("false")) return Value{false};
    if (Consume("null")) return Value{std::monostate{}};
    const auto start = pos_;
    while (pos_ < s_.size() && (std::isdigit(static_cast<unsigned char>(s_[pos_])) || s_[pos_] == '-' || s_[pos_] == '+' ||
                                s_[pos_] == '.' || s_[pos_] == 'e' || s_[pos_] == 'E')) {
      ++pos_;
    }
    if (start == pos_) return std::nullopt;
    const std::string number = s_.substr(start, pos_ - start);
    char* end = nullptr;
    const double value = std::strtod(number.c_str(), &end);
    if (end != number.c_str() + number.size() || !std::isfinite(value)) return std::nullopt;
    return Value{value};
  }

  const std::string& s_;
  std::size_t pos_{0};
};

}  // namespace

const Value* Value::Get(const std::string& key) const {
  if (const auto* obj = std::get_if<Object>(&v)) {
    const auto it = obj->find(key);
    return it == obj->end() ? nullptr : &it->second;
  }
  return nullptr;
}

std::optional<bool> Value::Bool() const {
  if (const auto* b = std::get_if<bool>(&v)) return *b;
  return std::nullopt;
}

std::optional<double> Value::Number() const {
  if (const auto* d = std::get_if<double>(&v)) return *d;
  return std::nullopt;
}

std::optional<std::string> Value::String() const {
  if (const auto* s = std::get_if<std::string>(&v)) return *s;
  return std::nullopt;
}

std::vector<std::string> Value::Strings() const {
  std::vector<std::string> out;
  if (const auto* arr = std::get_if<Array>(&v)) {
    for (const auto& item : *arr) {
      if (const auto* s = std::get_if<std::string>(&item.v)) out.push_back(*s);
    }
  }
  return out;
}

std::optional<Value> Parse(const std::string& text) {
  if (text.size() > 8 * 1024 * 1024) return std::nullopt;
  return Parser(text).Run();
}

}  // namespace json

std::wstring Utf8ToWideString(const std::string& value) {
  std::wstring out;
  out.reserve(value.size());
  for (std::size_t i = 0; i < value.size();) {
    const auto c = static_cast<unsigned char>(value[i]);
    unsigned cp = 0;
    std::size_t len = 1;
    if (c < 0x80) {
      cp = c;
    } else if ((c >> 5) == 0x6 && i + 1 < value.size()) {
      cp = ((c & 0x1F) << 6) | (static_cast<unsigned char>(value[i + 1]) & 0x3F);
      len = 2;
    } else if ((c >> 4) == 0xE && i + 2 < value.size()) {
      cp = ((c & 0x0F) << 12) | ((static_cast<unsigned char>(value[i + 1]) & 0x3F) << 6) |
           (static_cast<unsigned char>(value[i + 2]) & 0x3F);
      len = 3;
    } else if ((c >> 3) == 0x1E && i + 3 < value.size()) {
      cp = ((c & 0x07) << 18) | ((static_cast<unsigned char>(value[i + 1]) & 0x3F) << 12) |
           ((static_cast<unsigned char>(value[i + 2]) & 0x3F) << 6) | (static_cast<unsigned char>(value[i + 3]) & 0x3F);
      len = 4;
    } else {
      cp = 0xFFFD;
    }
    if (sizeof(wchar_t) == 2 && cp >= 0x10000) {
      cp -= 0x10000;
      out.push_back(static_cast<wchar_t>(0xD800 + (cp >> 10)));
      out.push_back(static_cast<wchar_t>(0xDC00 + (cp & 0x3FF)));
    } else {
      out.push_back(static_cast<wchar_t>(cp));
    }
    i += len;
  }
  return out;
}

namespace {

std::vector<std::wstring> WideList(const json::Value* section, const char* key) {
  std::vector<std::wstring> out;
  if (section == nullptr) return out;
  if (const auto* v = section->Get(key)) {
    for (const auto& item : v->Strings()) out.push_back(Utf8ToWideString(item));
  }
  return out;
}

std::wstring WideString(const json::Value* section, const char* key, const wchar_t* fallback) {
  if (section != nullptr) {
    if (const auto* v = section->Get(key)) {
      if (auto s = v->String()) return Utf8ToWideString(*s);
    }
  }
  return fallback;
}

bool BoolOr(const json::Value* section, const char* key, bool fallback) {
  if (section != nullptr) {
    if (const auto* v = section->Get(key)) {
      if (auto b = v->Bool()) return *b;
    }
  }
  return fallback;
}

}  // namespace

namespace {
ScanPlan ParseScanPlan(const json::Value* antimalware, const char* key) {
  ScanPlan plan;
  if (antimalware == nullptr) return plan;
  const auto* value = antimalware->Get(key);
  if (value == nullptr || !value->IsObject()) return plan;
  plan.present = true;
  plan.off = value->Get("off") != nullptr && value->Get("off")->Bool().value_or(false);
  if (const auto* minute = value->Get("minuteOfDay"); minute != nullptr) {
    plan.minuteOfDay = std::clamp(static_cast<int>(minute->Number().value_or(0)), 0, 24 * 60 - 1);
  }
  if (const auto* days = value->Get("days"); days != nullptr) {
    if (const auto* list = std::get_if<json::Array>(&days->v)) {
      for (const auto& day : *list) {
        if (const auto number = day.Number(); number && *number >= 0 && *number <= 6) {
          plan.days.push_back(static_cast<int>(*number));
        }
      }
    }
  }
  if (!plan.off && plan.days.empty()) plan.present = false;
  return plan;
}
}  // namespace

ExtendedPolicy ExtendedPolicy::Parse(const std::string& modulesJson) {
  ExtendedPolicy policy;
  const auto root = json::Parse(modulesJson);
  if (!root || !root->IsObject()) return policy;
  policy.present = true;

  const auto* antimalware = root->Get("antimalware");
  policy.mlSensitivity = WideString(antimalware, "mlSensitivity", L"balanced");
  policy.behavior.excludedProcesses = WideList(antimalware, "exclusionProcesses");
  policy.quickScanPlan = ParseScanPlan(antimalware, "quickScanPlan");
  policy.fullScanPlan = ParseScanPlan(antimalware, "fullScanPlan");

  if (const auto* asr = root->Get("attackSurface"); asr != nullptr) {
    if (const auto* obj = std::get_if<json::Object>(&asr->v)) {
      for (const auto& [key, value] : *obj) {
        if (auto mode = value.String()) {
          policy.behavior.asr[Utf8ToWideString(key)] = behavior::ParseRuleMode(Utf8ToWideString(*mode));
        }
      }
    }
  }

  policy.scriptExecution = BoolOr(root->Get("response"), "scriptExecution", true);
  policy.remoteAccessEnabled = BoolOr(root->Get("remoteAccess"), "enabled", true);

  const auto* ransomware = root->Get("ransomware");
  policy.ransomwareEnabled = BoolOr(ransomware, "enabled", true);
  policy.behavior.blockShadowCopyDeletion = policy.ransomwareEnabled && BoolOr(ransomware, "blockShadowCopyDeletion", true);
  policy.canaryFiles = policy.ransomwareEnabled && BoolOr(ransomware, "canaryFiles", true);

  const auto* app = root->Get("applicationControl");
  policy.behavior.appControlMode = WideString(app, "mode", L"off");
  policy.behavior.blockedApps = WideList(app, "blockedApps");
  policy.behavior.allowedPublishers = WideList(app, "allowedPublishers");
  policy.behavior.allowedHashes = WideList(app, "allowedHashes");
  policy.behavior.blockUnknownReputation = BoolOr(app, "blockUnknownReputation", false);

  const auto* dc = root->Get("deviceControl");
  policy.deviceControl.enabled = BoolOr(dc, "enabled", false);
  policy.deviceControl.usbStorage = WideString(dc, "usbStorage", L"allow");
  policy.deviceControl.opticalMedia = WideString(dc, "opticalMedia", L"allow");
  policy.deviceControl.mtpDevices = WideString(dc, "mtpDevices", L"allow");
  policy.deviceControl.bluetoothFileTransfer = WideString(dc, "bluetoothFileTransfer", L"allow");
  policy.deviceControl.printing = WideString(dc, "printing", L"allow");
  policy.deviceControl.encryptedUsbOnly = BoolOr(dc, "encryptedUsbOnly", false);
  policy.deviceControl.usbAllowedIds = WideList(dc, "usbAllowedIds");
  return policy;
}

}  // namespace antivirus::agent
