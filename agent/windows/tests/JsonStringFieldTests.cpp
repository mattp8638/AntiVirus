#include "JsonStringField.h"
#include <string>

using antivirus::agent::FindRawJsonStringField;

int main() {
  const std::string field(256 * 1024, 'x');
  const auto json = "{\"value\":\"" + field + "\"}";
  if (FindRawJsonStringField(json, "value") != field) return 1;
  if (FindRawJsonStringField(json.substr(0, json.size() - 2), "value")) return 2;
  if (FindRawJsonStringField(R"({"value":""})", "value") != "") return 3;
  if (FindRawJsonStringField(R"({"msg":"\"value\":\"fake\"","nested":{"value":"a\"b"}})", "value") != R"(a\"b)") return 4;
  if (FindRawJsonStringField(R"({"value":42})", "value")) return 5;
  if (FindRawJsonStringField(R"({"value":"abc\)", "value")) return 6;
  if (FindRawJsonStringField(R"({"value":"abc\\"})", "value") != R"(abc\\)") return 7;
  return 0;
}
