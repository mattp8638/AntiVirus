#pragma once

#include <string>

namespace agent {

std::string CanonicalJson(const std::string& payload);
std::string SignPayload(const std::string& shared_key,
                        const std::string& payload,
                        long long timestamp_seconds);
bool VerifySignature(const std::string& shared_key,
                     const std::string& payload,
                     long long timestamp_seconds,
                     const std::string& signature);

}  // namespace agent
