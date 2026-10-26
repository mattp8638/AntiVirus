#pragma once

#include <string>

namespace antivirus::agent {

// Runs the cloud's network.probe command: TCP-connects to each target in
// {"targets":[{"monitorId","address","port"}]} (at most 100, 2 s timeout) and
// returns {"results":[{"monitorId","up","latencyMs"|"error"}]} as UTF-8 JSON.
// Loopback, link-local (including cloud metadata), multicast and unspecified
// addresses are refused.
std::string RunNetworkProbe(const std::string& payloadUtf8);

}  // namespace antivirus::agent
