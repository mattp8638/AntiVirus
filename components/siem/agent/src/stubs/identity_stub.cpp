// Minimal stub to satisfy agent_identity usage during builds
#include "../../include/agent_identity.h"
#include <string>

namespace agent_identity {
    // Return a stable placeholder AgentIdentity for builds
    AgentIdentity GenerateOrLoadIdentity(const std::string& storage_path) {
        AgentIdentity id;
        id.uuid = "00000000-0000-0000-0000-000000000000";
        id.hardware_binding = "stub-hw";
        id.public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq...stub...IDAQAB\n-----END PUBLIC KEY-----\n";
        id.encrypted_private_key_blob = ""; // no private key in stub
        (void)storage_path;
        return id;
    }

    bool SaveIdentitySecure(const AgentIdentity& identity, const std::string& storage_path) {
        (void)identity; (void)storage_path; return true;
    }

    AgentIdentity LoadIdentity(const std::string& storage_path) {
        return GenerateOrLoadIdentity(storage_path);
    }
}
