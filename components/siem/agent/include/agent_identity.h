// agent_identity.h
// Agent identity, keypair generation and persistence
#pragma once
#include <string>

namespace agent_identity {
    struct AgentIdentity {
        std::string uuid;
        std::string hardware_binding;
        std::string public_key_pem;
        std::string encrypted_private_key_blob; // protected by DPAPI
    };

    // Generate or load an existing identity from disk. If not present, generate keys and persist.
    AgentIdentity GenerateOrLoadIdentity(const std::string& storage_path);

    // Helper to persist identity securely (private key protected using DPAPI)
    bool SaveIdentitySecure(const AgentIdentity& identity, const std::string& storage_path);

    // Load identity (decrypt private key using DPAPI)
    AgentIdentity LoadIdentity(const std::string& storage_path);
}
