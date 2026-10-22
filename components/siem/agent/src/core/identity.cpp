#include "../../include/agent_identity.h"
#include <windows.h>
#include <wincrypt.h>
#include <rpc.h>
#include <fstream>
#include <iostream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Rpcrt4.lib")

namespace agent_identity {

    static std::string GuidToString(GUID g) {
        RPC_CSTR str = nullptr;
        if (UuidToStringA(&g, &str) == RPC_S_OK) {
            std::string s((char*)str);
            RpcStringFreeA(&str);
            return s;
        }
        return "";
    }

    static std::string ProtectDataToString(const DATA_BLOB& in) {
        // Convert blob to hex string for simple storage
        std::string out; out.reserve(in.cbData * 2);
        for (DWORD i = 0; i < in.cbData; ++i) {
            char buf[3]; sprintf_s(buf, "%02x", in.pbData[i]); out += buf;
        }
        return out;
    }

    AgentIdentity GenerateOrLoadIdentity(const std::string& storage_path) {
        // Try to load first
        AgentIdentity id;
        std::ifstream ifs(storage_path, std::ios::binary);
        if (ifs.good()) {
            try { ifs >> id.uuid; ifs >> id.public_key_pem; ifs >> id.encrypted_private_key_blob; } catch(...) {}
            ifs.close();
            return id;
        }

        // Generate new UUID
        GUID g; UuidCreate(&g);
        id.uuid = GuidToString(g);
        id.hardware_binding = "TODO: collect hardware fingerprint";

        // Key generation is left as a TODO placeholder. Real implementation should use CNG/OpenSSL and
        // then protect the private key with CryptProtectData (DPAPI) or TPM.
        std::string fake_priv = "FAKE_PRIVATE_KEY_FOR_" + id.uuid;
        DATA_BLOB in; in.pbData = (BYTE*)fake_priv.data(); in.cbData = (DWORD)fake_priv.size();
        DATA_BLOB out;
        if (CryptProtectData(&in, L"AgentPrivateKey", nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &out)) {
            id.encrypted_private_key_blob = ProtectDataToString(out);
            LocalFree(out.pbData);
        }
        id.public_key_pem = "FAKE_PUBLIC_KEY_FOR_" + id.uuid;

        // Persist minimal identity (insecure text for prototype) — production must use secure storage
        std::ofstream ofs(storage_path, std::ios::binary | std::ios::trunc);
        if (ofs.good()) {
            ofs << id.uuid << "\n";
            ofs << id.public_key_pem << "\n";
            ofs << id.encrypted_private_key_blob << "\n";
            ofs.close();
        }

        return id;
    }

    bool SaveIdentitySecure(const AgentIdentity& identity, const std::string& storage_path) {
        std::ofstream ofs(storage_path, std::ios::binary | std::ios::trunc);
        if (!ofs.good()) return false;
        ofs << identity.uuid << "\n";
        ofs << identity.public_key_pem << "\n";
        ofs << identity.encrypted_private_key_blob << "\n";
        ofs.close();
        return true;
    }

    AgentIdentity LoadIdentity(const std::string& storage_path) {
        AgentIdentity id;
        std::ifstream ifs(storage_path, std::ios::binary);
        if (!ifs.good()) return id;
        ifs >> id.uuid; ifs >> id.public_key_pem; ifs >> id.encrypted_private_key_blob; ifs.close();
        return id;
    }
}
