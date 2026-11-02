// evidence_impl.cpp
// EvidenceBroker implementation: hashing, signing (OpenSSL), packaging, upload stub
#include "../../include/agent_evidence.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <mutex>
#include "../../include/agent_config.h"

namespace fs = std::filesystem;

static std::mutex g_evidence_mutex;

namespace agent_evidence {

namespace {
std::string EscapeJsonString(const std::string& input) {
    std::string escaped;
    escaped.reserve(input.size() + 8);
    for (char c : input) {
        switch (c) {
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
                escaped += c;
                break;
        }
    }
    return escaped;
}

bool EnqueueUplinkEvidence(
    const std::string& queue_dir,
    const std::string& evidence_id,
    const std::string& tenant_id,
    const std::string& asset_id,
    const std::string& source,
    const std::string& type,
    const std::string& related_id,
    const std::string& hash,
    const std::string& storage_uri,
    const std::string& captured_at
) {
    if (queue_dir.empty() || evidence_id.empty() || hash.empty()) {
        std::cerr << "EnqueueUplinkEvidence: missing required fields\n";
        return false;
    }

    fs::path queue_path(queue_dir);
    fs::create_directories(queue_path);
    fs::path payload_path = queue_path / ("evidence_" + evidence_id + ".json");

    std::ofstream out(payload_path);
    if (!out) {
        std::cerr << "EnqueueUplinkEvidence: unable to write " << payload_path << std::endl;
        return false;
    }

    std::string json = "{";
    json += "\"kind\":\"evidence\",";
    json += "\"evidence_id\":\"" + EscapeJsonString(evidence_id) + "\",";
    json += "\"tenant_id\":\"" + EscapeJsonString(tenant_id) + "\",";
    json += "\"asset_id\":\"" + EscapeJsonString(asset_id) + "\",";
    json += "\"source\":\"" + EscapeJsonString(source) + "\",";
    json += "\"type\":\"" + EscapeJsonString(type) + "\",";
    json += "\"related_id\":\"" + EscapeJsonString(related_id) + "\",";
    json += "\"hash\":\"" + EscapeJsonString(hash) + "\",";
    json += "\"storage_uri\":\"" + EscapeJsonString(storage_uri) + "\",";
    json += "\"captured_at\":\"" + EscapeJsonString(captured_at) + "\"";
    json += "}";

    out << json;
    out.close();
    return true;
}
} // namespace

static std::string ComputeSHA256Hex(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return "";

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    EVP_DigestInit_ex(mdctx, md, nullptr);
    char buf[4096];
    while (ifs.good()) {
        ifs.read(buf, sizeof(buf));
        std::streamsize r = ifs.gcount();
        if (r > 0) EVP_DigestUpdate(mdctx, buf, (size_t)r);
    }
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    // hex
    std::string hex; hex.reserve(md_len*2);
    static const char* hexchars = "0123456789abcdef";
    for (unsigned int i=0;i<md_len;i++){
        unsigned char v = md_value[i];
        hex.push_back(hexchars[(v>>4)&0xF]);
        hex.push_back(hexchars[v&0xF]);
    }
    return hex;
}

void EvidenceBroker::AddEvidence(const EvidenceItem& item) {
    std::lock_guard<std::mutex> lk(g_evidence_mutex);
    evidence_store_.push_back(item);
}

void EvidenceBroker::SealEvidence(const std::string& evidence_id) {
    std::lock_guard<std::mutex> lk(g_evidence_mutex);
    for (auto &it : evidence_store_) {
        if (it.evidence_id == evidence_id) {
            if (!fs::exists(it.storage_path)) {
                std::cerr << "Evidence file missing: " << it.storage_path << std::endl;
                return;
            }
            it.hash = ComputeSHA256Hex(it.storage_path);
            // Signing the hash with a local key would happen here. Placeholder.
            std::cout << "Sealed evidence " << it.evidence_id << " hash=" << it.hash << std::endl;
            return;
        }
    }
    std::cerr << "SealEvidence: id not found " << evidence_id << std::endl;
}

void EvidenceBroker::UploadEvidence(const std::string& evidence_id) {
    std::lock_guard<std::mutex> lk(g_evidence_mutex);
    for (auto &it : evidence_store_) {
        if (it.evidence_id == evidence_id) {
            agent::Config config = agent::LoadConfig();
            // Package evidence: create a tar/zip or simple folder with metadata
            fs::path outdir = fs::current_path() / "evidence_packages" / it.evidence_id;
            fs::create_directories(outdir);
            try {
                fs::path src(it.storage_path);
                if (fs::exists(src)) {
                    fs::copy_file(src, outdir / src.filename(), fs::copy_options::overwrite_existing);
                }
                // write metadata
                std::ofstream meta(outdir / "metadata.txt");
                meta << "tenant_id=" << config.tenant_id << "\n";
                meta << "asset_id=" << config.asset_id << "\n";
                meta << "evidence_id=" << it.evidence_id << "\n";
                meta << "source=" << it.source << "\n";
                meta << "type=" << it.type << "\n";
                meta << "related_id=" << it.related_id << "\n";
                meta << "hash=" << it.hash << "\n";
                meta << "storage_uri=" << "file://" << outdir.string() << "\n";
                meta << "captured_at=" << std::chrono::duration_cast<std::chrono::seconds>(it.captured_at.time_since_epoch()).count() << "\n";
                meta.close();
            } catch(const std::exception &e) {
                std::cerr << "UploadEvidence packaging failed: " << e.what() << std::endl;
                return;
            }

            std::string packagedir = (fs::current_path() / "evidence_packages" / it.evidence_id).string();
            std::string storage_uri = "file://" + packagedir;
            std::string captured_at = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                it.captured_at.time_since_epoch()).count());
            std::string queue_dir = std::getenv("RUST_UPLINK_QUEUE_DIR")
                ? std::getenv("RUST_UPLINK_QUEUE_DIR")
                : "uplink_queue";
            bool queued = EnqueueUplinkEvidence(
                queue_dir,
                it.evidence_id,
                config.tenant_id,
                config.asset_id,
                it.source,
                it.type,
                it.related_id.empty() ? it.evidence_id : it.related_id,
                it.hash,
                storage_uri,
                captured_at
            );
            if (queued) {
                std::cout << "Evidence package queued for uplink: " << packagedir << std::endl;
            } else {
                std::cerr << "Evidence uplink queue failed for: " << packagedir << std::endl;
            }
            return;
        }
    }
    std::cerr << "UploadEvidence: id not found " << evidence_id << std::endl;
}

std::vector<EvidenceItem> EvidenceBroker::ListEvidence() const {
    std::lock_guard<std::mutex> lk(g_evidence_mutex);
    return evidence_store_;
}

}
