#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace antivirus::agent {

std::wstring ComputeFileSha256(const std::filesystem::path& path);
std::wstring ComputeBufferSha256(const unsigned char* buffer, std::size_t length);
std::wstring ComputeBufferSha256(const std::vector<unsigned char>& buffer);
bool VerifyFileAuthenticodeSignature(const std::filesystem::path& path);
std::wstring QueryFileSignerSubject(const std::filesystem::path& path);
// The publisher of a validly signed file (its own signature, or the Windows catalog that lists it), for example
// "Microsoft Windows" or "Adobe Inc."; empty when it is unsigned or the signature does not verify.
std::wstring QueryFilePublisher(const std::filesystem::path& path);

}  // namespace antivirus::agent
