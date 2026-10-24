#include "CryptoUtils.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#include <sstream>
#include <stdexcept>
#include <vector>

namespace antivirus::agent {
namespace {

std::wstring BytesToHex(const std::vector<unsigned char>& bytes) {
  static constexpr wchar_t kHexDigits[] = L"0123456789abcdef";

  std::wstring value;
  value.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    value.push_back(kHexDigits[(byte >> 4) & 0x0F]);
    value.push_back(kHexDigits[byte & 0x0F]);
  }

  return value;
}

void ThrowLastError(const char* message) {
  throw std::runtime_error(message);
}

void ThrowNtStatus(const char* message, const NTSTATUS status) {
  std::ostringstream stream;
  stream << message << " (NTSTATUS 0x" << std::hex << status << ")";
  throw std::runtime_error(stream.str());
}

std::wstring ComputeSha256Internal(const unsigned char* data, const std::size_t length, HANDLE fileHandle) {
  BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
  BCRYPT_HASH_HANDLE hashHandle = nullptr;
  std::vector<unsigned char> hashObject;
  std::vector<unsigned char> hashValue;
  std::vector<unsigned char> buffer(64 * 1024);

  try {
    const auto openStatus = BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(openStatus)) {
      ThrowNtStatus("BCryptOpenAlgorithmProvider failed", openStatus);
    }

    DWORD hashObjectLength = 0;
    DWORD hashObjectLengthResult = 0;
    const auto objectStatus =
        BCryptGetProperty(algorithmHandle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjectLength),
                          sizeof(hashObjectLength), &hashObjectLengthResult, 0);
    if (!BCRYPT_SUCCESS(objectStatus)) {
      ThrowNtStatus("BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed", objectStatus);
    }

    DWORD hashLength = 0;
    DWORD hashLengthResult = 0;
    const auto hashLengthStatus =
        BCryptGetProperty(algorithmHandle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength),
                          &hashLengthResult, 0);
    if (!BCRYPT_SUCCESS(hashLengthStatus)) {
      ThrowNtStatus("BCryptGetProperty(BCRYPT_HASH_LENGTH) failed", hashLengthStatus);
    }

    hashObject.resize(hashObjectLength);
    hashValue.resize(hashLength);

    const auto createStatus = BCryptCreateHash(algorithmHandle, &hashHandle, hashObject.data(),
                                               static_cast<ULONG>(hashObject.size()), nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(createStatus)) {
      ThrowNtStatus("BCryptCreateHash failed", createStatus);
    }

    if (fileHandle != INVALID_HANDLE_VALUE) {
      for (;;) {
        DWORD bytesRead = 0;
        if (ReadFile(fileHandle, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) == FALSE) {
          ThrowLastError("ReadFile failed while hashing a file");
        }

        if (bytesRead == 0) {
          break;
        }

        const auto hashStatus = BCryptHashData(hashHandle, buffer.data(), bytesRead, 0);
        if (!BCRYPT_SUCCESS(hashStatus)) {
          ThrowNtStatus("BCryptHashData failed", hashStatus);
        }
      }
    } else if (data != nullptr && length != 0) {
      const auto hashStatus = BCryptHashData(hashHandle, const_cast<PUCHAR>(data), static_cast<ULONG>(length), 0);
      if (!BCRYPT_SUCCESS(hashStatus)) {
        ThrowNtStatus("BCryptHashData failed", hashStatus);
      }
    }

    const auto finishStatus = BCryptFinishHash(hashHandle, hashValue.data(), static_cast<ULONG>(hashValue.size()), 0);
    if (!BCRYPT_SUCCESS(finishStatus)) {
      ThrowNtStatus("BCryptFinishHash failed", finishStatus);
    }
  } catch (...) {
    if (hashHandle != nullptr) {
      BCryptDestroyHash(hashHandle);
    }
    if (algorithmHandle != nullptr) {
      BCryptCloseAlgorithmProvider(algorithmHandle, 0);
    }
    if (fileHandle != INVALID_HANDLE_VALUE) {
      CloseHandle(fileHandle);
    }
    throw;
  }

  if (hashHandle != nullptr) {
    BCryptDestroyHash(hashHandle);
  }
  if (algorithmHandle != nullptr) {
    BCryptCloseAlgorithmProvider(algorithmHandle, 0);
  }
  if (fileHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(fileHandle);
  }

  return BytesToHex(hashValue);
}

}  // namespace

std::wstring ComputeFileSha256(const std::filesystem::path& path) {
  const auto fileHandle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (fileHandle == INVALID_HANDLE_VALUE) {
    ThrowLastError("CreateFileW failed while hashing a file");
  }

  return ComputeSha256Internal(nullptr, 0, fileHandle);
}

std::wstring ComputeBufferSha256(const unsigned char* buffer, const std::size_t length) {
  return ComputeSha256Internal(buffer, length, INVALID_HANDLE_VALUE);
}

std::wstring ComputeBufferSha256(const std::vector<unsigned char>& buffer) {
  return buffer.empty() ? ComputeBufferSha256(static_cast<const unsigned char*>(nullptr), 0)
                        : ComputeBufferSha256(buffer.data(), buffer.size());
}

bool VerifyFileAuthenticodeSignature(const std::filesystem::path& path) {
  WINTRUST_FILE_INFO fileInfo{};
  fileInfo.cbStruct = sizeof(fileInfo);
  fileInfo.pcwszFilePath = path.c_str();

  WINTRUST_DATA trustData{};
  trustData.cbStruct = sizeof(trustData);
  trustData.dwUIChoice = WTD_UI_NONE;
  trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
  trustData.dwUnionChoice = WTD_CHOICE_FILE;
  trustData.pFile = &fileInfo;
  trustData.dwStateAction = WTD_STATEACTION_VERIFY;
  trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

  GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const auto status = WinVerifyTrust(nullptr, &policyGuid, &trustData);

  trustData.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &policyGuid, &trustData);

  return status == ERROR_SUCCESS;
}

std::wstring QueryFileSignerSubject(const std::filesystem::path& path) {
  HCERTSTORE store = nullptr;
  HCRYPTMSG message = nullptr;
  PCCERT_CONTEXT certificate = nullptr;
  DWORD encoding = 0;
  DWORD contentType = 0;
  DWORD formatType = 0;

  if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                       CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType, &formatType, &store, &message,
                       nullptr) == FALSE) {
    return {};
  }

  DWORD signerInfoSize = 0;
  if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) == FALSE) {
    if (message != nullptr) {
      CryptMsgClose(message);
    }
    if (store != nullptr) {
      CertCloseStore(store, 0);
    }
    return {};
  }

  std::vector<BYTE> buffer(signerInfoSize);
  if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, buffer.data(), &signerInfoSize) == FALSE) {
    if (message != nullptr) {
      CryptMsgClose(message);
    }
    if (store != nullptr) {
      CertCloseStore(store, 0);
    }
    return {};
  }

  const auto* signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(buffer.data());
  CERT_INFO certInfo{};
  certInfo.Issuer = signerInfo->Issuer;
  certInfo.SerialNumber = signerInfo->SerialNumber;
  certificate =
      CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo,
                                 nullptr);

  std::wstring subject;
  if (certificate != nullptr) {
    const auto length = CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (length > 1) {
      subject.resize(length - 1);
      CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject.data(), length);
    }
    CertFreeCertificateContext(certificate);
  }

  if (message != nullptr) {
    CryptMsgClose(message);
  }
  if (store != nullptr) {
    CertCloseStore(store, 0);
  }

  return subject;
}

}  // namespace antivirus::agent
