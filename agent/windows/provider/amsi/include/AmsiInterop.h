#pragma once

#include <windows.h>
#include <unknwn.h>

typedef enum AMSI_RESULT {
  AMSI_RESULT_CLEAN = 0,
  AMSI_RESULT_NOT_DETECTED = 1,
  AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000,
  AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4fff,
  AMSI_RESULT_DETECTED = 32768
} AMSI_RESULT;

#define AmsiResultIsMalware(r) ((r) >= AMSI_RESULT_DETECTED)

typedef enum AMSI_ATTRIBUTE {
  AMSI_ATTRIBUTE_APP_NAME = 0,
  AMSI_ATTRIBUTE_CONTENT_NAME = 1,
  AMSI_ATTRIBUTE_CONTENT_SIZE = 2,
  AMSI_ATTRIBUTE_CONTENT_ADDRESS = 3,
  AMSI_ATTRIBUTE_SESSION = 4,
  AMSI_ATTRIBUTE_REDIRECT_CHAIN_SIZE = 5,
  AMSI_ATTRIBUTE_REDIRECT_CHAIN_ADDRESS = 6,
  AMSI_ATTRIBUTE_ALL_SIZE = 7,
  AMSI_ATTRIBUTE_ALL_ADDRESS = 8,
  AMSI_ATTRIBUTE_QUIET = 9
} AMSI_ATTRIBUTE;

struct IAmsiStream : public IUnknown {
  virtual HRESULT STDMETHODCALLTYPE GetAttribute(AMSI_ATTRIBUTE attribute, ULONG dataSize, unsigned char* data,
                                                 ULONG* retData) = 0;
  virtual HRESULT STDMETHODCALLTYPE Read(ULONGLONG position, ULONG size, unsigned char* buffer, ULONG* readSize) = 0;
};

struct IAntimalwareProvider : public IUnknown {
  virtual HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) = 0;
  virtual void STDMETHODCALLTYPE CloseSession(ULONGLONG session) = 0;
  virtual HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* displayName) = 0;
};

struct IAntimalwareProvider2 : public IAntimalwareProvider {
  virtual HRESULT STDMETHODCALLTYPE Notify(PVOID buffer, ULONG length, LPCWSTR contentName, LPCWSTR appName,
                                           AMSI_RESULT* result) = 0;
};
