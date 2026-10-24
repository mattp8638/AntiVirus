#include "AntiVirusAmsiProvider.h"

#include <windows.h>

#include <string>

namespace antivirus::agent {

HRESULT CreateAntiVirusAmsiProviderClassFactory(REFIID riid, void** object);
void SetAntiVirusAmsiProviderModuleHandle(HMODULE moduleHandle);
bool CanAntiVirusAmsiProviderUnloadNow();
std::wstring AntiVirusAmsiProviderClsidString();

namespace {

bool WriteStringValue(HKEY root, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(root, subKey.c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
    return false;
  }

  const auto dataBytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
  const auto status = RegSetValueExW(key, valueName.empty() ? nullptr : valueName.c_str(), 0, REG_SZ,
                                     reinterpret_cast<const BYTE*>(value.c_str()), dataBytes);
  RegCloseKey(key);
  return status == ERROR_SUCCESS;
}

std::wstring GetModulePath(HMODULE moduleHandle) {
  std::wstring buffer(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(moduleHandle, buffer.data(), static_cast<DWORD>(buffer.size()));
  return written == 0 ? std::wstring() : std::wstring(buffer.data(), written);
}

}  // namespace

}  // namespace antivirus::agent

// COM entry points must be global C exports, matching combaseapi.h declarations.
// MSVC exports these through AmsiExports.def: SDK declarations cannot gain dllexport.
#ifdef _MSC_VER
#define FENRIR_AMSI_COM_EXPORT
#else
#define FENRIR_AMSI_COM_EXPORT __declspec(dllexport)
#endif
using namespace antivirus::agent;

extern "C" BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
    SetAntiVirusAmsiProviderModuleHandle(instance);
  }
  return TRUE;
}

extern "C" FENRIR_AMSI_COM_EXPORT HRESULT __stdcall DllGetClassObject(REFCLSID clsid, REFIID riid, void** object) {
  if (!InlineIsEqualGUID(clsid, CLSID_AntiVirusAmsiProvider)) {
    return CLASS_E_CLASSNOTAVAILABLE;
  }

  return CreateAntiVirusAmsiProviderClassFactory(riid, object);
}

extern "C" FENRIR_AMSI_COM_EXPORT HRESULT __stdcall DllCanUnloadNow() {
  return CanAntiVirusAmsiProviderUnloadNow() ? S_OK : S_FALSE;
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllRegisterServer() {
  const auto clsidString = AntiVirusAmsiProviderClsidString();
  const auto modulePath = GetModulePath(GetModuleHandleW(L"fenrir-amsi-provider.dll"));
  if (clsidString.empty() || modulePath.empty()) {
    return E_FAIL;
  }

  const auto clsidRoot = std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + clsidString;
  if (!WriteStringValue(HKEY_LOCAL_MACHINE, clsidRoot, L"", L"AntiVirus AMSI Provider")) {
    return E_FAIL;
  }

  if (!WriteStringValue(HKEY_LOCAL_MACHINE, clsidRoot + L"\\InprocServer32", L"", modulePath)) {
    return E_FAIL;
  }

  if (!WriteStringValue(HKEY_LOCAL_MACHINE, clsidRoot + L"\\InprocServer32", L"ThreadingModel", L"Both")) {
    return E_FAIL;
  }

  if (!WriteStringValue(HKEY_LOCAL_MACHINE, std::wstring(L"SOFTWARE\\Microsoft\\AMSI\\Providers\\") + clsidString, L"",
                        L"AntiVirus AMSI Provider")) {
    return E_FAIL;
  }

  return S_OK;
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllUnregisterServer() {
  const auto clsidString = AntiVirusAmsiProviderClsidString();
  if (clsidString.empty()) {
    return E_FAIL;
  }

  RegDeleteTreeW(HKEY_LOCAL_MACHINE, (std::wstring(L"SOFTWARE\\Microsoft\\AMSI\\Providers\\") + clsidString).c_str());
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, (std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + clsidString).c_str());
  return S_OK;
}

