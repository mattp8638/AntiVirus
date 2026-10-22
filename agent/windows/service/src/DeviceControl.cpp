#include "DeviceControl.h"

#ifdef _WIN32
#include <Windows.h>
#endif

namespace antivirus::agent::devicecontrol {
namespace {

const std::wstring kStoragePolicyRoot = L"SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices\\";

void ClassAccess(Plan& plan, const wchar_t* classGuid, const std::wstring& mode) {
  const auto key = kStoragePolicyRoot + classGuid;
  const bool denyRead = mode == L"block";
  const bool denyWrite = mode == L"block" || mode == L"read-only";
  for (const auto& [name, deny] : {std::pair{L"Deny_Read", denyRead}, std::pair{L"Deny_Write", denyWrite},
                                   std::pair{L"Deny_Execute", denyRead}}) {
    plan.ops.push_back(deny ? RegistryOp{key, name, false, 1} : RegistryOp{key, name, true, 0});
  }
}

}  // namespace

Plan BuildPlan(const DeviceControlSettings& s) {
  Plan plan;
  const bool on = s.enabled;
  const auto usb = on ? s.usbStorage : std::wstring(L"allow");
  ClassAccess(plan, kRemovableDisksClass, usb == L"audit" ? L"allow" : usb);
  // Blocking also stops the mass-storage driver loading for new devices (3 = on demand, 4 = disabled).
  plan.ops.push_back({L"SYSTEM\\CurrentControlSet\\Services\\USBSTOR", L"Start", false, usb == L"block" ? 4ul : 3ul});
  ClassAccess(plan, kCdDvdClass, on ? s.opticalMedia : L"allow");
  ClassAccess(plan, kWpdClassA, on ? s.mtpDevices : L"allow");
  ClassAccess(plan, kWpdClassB, on ? s.mtpDevices : L"allow");
  const auto fve = L"SYSTEM\\CurrentControlSet\\Policies\\Microsoft\\FVE";
  plan.ops.push_back(on && s.encryptedUsbOnly ? RegistryOp{fve, L"RDVDenyWriteAccess", false, 1}
                                              : RegistryOp{fve, L"RDVDenyWriteAccess", true, 0});

  if (on && usb == L"audit") plan.notes.push_back(L"USB audit mode records insertions only; access is not restricted.");
  if (on && !s.usbAllowedIds.empty() && usb != L"allow") {
    plan.notes.push_back(L"Per-device USB exceptions need the kernel driver; class-wide policy applies to every USB drive.");
  }
  if (on && s.bluetoothFileTransfer != L"allow") plan.notes.push_back(L"Bluetooth file transfer control is not enforced on Windows yet.");
  if (on && s.printing != L"allow") plan.notes.push_back(L"Printing control is not enforced on Windows yet.");
  plan.summary = L"usb=" + usb + L" optical=" + (on ? s.opticalMedia : L"allow") + L" mtp=" + (on ? s.mtpDevices : L"allow") +
                 L" encryptedUsbOnly=" + (on && s.encryptedUsbOnly ? L"true" : L"false");
  return plan;
}

int Apply(const Plan& plan, std::wstring* error) {
#ifdef _WIN32
  int failures = 0;
  for (const auto& op : plan.ops) {
    HKEY key = nullptr;
    if (op.remove) {
      if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, op.key.c_str(), 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) continue;
      const auto status = RegDeleteValueW(key, op.valueName.c_str());
      if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) ++failures;
      RegCloseKey(key);
      continue;
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, op.key.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
      ++failures;
      if (error != nullptr) *error = L"could not open HKLM\\" + op.key;
      continue;
    }
    const DWORD data = op.data;
    if (RegSetValueExW(key, op.valueName.c_str(), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&data), sizeof(data)) != ERROR_SUCCESS) {
      ++failures;
      if (error != nullptr) *error = L"could not set " + op.valueName;
    }
    RegCloseKey(key);
  }
  return failures;
#else
  (void)plan;
  (void)error;
  return 0;
#endif
}

}  // namespace antivirus::agent::devicecontrol
