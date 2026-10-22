#pragma once

// Device control without a kernel driver, using documented Windows policies:
//  - Removable Storage Access (HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{class}\Deny_*)
//  - USBSTOR service start type (blocks the USB mass-storage driver)
//  - BitLocker To Go "deny write to unprotected removable drives" (FVE\RDVDenyWriteAccess)
// Plan() is pure and unit-tested; Apply() writes the registry on Windows.

#include <string>
#include <vector>

#include "ExtendedPolicy.h"

namespace antivirus::agent::devicecontrol {

struct RegistryOp {
  std::wstring key;        // under HKEY_LOCAL_MACHINE
  std::wstring valueName;
  bool remove{false};      // delete the value instead of setting it
  unsigned long data{0};   // REG_DWORD
};

struct Plan {
  std::vector<RegistryOp> ops;
  std::vector<std::wstring> notes;  // settings that cannot be enforced this way
  std::wstring summary;
};

constexpr const wchar_t* kRemovableDisksClass = L"{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";
constexpr const wchar_t* kCdDvdClass = L"{53f56308-b6bf-11d0-94f2-00a0c91efb8b}";
constexpr const wchar_t* kWpdClassA = L"{6AC27878-A6FA-4155-BA85-F98F491D4F33}";
constexpr const wchar_t* kWpdClassB = L"{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}";

Plan BuildPlan(const DeviceControlSettings& settings);

// Applies the plan on Windows. Returns the number of failed operations (0 elsewhere is a no-op).
int Apply(const Plan& plan, std::wstring* error);

}  // namespace antivirus::agent::devicecontrol
