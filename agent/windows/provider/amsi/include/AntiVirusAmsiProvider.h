#pragma once

#include <windows.h>

#include "AmsiInterop.h"

namespace antivirus::agent {

extern const CLSID CLSID_AntiVirusAmsiProvider;

HRESULT CreateAntiVirusAmsiProviderForTesting(HMODULE moduleHandle, IAntimalwareProvider2** provider);

}  // namespace antivirus::agent
