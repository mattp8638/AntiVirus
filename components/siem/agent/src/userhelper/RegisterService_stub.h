#pragma once
#include <string>
namespace agent_winservice {
bool RegisterService(const std::wstring&, void(*)(unsigned long, wchar_t**));
}
