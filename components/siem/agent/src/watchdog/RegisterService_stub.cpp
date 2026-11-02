#include <string>
namespace agent_winservice {
bool RegisterService(const std::wstring&, void(*)(unsigned long, wchar_t**)) {
    // Stub: always return true
    return true;
}
}
