#include "CrashReporter.h"

#include <windows.h>

#include <cstdio>
#include <exception>
#include <fstream>
#include <sstream>

#include "BuildInfo.h"

namespace antivirus::agent::crash {

namespace {

wchar_t g_reportPath[MAX_PATH * 2]{};

// Everything below runs inside a crashed process: no heap allocation, no C++ streams, only stack buffers.
void AppendFrame(wchar_t* out, std::size_t capacity, const DWORD64 address) {
  HMODULE module = nullptr;
  wchar_t name[MAX_PATH]{};
  wchar_t frame[MAX_PATH + 64]{};
  if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCWSTR>(address), &module) &&
      GetModuleFileNameW(module, name, MAX_PATH) > 0) {
    const wchar_t* base = wcsrchr(name, L'\\');
    swprintf_s(frame, L"%s+0x%llx", base ? base + 1 : name,
               static_cast<unsigned long long>(address - reinterpret_cast<DWORD64>(module)));
  } else {
    swprintf_s(frame, L"0x%llx", static_cast<unsigned long long>(address));
  }
  if (out[0] != L'\0') wcscat_s(out, capacity, L" < ");
  wcscat_s(out, capacity, frame);
}

void WriteReport(const wchar_t* text) {
  if (g_reportPath[0] == L'\0') return;
  const HANDLE file = CreateFileW(g_reportPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return;
  DWORD written = 0;
  WriteFile(file, text, static_cast<DWORD>(wcslen(text) * sizeof(wchar_t)), &written, nullptr);
  CloseHandle(file);
}

LONG WINAPI OnUnhandledException(EXCEPTION_POINTERS* pointers) {
  static volatile LONG entered = 0;
  if (InterlockedExchange(&entered, 1) != 0 || pointers == nullptr || pointers->ExceptionRecord == nullptr) {
    return EXCEPTION_CONTINUE_SEARCH;
  }
  wchar_t stack[2048]{};
#if defined(_M_X64) || defined(__x86_64__)
  if (pointers->ContextRecord != nullptr) {
    CONTEXT context = *pointers->ContextRecord;
    for (int depth = 0; depth < 16 && context.Rip != 0; ++depth) {
      AppendFrame(stack, std::size(stack), context.Rip);
      DWORD64 imageBase = 0;
      const auto* function = RtlLookupFunctionEntry(context.Rip, &imageBase, nullptr);
      if (function == nullptr) {
        // Leaf function: the return address is on top of the stack.
        if (IsBadReadPtr(reinterpret_cast<void*>(context.Rsp), sizeof(DWORD64))) break;
        context.Rip = *reinterpret_cast<DWORD64*>(context.Rsp);
        context.Rsp += sizeof(DWORD64);
        continue;
      }
      PVOID handlerData = nullptr;
      DWORD64 establisher = 0;
      RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, context.Rip, const_cast<PRUNTIME_FUNCTION>(function), &context,
                       &handlerData, &establisher, nullptr);
    }
  }
#else
  AppendFrame(stack, std::size(stack), reinterpret_cast<DWORD64>(pointers->ExceptionRecord->ExceptionAddress));
#endif
  const auto* record = pointers->ExceptionRecord;
  wchar_t text[3072]{};
  swprintf_s(text, L"code=0x%08lx;thread=%lu;build=%s;stack=%s", static_cast<unsigned long>(record->ExceptionCode),
             GetCurrentThreadId(), kFenrirBuildId, stack);
  WriteReport(text);
  return EXCEPTION_CONTINUE_SEARCH;  // let Windows Error Reporting and the service recovery carry on
}

void OnTerminate() {
  wchar_t text[256]{};
  swprintf_s(text, L"code=std::terminate;thread=%lu;build=%s;stack=", GetCurrentThreadId(), kFenrirBuildId);
  WriteReport(text);
  std::abort();
}

std::wstring Escape(const std::wstring& value) {
  std::wstring out;
  for (const auto c : value) {
    if (c == L'"' || c == L'\\') out += L'\\';
    if (c < 0x20) continue;
    out += c;
  }
  return out;
}

}  // namespace

void Install() {
  wchar_t module[MAX_PATH * 2]{};
  if (GetModuleFileNameW(nullptr, module, MAX_PATH * 2) == 0) return;
  if (auto* slash = wcsrchr(module, L'\\')) *slash = L'\0';
  std::wstring folder = std::wstring(module) + L"\\runtime";
  CreateDirectoryW(folder.c_str(), nullptr);
  swprintf_s(g_reportPath, L"%s\\crash-last.txt", folder.c_str());
  SetUnhandledExceptionFilter(&OnUnhandledException);
  std::set_terminate(&OnTerminate);
}

std::wstring TakeLastReport() {
  if (g_reportPath[0] == L'\0') return {};
  const HANDLE file = CreateFileW(g_reportPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
  if (file == INVALID_HANDLE_VALUE) return {};
  wchar_t buffer[3072]{};
  DWORD read = 0;
  ReadFile(file, buffer, sizeof(buffer) - sizeof(wchar_t), &read, nullptr);
  CloseHandle(file);
  DeleteFileW(g_reportPath);
  std::wstring text(buffer, read / sizeof(wchar_t));
  std::wstring json = L"{";
  std::wstringstream parts(text);
  bool first = true;
  for (std::wstring field; std::getline(parts, field, L';');) {
    const auto equals = field.find(L'=');
    if (equals == std::wstring::npos) continue;
    json += (first ? L"" : L",") + std::wstring(L"\"") + Escape(field.substr(0, equals)) + L"\":\"" + Escape(field.substr(equals + 1)) + L"\"";
    first = false;
  }
  return first ? std::wstring{} : json + L"}";
}

}  // namespace antivirus::agent::crash
