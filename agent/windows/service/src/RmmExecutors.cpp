#include "RmmExecutors.h"

#include <windows.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <urlmon.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <thread>

#include "CryptoUtils.h"
#include "WingetSupport.h"
#include "ExtendedPolicy.h"
#include "StringUtils.h"

#ifndef SERVICE_CONFIG_TRIGGER_INFO
#define SERVICE_CONFIG_TRIGGER_INFO 8
#endif

namespace antivirus::agent::rmm {
namespace {

std::string Q(const std::string& utf8) { return "\"" + EscapeJsonString(Utf8ToWide(utf8)) + "\""; }
std::string Q(const std::wstring& wide) { return "\"" + EscapeJsonString(wide) + "\""; }

json::Value ParsePayload(const std::wstring& payloadJson) {
  auto parsed = json::Parse(WideToUtf8(payloadJson));
  if (!parsed || !parsed->IsObject()) {
    throw std::runtime_error("The command payload is not valid JSON");
  }
  return *parsed;
}

std::string Str(const json::Value& root, const char* key, const std::string& fallback = "") {
  const auto* value = root.Get(key);
  return value && value->String() ? *value->String() : fallback;
}

double Num(const json::Value& root, const char* key, double fallback) {
  const auto* value = root.Get(key);
  return value && value->Number() ? *value->Number() : fallback;
}

// Read one pipe into a capped buffer on a worker thread, so stdout and stderr cannot deadlock each other.
void Drain(HANDLE pipe, std::string* out, std::size_t cap, std::size_t* dropped) {
  std::array<char, 8192> buffer{};
  DWORD read = 0;
  while (ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) != FALSE && read > 0) {
    const auto room = cap > out->size() ? cap - out->size() : 0;
    out->append(buffer.data(), std::min<std::size_t>(room, read));
    if (read > room) {
      *dropped += read - room;
    }
  }
}

std::vector<wchar_t> BuildEnvironment(const std::vector<std::pair<std::wstring, std::wstring>>& extra, void* baseBlock) {
  std::vector<std::wstring> entries;
  const auto* cursor = static_cast<const wchar_t*>(baseBlock);
  wchar_t* ownBlock = nullptr;
  if (cursor == nullptr) {
    ownBlock = GetEnvironmentStringsW();
    cursor = ownBlock;
  }
  for (; cursor && *cursor; cursor += wcslen(cursor) + 1) {
    entries.emplace_back(cursor);
  }
  if (ownBlock) {
    FreeEnvironmentStringsW(ownBlock);
  }
  for (const auto& [name, value] : extra) {
    const auto prefix = name + L"=";
    entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const std::wstring& e) { return _wcsnicmp(e.c_str(), prefix.c_str(), prefix.size()) == 0; }),
                  entries.end());
    entries.push_back(prefix + value);
  }
  std::sort(entries.begin(), entries.end(), [](const std::wstring& a, const std::wstring& b) { return _wcsicmp(a.c_str(), b.c_str()) < 0; });
  std::vector<wchar_t> block;
  for (const auto& entry : entries) {
    block.insert(block.end(), entry.begin(), entry.end());
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  return block;
}

HANDLE ActiveUserToken() {
  const auto session = WTSGetActiveConsoleSessionId();
  HANDLE token = nullptr;
  if (session == 0xFFFFFFFF || WTSQueryUserToken(session, &token) == FALSE) {
    return nullptr;
  }
  return token;
}

ProcessResult RunProcessAs(const std::wstring& commandLine, const std::wstring& workingDirectory,
                           const std::vector<std::pair<std::wstring, std::wstring>>& extraEnvironment, unsigned long timeoutMs,
                           std::size_t maxOutputBytes, HANDLE userToken) {
  SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
  HANDLE outRead = nullptr, outWrite = nullptr, errRead = nullptr, errWrite = nullptr;
  if (!CreatePipe(&outRead, &outWrite, &inherit, 0) || !CreatePipe(&errRead, &errWrite, &inherit, 0)) {
    throw std::runtime_error("CreatePipe failed");
  }
  SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);
  HANDLE nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr);

  void* userEnvironment = nullptr;
  if (userToken) {
    CreateEnvironmentBlock(&userEnvironment, userToken, FALSE);
  }
  auto environment = BuildEnvironment(extraEnvironment, userEnvironment);
  if (userEnvironment) {
    DestroyEnvironmentBlock(userEnvironment);
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  startup.wShowWindow = SW_HIDE;
  startup.hStdInput = nul;
  startup.hStdOutput = outWrite;
  startup.hStdError = errWrite;
  wchar_t desktop[] = L"winsta0\\default";
  if (userToken) {
    startup.lpDesktop = desktop;
  }
  std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
  mutableCommand.push_back(L'\0');

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));

  PROCESS_INFORMATION process{};
  const DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;
  const auto started = std::chrono::steady_clock::now();
  BOOL created = userToken
                     ? CreateProcessAsUserW(userToken, nullptr, mutableCommand.data(), nullptr, nullptr, TRUE, flags, environment.data(),
                                            workingDirectory.empty() ? nullptr : workingDirectory.c_str(), &startup, &process)
                     : CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE, flags, environment.data(),
                                      workingDirectory.empty() ? nullptr : workingDirectory.c_str(), &startup, &process);
  CloseHandle(outWrite);
  CloseHandle(errWrite);
  CloseHandle(nul);
  if (!created) {
    const auto error = GetLastError();
    CloseHandle(outRead);
    CloseHandle(errRead);
    CloseHandle(job);
    throw std::runtime_error("Could not start the process (error " + std::to_string(error) + ")");
  }
  AssignProcessToJobObject(job, process.hProcess);
  ResumeThread(process.hThread);

  ProcessResult result;
  std::size_t droppedOut = 0, droppedErr = 0;
  std::thread outThread(Drain, outRead, &result.stdoutText, maxOutputBytes, &droppedOut);
  std::thread errThread(Drain, errRead, &result.stderrText, maxOutputBytes, &droppedErr);
  if (WaitForSingleObject(process.hProcess, timeoutMs) == WAIT_TIMEOUT) {
    result.timedOut = true;
    TerminateJobObject(job, 1);
    WaitForSingleObject(process.hProcess, 5000);
  }
  // Closing the job kills anything the script left running, which also closes the pipes.
  CloseHandle(job);
  outThread.join();
  errThread.join();
  GetExitCodeProcess(process.hProcess, &result.exitCode);
  result.durationMs = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count());
  if (droppedOut) {
    result.stdoutText += "\n... " + std::to_string(droppedOut) + " more bytes not shown";
  }
  if (droppedErr) {
    result.stderrText += "\n... " + std::to_string(droppedErr) + " more bytes not shown";
  }
  CloseHandle(outRead);
  CloseHandle(errRead);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return result;
}

std::wstring SystemPath(const wchar_t* leaf) {
  wchar_t directory[MAX_PATH]{};
  GetSystemDirectoryW(directory, MAX_PATH);
  return std::wstring(directory) + L"\\" + leaf;
}

std::wstring PowerShellCommand(const std::filesystem::path& script) {
  return L"\"" + SystemPath(L"WindowsPowerShell\\v1.0\\powershell.exe") + L"\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
         script.wstring() + L"\"";
}

std::filesystem::path WriteScript(const std::filesystem::path& root, const std::string& body, const wchar_t* extension, bool bom) {
  std::error_code ec;
  std::filesystem::create_directories(root, ec);
  const auto path = root / (L"run-" + GenerateGuidString() + extension);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (bom) {
    out << "\xEF\xBB\xBF";  // PowerShell 5 reads BOM-less files as ANSI
  }
  out << body;
  out.close();
  if (!out) {
    throw std::runtime_error("Could not write the script file");
  }
  return path;
}

std::wstring FindWinget() { return winget::FindExecutable(); }

std::string ResultJson(const ProcessResult& r) {
  std::ostringstream out;
  out << "{\"exitCode\":" << static_cast<long>(r.exitCode) << ",\"durationMs\":" << r.durationMs << ",\"timedOut\":" << (r.timedOut ? "true" : "false")
      << ",\"stdout\":" << Q(r.stdoutText) << ",\"stderr\":" << Q(r.stderrText) << "}";
  return out.str();
}

std::string LastLines(const std::string& text, int count) {
  std::vector<std::string> lines;
  std::istringstream in(text);
  for (std::string line; std::getline(in, line);) {
    if (!TrimCopy(line).empty()) {
      lines.push_back(TrimCopy(line));
    }
  }
  std::string out;
  for (std::size_t i = lines.size() > static_cast<std::size_t>(count) ? lines.size() - count : 0; i < lines.size(); ++i) {
    out += (out.empty() ? "" : "\n") + lines[i];
  }
  return out;
}

bool RegistryKeyExists(const wchar_t* path) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS) {
    RegCloseKey(key);
    return true;
  }
  return false;
}

std::wstring RegistryString(const wchar_t* path, const wchar_t* value) {
  wchar_t buffer[512]{};
  DWORD size = sizeof(buffer);
  if (RegGetValueW(HKEY_LOCAL_MACHINE, path, value, RRF_RT_REG_SZ, nullptr, buffer, &size) == ERROR_SUCCESS) {
    return buffer;
  }
  return L"";
}

bool RebootPending() {
  if (RegistryKeyExists(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending") ||
      RegistryKeyExists(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired")) {
    return true;
  }
  DWORD size = 0;
  return RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"PendingFileRenameOperations",
                      RRF_RT_REG_MULTI_SZ, nullptr, nullptr, &size) == ERROR_SUCCESS && size > 4;
}

std::uint64_t FileTimeValue(const FILETIME& ft) { return (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime; }

const char kPatchScanScript[] = R"PS(
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1's ConvertTo-Json throws "Argument types do not match" on some objects
# (lists of custom objects built from COM data), so the output JSON is written by hand.
function J($v) {
  if ($null -eq $v) { return 'null' }
  if ($v -is [bool]) { if ($v) { return 'true' } else { return 'false' } }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('"')
  foreach ($ch in ([string]$v).ToCharArray()) {
    $code = [int]$ch
    if ($code -eq 34) { [void]$sb.Append('\"') }
    elseif ($code -eq 92) { [void]$sb.Append('\\') }
    elseif ($code -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
    else { [void]$sb.Append($ch) }
  }
  [void]$sb.Append('"')
  return $sb.ToString()
}
function O($h) { return '{' + ((@($h.Keys) | ForEach-Object { (J ([string]$_)) + ':' + (J $h[$_]) }) -join ',') + '}' }
$patches = New-Object System.Collections.ArrayList
$wuOk = $false; $wuError = ''; $wgOk = $false; $wgError = 'WinGet/App Installer is unavailable to the service'
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $found = $searcher.Search("IsInstalled=0 and IsHidden=0")
  foreach ($u in $found.Updates) {
    $kb = $u.KBArticleIDs | Select-Object -First 1
    $id = if ($kb) { "KB$kb" } else { $u.Identity.UpdateID }
    $cats = ($u.Categories | ForEach-Object { $_.Name }) -join ', '
    $released = ''
    try { $released = $u.LastDeploymentChangeTime.ToUniversalTime().ToString('o') } catch { }
    [void]$patches.Add((O ([ordered]@{ id = [string]$id; title = [string]$u.Title; classification = [string]$cats;
      severity = [string]$u.MsrcSeverity; source = 'windows-update'; rebootRequired = [bool]$u.RebootRequired;
      releasedAt = [string]$released; cves = [string](@($u.CveIDs) -join ',') })))
  }
  $wuOk = $true
} catch { $wuError = [string]$_; [Console]::Error.WriteLine("Windows Update search failed: $_") }
$winget = $env:FENRIR_WINGET
if ($winget -and (Test-Path $winget)) {
  try {
  $inventory = @(& $winget list --source winget --accept-source-agreements --disable-interactivity 2>&1)
  $inventoryCode = [uint32]([int64]$LASTEXITCODE -band 4294967295L)
  if ($inventoryCode -ne 0) { throw (('WinGet cannot inspect installed packages (0x{0:X8}): ' -f $inventoryCode) + ($inventory -join ' ')) }
  $lines = @(& $winget list --upgrade-available --source winget --accept-source-agreements --disable-interactivity 2>&1)
  $scanCode = [uint32]([int64]$LASTEXITCODE -band 4294967295L)
  if ($scanCode -ne 0 -and $scanCode -ne 0x8A150014 -and $scanCode -ne 0x8A15002B) { throw (('WinGet scan failed (0x{0:X8}): ' -f $scanCode) + ($lines -join ' ')) }
  $matched = 0
  foreach ($line in $lines) {
    # Match data rows, not translated column headings or status messages.
    if ($line -match '^\s*(?<name>.+?)\s+(?<id>[A-Za-z0-9][A-Za-z0-9+_-]*\.[A-Za-z0-9.+_-]+)\s+(?<installed>\S+)\s+(?<available>\S+)(?:\s+winget)?\s*$') {
      $pkg = $Matches.id; $name = $Matches.name.Trim(); $installed = $Matches.installed; $available = $Matches.available
      if ($available -ne 'winget') { $matched++; [void]$patches.Add((O ([ordered]@{ id = "winget:$pkg"; title = "$name $installed -> $available"; source = 'winget';
        product = $name; installedVersion = $installed; availableVersion = $available; classification = 'third-party' }))) }
    }
  }
  if ($scanCode -eq 0 -and $matched -eq 0) { throw 'WinGet returned an unreadable update table; coverage is unknown' }
  $wgOk = $true; $wgError = ''
  } catch { $wgError = [string]$_ }
}
[Console]::Out.Write('{"patches":[' + ($patches -join ',') + '],"coverage":{"windows-update":' +
  (O ([ordered]@{success=[bool]$wuOk;error=[string]$wuError})) + ',"winget":' +
  (O ([ordered]@{success=[bool]$wgOk;error=[string]$wgError})) + '}}')
)PS";

const char kPatchInstallScript[] = R"PS(
$ErrorActionPreference = 'Continue'
# Windows PowerShell 5.1's ConvertTo-Json throws "Argument types do not match" on some objects
# (lists of custom objects built from COM data), so the output JSON is written by hand.
function J($v) {
  if ($null -eq $v) { return 'null' }
  if ($v -is [bool]) { if ($v) { return 'true' } else { return 'false' } }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('"')
  foreach ($ch in ([string]$v).ToCharArray()) {
    $code = [int]$ch
    if ($code -eq 34) { [void]$sb.Append('\"') }
    elseif ($code -eq 92) { [void]$sb.Append('\\') }
    elseif ($code -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
    else { [void]$sb.Append($ch) }
  }
  [void]$sb.Append('"')
  return $sb.ToString()
}
function O($h) { return '{' + ((@($h.Keys) | ForEach-Object { (J ([string]$_)) + ':' + (J $h[$_]) }) -join ',') + '}' }
$ids = @($env:FENRIR_PATCH_IDS -split ',' | Where-Object { $_ })
$results = New-Object System.Collections.ArrayList
$done = @{}
function Add-Result($id, $ok, $err) {
  $done[[string]$id] = $true
  [void]$results.Add((O ([ordered]@{ id = [string]$id; success = [bool]$ok; error = [string]$err })))
}
$rebootRequired = $false
$wu = @($ids | Where-Object { $_ -notlike 'winget:*' })
$wg = @($ids | Where-Object { $_ -like 'winget:*' } | ForEach-Object { $_.Substring(7) })
if ($wu.Count -gt 0) {
  try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $found = $searcher.Search("IsInstalled=0 and IsHidden=0")
    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    $names = @{}
    foreach ($u in $found.Updates) {
      $kb = $u.KBArticleIDs | Select-Object -First 1
      $id = if ($kb) { "KB$kb" } else { $u.Identity.UpdateID }
      if ($wu -contains $id -or $wu -contains $u.Identity.UpdateID) {
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        $names[$coll.Add($u)] = $id
      }
    }
    if ($coll.Count -gt 0) {
      $downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $coll; [void]$downloader.Download()
      $installer = $session.CreateUpdateInstaller(); $installer.Updates = $coll; $outcome = $installer.Install()
      $rebootRequired = [bool]$outcome.RebootRequired
      for ($i = 0; $i -lt $coll.Count; $i++) {
        $r = $outcome.GetUpdateResult($i)
        $ok = ($r.ResultCode -eq 2 -or $r.ResultCode -eq 3)
        $err = ''
        if (-not $ok) { $err = 'Windows Update result {0}, HRESULT 0x{1:X8}' -f $r.ResultCode, $r.HResult }
        Add-Result $names[$i] $ok $err
      }
    }
    foreach ($id in $wu) {
      if (-not $done.ContainsKey([string]$id)) { Add-Result $id $true 'already installed or superseded' }
    }
  } catch {
    $failure = "$_"
    foreach ($id in $wu) { if (-not $done.ContainsKey([string]$id)) { Add-Result $id $false $failure } }
  }
}
$winget = $env:FENRIR_WINGET
foreach ($pkg in $wg) {
  if (-not $winget -or -not (Test-Path $winget)) { Add-Result "winget:$pkg" $false 'WinGet/App Installer is unavailable to the service'; continue }
  $LASTEXITCODE = $null
  $output = ''
  $output = (& $winget upgrade --id $pkg --exact --source winget --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-String)
  $output = [string]$output
  if ($null -eq $LASTEXITCODE) { Add-Result "winget:$pkg" $false ('WinGet could not start: ' + $output.Trim()); continue }
  $code = [uint32]([int64]$LASTEXITCODE -band 4294967295L)
  $ok = $code -eq 0 -or $code -eq 0x8A15002B -or $code -eq 3010 -or $code -eq 1641
  if ($code -eq 3010 -or $code -eq 1641) { $rebootRequired = $true }
  $err = ''
  if (-not $ok) { $err = ('WinGet failed (0x{0:X8}): ' -f $code) + $output.Trim() }
  Add-Result "winget:$pkg" $ok $err
}
[Console]::Out.Write('{"results":[' + ($results -join ',') + '],"rebootRequired":' + (J ([bool]$rebootRequired)) + '}')
)PS";

std::string ScheduleReboot(const json::Value& payload, bool rebootRequired) {
  const auto* reboot = payload.Get("reboot");
  const auto mode = reboot ? Str(*reboot, "mode", "if_required") : "if_required";
  if (mode == "never" || (mode == "if_required" && !rebootRequired)) {
    return "";
  }
  const int minutes = static_cast<int>(std::clamp(reboot ? Num(*reboot, "deferMinutes", 5) : 5, 1.0, 1440.0));
  const auto command = L"\"" + SystemPath(L"shutdown.exe") + L"\" /r /t " + std::to_wstring(minutes * 60) +
                       L" /d p:2:17 /c \"Your IT provider is restarting this computer to finish installing updates. Save your work.\"";
  RunProcess(command, L"", {}, 30000);
  return ",\"rebootScheduledInMinutes\":" + std::to_string(minutes);
}

}  // namespace

std::string QuotePowerShell(const std::string& value) {
  std::string out = "'";
  for (const char c : value) {
    out += c;
    if (c == '\'') {
      out += '\'';
    }
  }
  return out + "'";
}

bool IsSafePackageId(const std::string& value) {
  static const std::regex pattern(R"(^[A-Za-z0-9][A-Za-z0-9.+_@-]{0,199}$)");
  return std::regex_match(value, pattern);
}

ProcessResult RunProcess(const std::wstring& commandLine, const std::wstring& workingDirectory,
                         const std::vector<std::pair<std::wstring, std::wstring>>& extraEnvironment, unsigned long timeoutMs,
                         std::size_t maxOutputBytes) {
  return RunProcessAs(commandLine, workingDirectory, extraEnvironment, timeoutMs, maxOutputBytes, nullptr);
}

std::string RunScript(const std::wstring& payloadJson, const std::filesystem::path& workRoot) {
  const auto payload = ParsePayload(payloadJson);
  const auto language = Str(payload, "language");
  const auto body = Str(payload, "body");
  if (body.empty()) {
    throw std::runtime_error("The script is empty");
  }
  const auto timeoutSeconds = std::clamp(Num(payload, "timeoutSeconds", 600), 10.0, 86400.0);
  std::vector<std::pair<std::wstring, std::wstring>> environment{{L"FENRIR_SCRIPT", Utf8ToWide(Str(payload, "scriptName"))}};
  if (const auto* env = payload.Get("environment"); env && env->IsObject()) {
    static const std::regex name(R"(^[A-Za-z_][A-Za-z0-9_]{0,63}$)");
    for (const auto& [key, value] : std::get<json::Object>(env->v)) {
      if (std::regex_match(key, name) && value.String()) {
        environment.emplace_back(Utf8ToWide(key), Utf8ToWide(*value.String()));
      }
    }
  }
  const auto root = workRoot / L"scripts";
  std::filesystem::path file;
  std::wstring command;
  if (language == "powershell") {
    file = WriteScript(root, body, L".ps1", true);
    command = PowerShellCommand(file);
  } else if (language == "cmd") {
    file = WriteScript(root, body, L".cmd", false);
    command = L"\"" + SystemPath(L"cmd.exe") + L"\" /d /c \"\"" + file.wstring() + L"\"\"";
  } else if (language == "python") {
    file = WriteScript(root, body, L".py", false);
    command = L"py.exe -3 \"" + file.wstring() + L"\"";
  } else {
    throw std::runtime_error(language + " scripts cannot run on Windows");
  }
  HANDLE userToken = nullptr;
  if (Str(payload, "runAs") == "user") {
    userToken = ActiveUserToken();
    if (userToken == nullptr) {
      std::error_code ec;
      std::filesystem::remove(file, ec);
      throw std::runtime_error("Nobody is signed in, so the script cannot run as the user");
    }
  }
  ProcessResult result;
  try {
    result = RunProcessAs(command, root.wstring(), environment, static_cast<unsigned long>(timeoutSeconds * 1000), 64 * 1024, userToken);
  } catch (...) {
    if (userToken) {
      CloseHandle(userToken);
    }
    std::error_code ec;
    std::filesystem::remove(file, ec);
    throw;
  }
  if (userToken) {
    CloseHandle(userToken);
  }
  std::error_code ec;
  std::filesystem::remove(file, ec);
  const auto json = ResultJson(result);
  if (result.timedOut) {
    throw CommandFailed("The script timed out", json);
  }
  if (result.exitCode != 0) {
    throw CommandFailed("The script exited with code " + std::to_string(static_cast<long>(result.exitCode)), json);
  }
  return json;
}

std::string CollectHealthMetricsJson() {
  static std::mutex mutex;
  static std::uint64_t lastIdle = 0, lastTotal = 0;
  std::ostringstream out;
  out << "{\"remoteCapabilities\":[\"desktop\",\"terminal\",\"files\",\"processes\",\"services\",\"chat\",\"cad\"]";
  FILETIME idle{}, kernel{}, user{};
  if (GetSystemTimes(&idle, &kernel, &user)) {
    const auto idleValue = FileTimeValue(idle), total = FileTimeValue(kernel) + FileTimeValue(user);
    std::lock_guard lock(mutex);
    if (lastTotal && total > lastTotal) {
      const double busy = 100.0 * (1.0 - static_cast<double>(idleValue - lastIdle) / static_cast<double>(total - lastTotal));
      out << ",\"cpuPercent\":" << std::clamp(busy, 0.0, 100.0);
    }
    lastIdle = idleValue;
    lastTotal = total;
  }
  MEMORYSTATUSEX memory{};
  memory.dwLength = sizeof(memory);
  if (GlobalMemoryStatusEx(&memory)) {
    out << ",\"memoryPercent\":" << memory.dwMemoryLoad << ",\"memoryTotalGb\":" << static_cast<double>(memory.ullTotalPhys) / (1ull << 30);
  }
  out << ",\"uptimeSeconds\":" << GetTickCount64() / 1000;
  out << ",\"disks\":[";
  wchar_t drives[512]{};
  bool first = true;
  if (GetLogicalDriveStringsW(511, drives)) {
    for (const wchar_t* drive = drives; *drive; drive += wcslen(drive) + 1) {
      if (GetDriveTypeW(drive) != DRIVE_FIXED) {
        continue;
      }
      ULARGE_INTEGER available{}, total{}, free{};
      if (!GetDiskFreeSpaceExW(drive, &available, &total, &free) || total.QuadPart == 0) {
        continue;
      }
      std::wstring mount(drive);
      if (mount.size() > 2 && mount.back() == L'\\') {
        mount.pop_back();
      }
      out << (first ? "" : ",") << "{\"mount\":" << Q(mount) << ",\"totalGb\":" << static_cast<double>(total.QuadPart) / (1ull << 30)
          << ",\"freeGb\":" << static_cast<double>(available.QuadPart) / (1ull << 30)
          << ",\"freePercent\":" << 100.0 * static_cast<double>(available.QuadPart) / static_cast<double>(total.QuadPart) << "}";
      first = false;
    }
  }
  out << "]";
  const auto session = WTSGetActiveConsoleSessionId();
  LPWSTR name = nullptr, domain = nullptr;
  DWORD bytes = 0;
  if (session != 0xFFFFFFFF && WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSUserName, &name, &bytes) && name && *name) {
    std::wstring account = name;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSDomainName, &domain, &bytes) && domain && *domain) {
      account = std::wstring(domain) + L"\\" + account;
    }
    out << ",\"loggedOnUser\":" << Q(account);
  }
  if (name) {
    WTSFreeMemory(name);
  }
  if (domain) {
    WTSFreeMemory(domain);
  }
  out << ",\"rebootPending\":" << (RebootPending() ? "true" : "false");
  const auto manufacturer = RegistryString(L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer");
  const auto model = RegistryString(L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
  if (!manufacturer.empty()) {
    out << ",\"manufacturer\":" << Q(manufacturer);
  }
  if (!model.empty()) {
    out << ",\"model\":" << Q(model);
  }
  // Automatic services that are not running (trigger-start and delayed services are expected to stop).
  out << ",\"stoppedServices\":[";
  if (SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE)) {
    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_INACTIVE, nullptr, 0, &needed, &count, &resume, nullptr);
    std::vector<BYTE> buffer(needed + 1024);
    first = true;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_INACTIVE, buffer.data(), static_cast<DWORD>(buffer.size()),
                              &needed, &count, &resume, nullptr)) {
      const auto* services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
      for (DWORD i = 0; i < count; ++i) {
        SC_HANDLE service = OpenServiceW(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!service) {
          continue;
        }
        std::vector<BYTE> config(8192);
        DWORD size = 0;
        bool automatic = false, delayed = false, triggered = false;
        if (QueryServiceConfigW(service, reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data()), static_cast<DWORD>(config.size()), &size)) {
          automatic = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data())->dwStartType == SERVICE_AUTO_START;
        }
        SERVICE_DELAYED_AUTO_START_INFO delayInfo{};
        if (QueryServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, reinterpret_cast<BYTE*>(&delayInfo), sizeof(delayInfo), &size)) {
          delayed = delayInfo.fDelayedAutostart != FALSE;
        }
        std::vector<BYTE> trigger(4096);
        if (QueryServiceConfig2W(service, SERVICE_CONFIG_TRIGGER_INFO, trigger.data(), static_cast<DWORD>(trigger.size()), &size)) {
          triggered = *reinterpret_cast<const DWORD*>(trigger.data()) > 0;  // SERVICE_TRIGGER_INFO::cTriggers
        }
        CloseServiceHandle(service);
        if (automatic && !delayed && !triggered) {
          out << (first ? "" : ",") << Q(std::wstring(services[i].lpServiceName));
          first = false;
        }
      }
    }
    CloseServiceHandle(scm);
  }
  out << "],\"processNames\":[";
  std::set<std::wstring> names;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry)) {
      names.insert(entry.szExeFile);
    }
    CloseHandle(snapshot);
  }
  first = true;
  std::size_t written = 0;
  for (const auto& n : names) {
    if (++written > 400) {
      break;
    }
    out << (first ? "" : ",") << Q(n);
    first = false;
  }
  out << "]}";
  return out.str();
}

std::string PatchScan(const std::filesystem::path& workRoot) {
  const auto file = WriteScript(workRoot / L"patching", kPatchScanScript, L".ps1", true);
  const auto result = RunProcess(PowerShellCommand(file), (workRoot / L"patching").wstring(), {{L"FENRIR_WINGET", FindWinget()}}, 30 * 60 * 1000,
                                 8 * 1024 * 1024);
  std::error_code ec;
  std::filesystem::remove(file, ec);
  const auto parsed = json::Parse(result.stdoutText);
  if (result.timedOut || result.exitCode != 0 || !parsed || !parsed->IsObject()) {
    throw CommandFailed("The patch scan did not complete successfully", ResultJson(result));
  }
  // Re-emit with the reboot state appended so the cloud can show "restart pending".
  auto body = result.stdoutText;
  body.pop_back();
  return body + ",\"rebootPending\":" + (RebootPending() ? "true" : "false") + ",\"stderr\":" + Q(LastLines(result.stderrText, 5)) + "}";
}

std::string PatchInstall(const std::wstring& payloadJson, const std::filesystem::path& workRoot) {
  const auto payload = ParsePayload(payloadJson);
  std::string ids;
  static const std::regex allowed(R"(^(KB\d{4,10}|[0-9a-fA-F-]{36}|winget:[A-Za-z0-9][A-Za-z0-9.+_-]{0,199})$)");
  if (const auto* list = payload.Get("patchIds")) {
    for (const auto& id : list->Strings()) {
      if (std::regex_match(id, allowed)) {
        ids += (ids.empty() ? "" : ",") + id;
      }
    }
  }
  if (ids.empty()) {
    return "{\"results\":[],\"rebootRequired\":false}";
  }
  const auto file = WriteScript(workRoot / L"patching", kPatchInstallScript, L".ps1", true);
  const auto result = RunProcess(PowerShellCommand(file), (workRoot / L"patching").wstring(),
                                 {{L"FENRIR_PATCH_IDS", Utf8ToWide(ids)}, {L"FENRIR_WINGET", FindWinget()}}, 3 * 60 * 60 * 1000, 4 * 1024 * 1024);
  std::error_code ec;
  std::filesystem::remove(file, ec);
  const auto parsed = json::Parse(result.stdoutText);
  if (!parsed || !parsed->IsObject()) {
    throw CommandFailed("Patch installation did not return a result", ResultJson(result));
  }
  bool rebootRequired = false;
  if (const auto* flag = parsed->Get("rebootRequired"); flag && flag->Bool()) {
    rebootRequired = *flag->Bool();
  }
  rebootRequired = rebootRequired || RebootPending();
  auto body = result.stdoutText;
  body.pop_back();
  return body + ScheduleReboot(payload, rebootRequired) + "}";
}

std::string Software(const std::wstring& payloadJson, const bool uninstall, const std::filesystem::path& workRoot) {
  const auto payload = ParsePayload(payloadJson);
  const auto installer = Str(payload, "installer");
  const auto identifier = Str(payload, "identifier");
  const auto args = Utf8ToWide(Str(payload, "args"));
  std::wstring command;
  if (installer == "winget" || installer == "choco") {
    if (!IsSafePackageId(identifier)) {
      throw std::runtime_error("Invalid package id");
    }
    if (installer == "winget") {
      const auto winget = FindWinget();
      if (winget.empty()) throw std::runtime_error("WinGet/App Installer is unavailable to the protection service");
      command = L"\"" + winget + L"\" " + (uninstall ? L"uninstall" : L"install") + L" --id " + Utf8ToWide(identifier) +
                L" --exact --source winget --silent --accept-source-agreements --disable-interactivity" +
                (uninstall ? L"" : L" --accept-package-agreements --scope machine");
    } else {
      command = std::wstring(L"choco.exe ") + (uninstall ? L"uninstall " : L"install ") + Utf8ToWide(identifier) + L" -y --no-progress";
    }
  } else if (installer == "msi" || installer == "exe") {
    const auto sha256 = Str(payload, "sha256");
    if (identifier.rfind("https://", 0) != 0 || sha256.size() != 64) {
      throw std::runtime_error("Direct installers need an https URL and a SHA-256");
    }
    const auto downloads = workRoot / L"downloads";
    std::error_code ec;
    std::filesystem::create_directories(downloads, ec);
    const auto target = downloads / (GenerateGuidString() + (installer == "msi" ? L".msi" : L".exe"));
    if (URLDownloadToFileW(nullptr, Utf8ToWide(identifier).c_str(), target.c_str(), 0, nullptr) != S_OK) {
      throw std::runtime_error("The installer could not be downloaded");
    }
    std::wstring actual = ComputeFileSha256(target);
    std::transform(actual.begin(), actual.end(), actual.begin(), ::towlower);
    if (WideToUtf8(actual) != sha256) {
      std::filesystem::remove(target, ec);
      throw std::runtime_error("The downloaded installer does not match its SHA-256; it was deleted");
    }
    if (installer == "msi") {
      command = L"\"" + SystemPath(L"msiexec.exe") + L"\" " + (uninstall ? L"/x" : L"/i") + L" \"" + target.wstring() + L"\" /qn /norestart " + args;
    } else {
      command = L"\"" + target.wstring() + L"\" " + args;
    }
  } else {
    throw std::runtime_error(installer + " packages cannot be installed on Windows");
  }
  const auto result = RunProcess(command, workRoot.wstring(), {}, 60 * 60 * 1000);
  const auto json = "{\"exitCode\":" + std::to_string(static_cast<long>(result.exitCode)) + ",\"output\":" +
                    Q(LastLines(result.stdoutText + "\n" + result.stderrText, 20)) + "}";
  // 3010 = success, reboot required (MSI convention).
  if (result.exitCode != 0 && result.exitCode != 3010) {
    throw CommandFailed("The installer exited with code " + std::to_string(static_cast<long>(result.exitCode)), json);
  }
  return json;
}

std::string ServiceControl(const std::wstring& serviceName, const std::wstring& payloadJson) {
  const auto payload = payloadJson.empty() ? json::Value{} : ParsePayload(payloadJson);
  const auto action = payload.IsObject() ? Str(payload, "action", "restart") : "restart";
  if (action != "start" && action != "stop" && action != "restart") {
    throw std::runtime_error("action must be start, stop or restart");
  }
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!scm) {
    throw std::runtime_error("Cannot open the service manager");
  }
  SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (!service) {
    CloseServiceHandle(scm);
    throw std::runtime_error("Service not found");
  }
  auto waitFor = [&](DWORD wanted) {
    SERVICE_STATUS status{};
    for (int i = 0; i < 60; ++i) {
      if (QueryServiceStatus(service, &status) && status.dwCurrentState == wanted) {
        return true;
      }
      Sleep(500);
    }
    return false;
  };
  bool ok = true;
  if (action == "stop" || action == "restart") {
    SERVICE_STATUS status{};
    if (ControlService(service, SERVICE_CONTROL_STOP, &status) || GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
      ok = waitFor(SERVICE_STOPPED);
    } else {
      ok = false;
    }
  }
  if (ok && (action == "start" || action == "restart")) {
    ok = (StartServiceW(service, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) && waitFor(SERVICE_RUNNING);
  }
  SERVICE_STATUS status{};
  QueryServiceStatus(service, &status);
  CloseServiceHandle(service);
  CloseServiceHandle(scm);
  const auto state = status.dwCurrentState == SERVICE_RUNNING ? "running" : status.dwCurrentState == SERVICE_STOPPED ? "stopped" : "pending";
  const auto json = "{\"service\":" + Q(serviceName) + ",\"action\":\"" + action + "\",\"status\":\"" + state + "\"}";
  if (!ok) {
    throw CommandFailed("The service did not reach the requested state", json);
  }
  return json;
}

std::string PowerAction(const bool reboot, const std::wstring& payloadJson) {
  const auto payload = payloadJson.empty() ? json::Value{} : ParsePayload(payloadJson);
  const int minutes = static_cast<int>(std::clamp(payload.IsObject() ? Num(payload, "delayMinutes", 1) : 1, 0.0, 1440.0));
  auto message = payload.IsObject() ? Str(payload, "message") : "";
  if (message.empty()) {
    message = reboot ? "Your IT provider is restarting this computer." : "Your IT provider is shutting down this computer.";
  }
  message.erase(std::remove(message.begin(), message.end(), '"'), message.end());
  const auto command = L"\"" + SystemPath(L"shutdown.exe") + L"\" " + (reboot ? L"/r" : L"/s") + L" /t " + std::to_wstring(minutes * 60) +
                       L" /d p:0:0 /c \"" + Utf8ToWide(message.substr(0, 400)) + L"\"";
  const auto result = RunProcess(command, L"", {}, 30000);
  if (result.exitCode != 0) {
    throw std::runtime_error("shutdown.exe failed: " + LastLines(result.stdoutText + result.stderrText, 2));
  }
  return "{\"scheduledInMinutes\":" + std::to_string(minutes) + ",\"reboot\":" + (reboot ? "true" : "false") + "}";
}

std::string MessageUser(const std::wstring& payloadJson) {
  const auto payload = ParsePayload(payloadJson);
  auto title = Utf8ToWide(Str(payload, "title", "Message from IT support"));
  auto text = Utf8ToWide(Str(payload, "message", Str(payload, "text")));
  if (text.empty()) {
    throw std::runtime_error("The message is empty");
  }
  const auto session = WTSGetActiveConsoleSessionId();
  DWORD response = 0;
  if (session == 0xFFFFFFFF ||
      !WTSSendMessageW(WTS_CURRENT_SERVER_HANDLE, session, title.data(), static_cast<DWORD>(title.size() * sizeof(wchar_t)), text.data(),
                       static_cast<DWORD>(text.size() * sizeof(wchar_t)), MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND,
                       static_cast<DWORD>(Num(payload, "timeoutSeconds", 0)), &response, FALSE)) {
    throw std::runtime_error("Nobody is signed in to show the message to");
  }
  return "{\"delivered\":true}";
}

}  // namespace antivirus::agent::rmm
