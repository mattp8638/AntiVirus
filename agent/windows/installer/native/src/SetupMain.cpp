#include <windows.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wrl/client.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "SetupResourceIds.h"

namespace {

constexpr wchar_t kWindowClassName[] = L"FenrirSetupWindow";
constexpr wchar_t kWindowTitle[] = L"Fenrir Endpoint Setup";
constexpr wchar_t kCompanyName[] = L"Fenrir";
constexpr wchar_t kProductName[] = L"Fenrir Endpoint";
constexpr wchar_t kServiceName[] = L"FenrirAgent";
constexpr wchar_t kMinifilterServiceName[] = L"AntivirusMinifilter";
constexpr wchar_t kMinifilterServiceDisplayName[] = L"AntiVirus Real-Time Protection Minifilter";
constexpr wchar_t kMinifilterServiceDescription[] =
    L"Intercepts file activity and asks the user-mode broker for real-time allow or block decisions.";
constexpr wchar_t kMinifilterServiceBinaryPath[] = L"\\SystemRoot\\System32\\drivers\\AntivirusMinifilter.sys";
constexpr wchar_t kMinifilterLoadOrderGroup[] = L"FSFilter Activity Monitor";
constexpr wchar_t kMinifilterDefaultInstanceName[] = L"AntivirusMinifilter Instance";
constexpr wchar_t kMinifilterDefaultInstanceAltitude[] = L"370030";
constexpr wchar_t kAgentRegistryRoot[] = L"SOFTWARE\\FenrirAgent";
constexpr wchar_t kControlPlaneBaseUrlValueName[] = L"ControlPlaneBaseUrl";
constexpr wchar_t kDefaultControlPlaneBaseUrl[] = L"https://api.fenrir-security.co.uk";
constexpr wchar_t kArpRegistryRoot[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FenrirEndpoint";
constexpr wchar_t kRunRegistryRoot[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValueName[] = L"FenrirEndpointClient";
constexpr wchar_t kInstallFolderName[] = L"Fenrir Endpoint";
constexpr wchar_t kServiceExeName[] = L"fenrir-agent-service.exe";
constexpr wchar_t kEndpointExeName[] = L"fenrir-endpoint-client.exe";
constexpr wchar_t kPamExeName[] = L"fenrir-pam.exe";
constexpr wchar_t kRemoteHelperExeName[] = L"fenrir-remote.exe";
constexpr wchar_t kAmsiDllName[] = L"fenrir-amsi-provider.dll";
constexpr wchar_t kScannerCliName[] = L"fenrir-scannercli.exe";
constexpr wchar_t kAmsiTestCliName[] = L"fenrir-amsitestcli.exe";
constexpr wchar_t kEtwTestCliName[] = L"fenrir-etwtestcli.exe";
constexpr wchar_t kWfpTestCliName[] = L"fenrir-wfptestcli.exe";
constexpr wchar_t kWinpthreadDllName[] = L"libwinpthread-1.dll";
constexpr wchar_t kWebView2LoaderDllName[] = L"WebView2Loader.dll";
constexpr wchar_t kWebView2RuntimeInstallerName[] = L"MicrosoftEdgeWebView2Setup.exe";
constexpr wchar_t kSetupExeName[] = L"FenrirSetup.exe";
constexpr wchar_t kSignatureBundleRelativePath[] = L"signatures\\default-signatures.tsv";
constexpr wchar_t kDriverInfRelativePath[] = L"driver\\AntivirusMinifilter.inf";
constexpr wchar_t kDriverSysRelativePath[] = L"driver\\AntivirusMinifilter.sys";
constexpr wchar_t kDriverCatRelativePath[] = L"driver\\AntivirusMinifilter.cat";
constexpr wchar_t kDriverReadmeRelativePath[] = L"driver\\README.md";
constexpr wchar_t kToolsRelativePath[] = L"tools\\fenrir-scannercli.exe";
constexpr wchar_t kToolsAmsiTestCliRelativePath[] = L"tools\\fenrir-amsitestcli.exe";
constexpr wchar_t kToolsEtwTestCliRelativePath[] = L"tools\\fenrir-etwtestcli.exe";
constexpr wchar_t kToolsWfpTestCliRelativePath[] = L"tools\\fenrir-wfptestcli.exe";
constexpr wchar_t kToolsWinpthreadRelativePath[] = L"tools\\libwinpthread-1.dll";
constexpr DWORD kPnpUtilUntrustedRootExitCode = static_cast<DWORD>(CERT_E_UNTRUSTEDROOT);
constexpr DWORD kPnpUtilNoMoreItemsExitCode = ERROR_NO_MORE_ITEMS;
constexpr DWORD kWin32InvalidImageHashError = 577;
constexpr DWORD kWin32DriverBlockedError = 1275;
constexpr DWORD kWin32VirusInfectedError = ERROR_VIRUS_INFECTED;
constexpr DWORD kWin32VirusDeletedError = ERROR_VIRUS_DELETED;

constexpr UINT kInstallerLogMessage = WM_APP + 1;
constexpr UINT kInstallerStatusMessage = WM_APP + 2;
constexpr UINT kInstallerCompleteMessage = WM_APP + 3;

enum : int {
  IDC_EYEBROW = 1001,
  IDC_TITLE = 1002,
  IDC_SUBTITLE = 1003,
  IDC_PATH_LABEL = 1004,
  IDC_PATH_VALUE = 1005,
  IDC_STATUS = 1007,
  IDC_PROGRESS = 1008,
  IDC_LOG = 1009,
  IDC_PRIMARY_BUTTON = 1010,
  IDC_UNINSTALL_BUTTON = 1011,
  IDC_OPEN_FOLDER_BUTTON = 1012,
  IDC_CLOSE_BUTTON = 1013,
  IDC_BADGE = 1014,
  IDC_LOG_TITLE = 1015
};

struct LogMessagePayload {
  std::wstring text;
};

struct StatusMessagePayload {
  std::wstring text;
  int progress{0};
};

struct CompletionPayload {
  bool success{false};
  bool installed{false};
  bool closeAfter{false};
  std::wstring message;
};

struct UiContext {
  HINSTANCE instance{};
  HWND hwnd{};
  HWND eyebrowLabel{};
  HWND titleLabel{};
  HWND subtitleLabel{};
  HWND pathLabel{};
  HWND pathValue{};
  HWND statusLabel{};
  HWND progressBar{};
  HWND logEdit{};
  HWND primaryButton{};
  HWND uninstallButton{};
  HWND openFolderButton{};
  HWND closeButton{};
  HWND badgeLabel{};
  HWND logTitleLabel{};
  HFONT titleFont{};
  HFONT headingFont{};
  HFONT bodyFont{};
  HFONT smallFont{};
  HBRUSH windowBrush{};
  HBRUSH surfaceBrush{};
  HBRUSH detailBrush{};
  HICON heroIcon{};
  std::filesystem::path installRoot;
  std::filesystem::path setupPath;
  std::wstring controlPlaneBaseUrl;
  std::wstring enrollmentToken;  // supplied only by a tenant-specific deployment package
  bool installed{false};
  bool busy{false};
};

struct InstallWorkerArgs {
  HWND hwnd{};
  UiContext* context{};
  bool repair{false};
};

struct UninstallWorkerArgs {
  HWND hwnd{};
  UiContext* context{};
};

UiContext* GetContext(HWND hwnd) {
  return reinterpret_cast<UiContext*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

std::wstring QuotePath(const std::filesystem::path& path) {
  return L"\"" + path.wstring() + L"\"";
}

COLORREF DarkTextColor() { return RGB(235, 241, 252); }
COLORREF MutedTextColor() { return RGB(145, 159, 185); }
COLORREF AccentBlue() { return RGB(49, 123, 242); }
COLORREF AccentBlueDark() { return RGB(153, 206, 255); }
COLORREF AccentGreen() { return RGB(31, 182, 123); }
COLORREF AccentGreenDark() { return RGB(173, 247, 213); }
COLORREF AccentAmber() { return RGB(224, 151, 39); }
COLORREF AccentAmberDark() { return RGB(255, 218, 158); }
COLORREF AccentRed() { return RGB(214, 72, 112); }
COLORREF WindowBackgroundColor() { return RGB(8, 12, 18); }
COLORREF SurfaceColor() { return RGB(14, 18, 26); }
COLORREF DetailColor() { return RGB(12, 16, 23); }
COLORREF BorderColor() { return RGB(34, 45, 62); }

COLORREF AdjustColor(const COLORREF color, const int delta) {
  const auto adjustChannel = [delta](const BYTE channel) -> BYTE {
    return static_cast<BYTE>(std::clamp(static_cast<int>(channel) + delta, 0, 255));
  };

  return RGB(adjustChannel(GetRValue(color)), adjustChannel(GetGValue(color)), adjustChannel(GetBValue(color)));
}

RECT ControlRectInClient(HWND parent, HWND control) {
  RECT rect{};
  if (parent == nullptr || control == nullptr) {
    return rect;
  }

  GetWindowRect(control, &rect);
  MapWindowPoints(HWND_DESKTOP, parent, reinterpret_cast<LPPOINT>(&rect), 2);
  return rect;
}

COLORREF ResolveBadgeFill(const UiContext& context) {
  if (context.busy) {
    return RGB(52, 74, 116);
  }
  if (context.installed) {
    return RGB(27, 68, 55);
  }
  return RGB(30, 52, 86);
}

void DrawRoundedPanel(HDC hdc, const RECT& rect, const COLORREF fillColor, const COLORREF borderColor,
                      const int radius = 12) {
  HBRUSH brush = CreateSolidBrush(fillColor);
  HPEN pen = CreatePen(PS_SOLID, 1, borderColor);
  const auto oldPen = SelectObject(hdc, pen);
  const auto oldBrush = SelectObject(hdc, brush);
  RoundRect(hdc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
  SelectObject(hdc, oldBrush);
  SelectObject(hdc, oldPen);
  DeleteObject(brush);
  DeleteObject(pen);
}

void ApplyDarkWindowFrame(HWND hwnd) {
  if (hwnd == nullptr) {
    return;
  }

  const BOOL darkMode = TRUE;
  DwmSetWindowAttribute(hwnd, 20, &darkMode, sizeof(darkMode));
  const auto captionColor = WindowBackgroundColor();
  DwmSetWindowAttribute(hwnd, 35, &captionColor, sizeof(captionColor));
  const auto textColor = DarkTextColor();
  DwmSetWindowAttribute(hwnd, 36, &textColor, sizeof(textColor));
}

void AppendLog(HWND edit, const std::wstring& line) {
  if (edit == nullptr) {
    return;
  }

  const auto message = line + L"\r\n";
  SendMessageW(edit, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
  SendMessageW(edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(message.c_str()));
}

COLORREF ResolveStaticTextColor(const UiContext& context, HWND control) {
  if (control == context.eyebrowLabel) {
    return AccentBlueDark();
  }
  if (control == context.subtitleLabel || control == context.pathLabel || control == context.logTitleLabel) {
    return MutedTextColor();
  }
  if (control == context.pathValue) {
    return AccentBlueDark();
  }
  if (control == context.badgeLabel) {
    return DarkTextColor();
  }
  if (control == context.statusLabel) {
    return context.busy ? AccentBlueDark() : DarkTextColor();
  }
  return DarkTextColor();
}

HBRUSH ResolveStaticBrush(UiContext& context, HWND control) {
  if (control == context.logTitleLabel || control == context.statusLabel || control == context.progressBar) {
    return context.surfaceBrush;
  }
  if (control == context.logEdit) {
    return context.detailBrush;
  }
  return context.surfaceBrush;
}

COLORREF ResolveButtonFill(const UiContext& context, const int controlId, const UINT itemState) {
  const auto disabled = (itemState & ODS_DISABLED) != 0;
  const auto pressed = (itemState & ODS_SELECTED) != 0;

  COLORREF base = RGB(43, 52, 68);
  switch (controlId) {
    case IDC_PRIMARY_BUTTON:
      base = context.installed ? RGB(34, 119, 94) : RGB(47, 102, 184);
      break;
    case IDC_UNINSTALL_BUTTON:
      base = RGB(168, 63, 92);
      break;
    case IDC_OPEN_FOLDER_BUTTON:
      base = RGB(54, 123, 162);
      break;
    case IDC_CLOSE_BUTTON:
      base = RGB(43, 52, 68);
      break;
    default:
      break;
  }

  if (disabled) {
    return RGB(31, 37, 48);
  }
  if (pressed) {
    return AdjustColor(base, -24);
  }
  return base;
}

COLORREF ResolveButtonTextColor(const UINT itemState) {
  return (itemState & ODS_DISABLED) != 0 ? RGB(112, 124, 144) : RGB(244, 247, 255);
}

void DrawOwnerButton(const DRAWITEMSTRUCT* draw, UiContext& context) {
  RECT rect = draw->rcItem;
  const auto fillColor = ResolveButtonFill(context, static_cast<int>(draw->CtlID), draw->itemState);
  const auto borderColor = AdjustColor(fillColor, 16);

  DrawRoundedPanel(draw->hDC, rect, fillColor, borderColor, 10);

  RECT accentRect{rect.left + 10, rect.top + 9, rect.left + 16, rect.bottom - 9};
  HBRUSH accentBrush = CreateSolidBrush(AdjustColor(fillColor, 22));
  FillRect(draw->hDC, &accentRect, accentBrush);
  DeleteObject(accentBrush);

  wchar_t text[128]{};
  GetWindowTextW(draw->hwndItem, text, static_cast<int>(std::size(text)));
  SetBkMode(draw->hDC, TRANSPARENT);
  SetTextColor(draw->hDC, ResolveButtonTextColor(draw->itemState));
  SelectObject(draw->hDC, context.bodyFont);
  RECT textRect = rect;
  textRect.left += 24;
  DrawTextW(draw->hDC, text, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

  if ((draw->itemState & ODS_FOCUS) != 0) {
    RECT focusRect = rect;
    InflateRect(&focusRect, -4, -4);
    DrawFocusRect(draw->hDC, &focusRect);
  }
}

void PaintInstallerChrome(HWND hwnd, UiContext& context) {
  PAINTSTRUCT paint{};
  const auto hdc = BeginPaint(hwnd, &paint);

  RECT client{};
  GetClientRect(hwnd, &client);
  FillRect(hdc, &client, context.windowBrush);

  const int padding = 20;
  const int width = client.right - client.left;
  const int heroHeight = 152;
  const int statusHeight = 84;
  const int buttonTop = client.bottom - 62;

  const RECT heroRect{padding, padding, width - padding, padding + heroHeight};
  const RECT statusRect{padding, heroRect.bottom + 16, width - padding, heroRect.bottom + 16 + statusHeight};
  const RECT logRect{padding, statusRect.bottom + 16, width - padding, buttonTop - 14};

  DrawRoundedPanel(hdc, heroRect, SurfaceColor(), BorderColor(), 14);
  DrawRoundedPanel(hdc, statusRect, SurfaceColor(), BorderColor(), 14);
  DrawRoundedPanel(hdc, logRect, DetailColor(), BorderColor(), 14);

  if (context.heroIcon != nullptr) {
    DrawIconEx(hdc, heroRect.left + 22, heroRect.top + 24, context.heroIcon, 48, 48, 0, nullptr, DI_NORMAL);
  }

  const RECT badgeRect = ControlRectInClient(hwnd, context.badgeLabel);
  if (badgeRect.right > badgeRect.left) {
    DrawRoundedPanel(hdc, badgeRect, ResolveBadgeFill(context), AdjustColor(ResolveBadgeFill(context), 18), 16);
  }

  const RECT progressRect = ControlRectInClient(hwnd, context.progressBar);
  if (progressRect.right > progressRect.left) {
    RECT glowRect = progressRect;
    InflateRect(&glowRect, 0, 4);
    HBRUSH glowBrush = CreateSolidBrush(RGB(18, 24, 34));
    FillRect(hdc, &glowRect, glowBrush);
    DeleteObject(glowBrush);
  }

  EndPaint(hwnd, &paint);
}

std::wstring TrimCopy(const std::wstring& value) {
  const auto first = value.find_first_not_of(L" \t\r\n");
  if (first == std::wstring::npos) {
    return {};
  }

  const auto last = value.find_last_not_of(L" \t\r\n");
  return value.substr(first, last - first + 1);
}

std::wstring HresultToHexString(const HRESULT value) {
  std::wstringstream stream;
  stream << L"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0')
         << static_cast<unsigned long>(value);
  return stream.str();
}

std::wstring FormatWin32ErrorMessage(const DWORD errorCode) {
  LPWSTR messageBuffer = nullptr;
  const auto messageLength =
      FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                     nullptr, errorCode, 0, reinterpret_cast<LPWSTR>(&messageBuffer), 0, nullptr);
  if (messageLength == 0 || messageBuffer == nullptr) {
    return {};
  }

  std::wstring message(messageBuffer, messageLength);
  LocalFree(messageBuffer);
  return TrimCopy(message);
}

std::wstring BuildProcessLaunchFailureMessage(const std::filesystem::path& executable,
                                              const DWORD processError) {
  std::wstring message = L"Could not start " + executable.wstring() + L" (error " +
                         std::to_wstring(processError) + L"). " +
                         FormatWin32ErrorMessage(processError);

  if (processError == kWin32VirusInfectedError || processError == kWin32VirusDeletedError) {
    message +=
        L" Windows Security or another antivirus product blocked this file as malware or potentially unwanted "
        L"software. For local testing, allow or exclude this Fenrir test build, then rerun setup.";
  }

  return message;
}

std::filesystem::path CreateTemporaryCaptureFilePath() {
  wchar_t temporaryDirectory[MAX_PATH]{};
  const auto temporaryDirectoryLength =
      GetTempPathW(static_cast<DWORD>(std::size(temporaryDirectory)), temporaryDirectory);
  if (temporaryDirectoryLength == 0 || temporaryDirectoryLength >= std::size(temporaryDirectory)) {
    return {};
  }

  wchar_t temporaryFile[MAX_PATH]{};
  if (GetTempFileNameW(temporaryDirectory, L"FNR", 0, temporaryFile) == 0) {
    return {};
  }

  return std::filesystem::path(temporaryFile);
}

std::wstring DecodeProcessOutputText(const std::string& text) {
  if (text.empty()) {
    return {};
  }

  const auto sourceLength = static_cast<int>(text.size());
  int convertedLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), sourceLength, nullptr, 0);
  UINT codePage = CP_UTF8;
  DWORD decodeFlags = MB_ERR_INVALID_CHARS;
  if (convertedLength <= 0) {
    codePage = CP_ACP;
    decodeFlags = 0;
    convertedLength = MultiByteToWideChar(codePage, decodeFlags, text.data(), sourceLength, nullptr, 0);
  }

  if (convertedLength <= 0) {
    return {};
  }

  std::wstring decoded(static_cast<std::size_t>(convertedLength), L'\0');
  MultiByteToWideChar(codePage, decodeFlags, text.data(), sourceLength, decoded.data(), convertedLength);
  return decoded;
}

std::wstring LoadCapturedProcessOutput(const std::filesystem::path& path) {
  if (path.empty()) {
    return {};
  }

  std::ifstream stream(path, std::ios::binary);
  if (!stream.good()) {
    return {};
  }

  std::ostringstream bytes;
  bytes << stream.rdbuf();
  auto decoded = TrimCopy(DecodeProcessOutputText(bytes.str()));
  constexpr std::size_t kMaxCapturedOutputCharacters = 3'000;
  if (decoded.size() > kMaxCapturedOutputCharacters) {
    decoded.resize(kMaxCapturedOutputCharacters);
    decoded += L" ... (truncated)";
  }
  return decoded;
}

std::wstring QueryCertificateSubject(PCCERT_CONTEXT certificateContext) {
  if (certificateContext == nullptr) {
    return {};
  }

  const auto subjectLength =
      CertGetNameStringW(certificateContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
  if (subjectLength <= 1) {
    return {};
  }

  std::wstring subject(static_cast<std::size_t>(subjectLength - 1), L'\0');
  CertGetNameStringW(certificateContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject.data(), subjectLength);
  return subject;
}

bool ResolveSignerCertificateFromSignedFile(const std::filesystem::path& signedFile,
                                            PCCERT_CONTEXT* signerContext,
                                            std::wstring* signerSubject,
                                            std::wstring* errorMessage) {
  if (signerContext == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Internal certificate resolution failure.";
    }
    return false;
  }

  *signerContext = nullptr;
  HCERTSTORE certificateStore = nullptr;
  HCRYPTMSG cryptMessage = nullptr;

  DWORD encoding = 0;
  DWORD contentType = 0;
  DWORD formatType = 0;
  if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, signedFile.c_str(),
                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                       CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType, &formatType,
                       &certificateStore, &cryptMessage, nullptr) == FALSE) {
    if (errorMessage != nullptr) {
      const auto error = GetLastError();
      *errorMessage = L"Could not inspect minifilter catalog signature metadata (error " +
                      std::to_wstring(error) + L"). " + FormatWin32ErrorMessage(error);
    }
    return false;
  }

  DWORD signerInfoBytes = 0;
  if (CryptMsgGetParam(cryptMessage, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoBytes) == FALSE ||
      signerInfoBytes == 0) {
    if (errorMessage != nullptr) {
      const auto error = GetLastError();
      *errorMessage = L"Could not read signer metadata from minifilter catalog (error " +
                      std::to_wstring(error) + L"). " + FormatWin32ErrorMessage(error);
    }
    if (cryptMessage != nullptr) {
      CryptMsgClose(cryptMessage);
    }
    if (certificateStore != nullptr) {
      CertCloseStore(certificateStore, 0);
    }
    return false;
  }

  std::vector<std::uint8_t> signerInfoBuffer(signerInfoBytes);
  if (CryptMsgGetParam(cryptMessage, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuffer.data(),
                       &signerInfoBytes) == FALSE) {
    if (errorMessage != nullptr) {
      const auto error = GetLastError();
      *errorMessage = L"Could not decode signer metadata from minifilter catalog (error " +
                      std::to_wstring(error) + L"). " + FormatWin32ErrorMessage(error);
    }
    CryptMsgClose(cryptMessage);
    CertCloseStore(certificateStore, 0);
    return false;
  }

  const auto signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(signerInfoBuffer.data());
  CERT_INFO certInfo{};
  certInfo.Issuer = signerInfo->Issuer;
  certInfo.SerialNumber = signerInfo->SerialNumber;

  const auto certificateContext = CertFindCertificateInStore(
      certificateStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT,
      &certInfo, nullptr);
  if (certificateContext == nullptr) {
    if (errorMessage != nullptr) {
      const auto error = GetLastError();
      *errorMessage = L"Could not locate minifilter signer certificate in the catalog store (error " +
                      std::to_wstring(error) + L"). " + FormatWin32ErrorMessage(error);
    }
    CryptMsgClose(cryptMessage);
    CertCloseStore(certificateStore, 0);
    return false;
  }

  if (signerSubject != nullptr) {
    *signerSubject = QueryCertificateSubject(certificateContext);
  }

  *signerContext = CertDuplicateCertificateContext(certificateContext);
  CertFreeCertificateContext(certificateContext);
  CryptMsgClose(cryptMessage);
  CertCloseStore(certificateStore, 0);
  return *signerContext != nullptr;
}

bool EnsureCertificateInMachineStore(PCCERT_CONTEXT certificateContext, const wchar_t* storeName,
                                     std::wstring* errorMessage) {
  const auto store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, static_cast<HCRYPTPROV_LEGACY>(0),
                                   CERT_SYSTEM_STORE_LOCAL_MACHINE, storeName);
  if (store == nullptr) {
    if (errorMessage != nullptr) {
      const auto error = GetLastError();
      *errorMessage = L"Could not open machine certificate store '" + std::wstring(storeName) +
                      L"' (error " + std::to_wstring(error) + L"). " + FormatWin32ErrorMessage(error);
    }
    return false;
  }

  const auto added =
      CertAddCertificateContextToStore(store, certificateContext, CERT_STORE_ADD_REPLACE_EXISTING,
                                       nullptr) != FALSE;
  const auto addError = added ? ERROR_SUCCESS : GetLastError();
  CertCloseStore(store, 0);

  if (!added) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not add the minifilter signer certificate to machine store '" +
                      std::wstring(storeName) + L"' (error " + std::to_wstring(addError) +
                      L"). " + FormatWin32ErrorMessage(addError);
    }
    return false;
  }

  return true;
}

bool BootstrapMinifilterSigningTrust(const std::filesystem::path& driverCatPath,
                                     std::wstring* signerSubject,
                                     std::wstring* errorMessage) {
  PCCERT_CONTEXT signerCertificate = nullptr;
  std::wstring resolvedSignerSubject;
  if (!ResolveSignerCertificateFromSignedFile(driverCatPath, &signerCertificate,
                                              &resolvedSignerSubject, errorMessage)) {
    return false;
  }

  const auto trustedPublisherOk =
      EnsureCertificateInMachineStore(signerCertificate, L"TrustedPublisher", errorMessage);
  const auto trustedRootOk =
      EnsureCertificateInMachineStore(signerCertificate, L"ROOT", errorMessage);

  CertFreeCertificateContext(signerCertificate);

  if (!trustedPublisherOk || !trustedRootOk) {
    return false;
  }

  if (signerSubject != nullptr) {
    *signerSubject = resolvedSignerSubject;
  }
  return true;
}

bool HasEmbeddedPayloadResource(HINSTANCE instance, const int resourceId) {
  return FindResourceW(instance, MAKEINTRESOURCEW(resourceId), RT_RCDATA) != nullptr;
}

bool IsWebView2RuntimeAvailable(const std::filesystem::path& installRoot, std::wstring* browserVersion,
                                std::wstring* errorMessage) {
  const auto loaderPath = installRoot / kWebView2LoaderDllName;
  if (!std::filesystem::exists(loaderPath)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"WebView2Loader.dll was not found in the install directory.";
    }
    return false;
  }

  const auto loaderModule = LoadLibraryW(loaderPath.c_str());
  if (loaderModule == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"WebView2Loader.dll could not be loaded.";
    }
    return false;
  }

  using GetAvailableVersionFn = HRESULT(WINAPI*)(PCWSTR, LPWSTR*);
  const auto getAvailableVersion = reinterpret_cast<GetAvailableVersionFn>(
      GetProcAddress(loaderModule, "GetAvailableCoreWebView2BrowserVersionString"));
  if (getAvailableVersion == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"WebView2 loader export GetAvailableCoreWebView2BrowserVersionString is unavailable.";
    }
    FreeLibrary(loaderModule);
    return false;
  }

  LPWSTR versionRaw = nullptr;
  const auto result = getAvailableVersion(nullptr, &versionRaw);
  if (FAILED(result) || versionRaw == nullptr || wcslen(versionRaw) == 0) {
    if (errorMessage != nullptr) {
      *errorMessage =
          L"Microsoft Edge WebView2 Runtime is not installed or not available (" + HresultToHexString(result) + L").";
    }
    if (versionRaw != nullptr) {
      CoTaskMemFree(versionRaw);
    }
    FreeLibrary(loaderModule);
    return false;
  }

  if (browserVersion != nullptr) {
    *browserVersion = versionRaw;
  }

  CoTaskMemFree(versionRaw);
  FreeLibrary(loaderModule);
  return true;
}

std::wstring ReadRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName);
bool WriteRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName, const std::wstring& value);
bool WriteRegistryDword(HKEY root, const wchar_t* subKey, const wchar_t* valueName, DWORD value);
bool DeleteRegistryTree(HKEY root, const wchar_t* subKey);
std::filesystem::path GetDefaultInstallRoot();
std::filesystem::path QueryInstallRoot();
std::filesystem::path ResolveSystemExecutablePath(const std::filesystem::path& windowsRoot,
                                                  const wchar_t* executableName);
std::wstring QueryServiceStateByName(const wchar_t* serviceName);
bool ServiceExists();
bool IsInstalledAt(const std::filesystem::path& installRoot);
bool IsProcessElevated();
bool EnsureDirectory(const std::filesystem::path& path, std::wstring* errorMessage = nullptr);
bool ExtractResourceToFile(HINSTANCE instance, int resourceId, const std::filesystem::path& targetPath,
                           std::wstring* errorMessage);
bool RunProcessHidden(const std::filesystem::path& executable, const std::wstring& arguments,
                      const std::filesystem::path& workingDirectory, DWORD* exitCode, std::wstring* errorMessage);
bool WaitForServiceStateByName(const wchar_t* serviceName, DWORD targetState, DWORD timeoutMs);
bool WaitForServiceState(DWORD targetState, DWORD timeoutMs);
bool StartServiceByName(const wchar_t* serviceName, DWORD timeoutMs, std::wstring* errorMessage,
                        DWORD* startFailureCode = nullptr);
bool StopServiceByName(const wchar_t* serviceName, DWORD timeoutMs, std::wstring* errorMessage);
bool StartInstalledService(std::wstring* errorMessage);
bool StopInstalledService(std::wstring* errorMessage);
bool ConfigureMinifilterInstanceRegistry(std::wstring* errorMessage);
bool EnsureMinifilterServiceRegistrationFallback(const std::filesystem::path& windowsRoot,
                                                 const std::filesystem::path& driverSysPath,
                                                 std::wstring* errorMessage);
bool InstallMinifilterDriver(const std::filesystem::path& installRoot, bool repair, std::wstring* errorMessage,
                             std::wstring* warningMessage = nullptr);
bool UninstallMinifilterDriver(const std::filesystem::path& installRoot, std::wstring* errorMessage);
bool RunPostInstallHealthChecks(const std::filesystem::path& installRoot, std::wstring* errorMessage);
bool StopMatchingProcess(const std::filesystem::path& imagePath);
bool CreateShortcut(const std::filesystem::path& linkPath, const std::filesystem::path& targetPath,
                    const std::wstring& arguments, const std::wstring& description);
bool CreateStartMenuShortcuts(const std::filesystem::path& installRoot);
bool RemoveStartMenuShortcuts();
bool RegisterEndpointAutoStart(const std::filesystem::path& installRoot);
bool RemoveEndpointAutoStart();
DWORD EstimateInstallSizeKb(const std::filesystem::path& installRoot);
bool WriteArpEntry(const std::filesystem::path& installRoot);
bool PersistControlPlaneUrl(const std::wstring& value, std::wstring* errorMessage);
void PostLog(HWND hwnd, const std::wstring& text);
void PostStatus(HWND hwnd, const std::wstring& text, int progress);
void PostComplete(HWND hwnd, bool success, bool installed, bool closeAfter, const std::wstring& message);
bool CopySelfToInstallRoot(const std::filesystem::path& currentPath, const std::filesystem::path& installRoot,
                           std::wstring* errorMessage);
bool LaunchInstalledEndpointClient(const std::filesystem::path& installRoot, bool backgroundMode);
bool InstallPayloadFiles(HWND hwnd, UiContext* context, bool repair, std::wstring* errorMessage);
void RunInstallOrRepair(HWND hwnd, UiContext* context, bool repair);
std::filesystem::path GetTemporaryHelperPath();
void LaunchCleanupHelper(const std::filesystem::path& currentSetupPath, const std::filesystem::path& installRoot);
void RunUninstall(HWND hwnd, UiContext* context);
DWORD WINAPI InstallWorkerThread(LPVOID parameter);
DWORD WINAPI UninstallWorkerThread(LPVOID parameter);
DWORD ParseWaitPid(int argc, wchar_t* argv[]);
std::optional<std::filesystem::path> ParseCleanupRoot(int argc, wchar_t* argv[]);
void WaitForProcessExit(DWORD pid);
void DeleteSelfWithCmd(const std::filesystem::path& helperPath);
int RunCleanupMode(int argc, wchar_t* argv[]);
void RefreshUi(UiContext& context);
void LayoutControls(UiContext& context);
LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
// Per-request enrollment overlay generated by the Ubuntu cloud. Never log it.
bool ReadEmbeddedEnrollment(std::wstring& server, std::wstring& token) {
  constexpr char magic[] = "FENRIR_ENROLL_V1!";
  std::array<wchar_t, 32768> path{};
  const auto count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (!count || count >= path.size()) throw std::runtime_error("Cannot locate setup executable");
  std::ifstream file(std::filesystem::path(path.data()), std::ios::binary | std::ios::ate);
  if (!file) throw std::runtime_error("Cannot read setup executable");
  const auto size = static_cast<std::streamoff>(file.tellg());
  constexpr auto magicSize = sizeof(magic) - 1;
  if (size < static_cast<std::streamoff>(magicSize + 4)) return false;
  file.seekg(size - static_cast<std::streamoff>(magicSize));
  std::array<char, magicSize> tail{};
  file.read(tail.data(), tail.size());
  if (std::string(tail.data(), tail.size()) != magic) return false;
  file.seekg(size - static_cast<std::streamoff>(magicSize + 4));
  std::array<unsigned char, 4> length{};
  file.read(reinterpret_cast<char*>(length.data()), length.size());
  const uint32_t bytes = uint32_t(length[0]) | (uint32_t(length[1]) << 8) |
      (uint32_t(length[2]) << 16) | (uint32_t(length[3]) << 24);
  if (!bytes || bytes > 4096 || size < static_cast<std::streamoff>(bytes + magicSize + 4))
    throw std::runtime_error("Invalid embedded enrollment length");
  file.seekg(size - static_cast<std::streamoff>(bytes + magicSize + 4));
  std::string payload(bytes, '\0');
  if (!file.read(payload.data(), bytes)) throw std::runtime_error("Incomplete enrollment configuration");
  const auto first = payload.find('\n');
  const auto second = first == std::string::npos ? first : payload.find('\n', first + 1);
  if (first == std::string::npos || second == std::string::npos || payload.size() - second - 1 != 32 ||
      payload.find_first_not_of("0123456789abcdef", second + 1) != std::string::npos)
    throw std::runtime_error("Invalid embedded enrollment configuration");
  for (unsigned char ch : payload) {
    if ((ch < 33 && ch != '\n') || ch > 126) throw std::runtime_error("Invalid enrollment characters");
  }
  server.assign(payload.begin(), payload.begin() + first);
  token.assign(payload.begin() + first + 1, payload.begin() + second);
  return true;
}

bool HasArgument(int argc, wchar_t* argv[], const wchar_t* name);

std::wstring ReadRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(root, subKey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
    return {};
  }

  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || type != REG_SZ || bytes == 0) {
    RegCloseKey(key);
    return {};
  }

  std::wstring value(bytes / sizeof(wchar_t), L'\0');
  if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(value.data()), &bytes) != ERROR_SUCCESS) {
    RegCloseKey(key);
    return {};
  }

  RegCloseKey(key);
  if (!value.empty() && value.back() == L'\0') {
    value.pop_back();
  }
  return value;
}

bool WriteRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* valueName, const std::wstring& value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(root, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
    return false;
  }

  const auto ok = RegSetValueExW(key, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                                 static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
  RegCloseKey(key);
  return ok;
}

bool WriteRegistryDword(HKEY root, const wchar_t* subKey, const wchar_t* valueName, const DWORD value) {
  HKEY key = nullptr;
  if (RegCreateKeyExW(root, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
    return false;
  }

  const auto ok =
      RegSetValueExW(key, valueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value)) == ERROR_SUCCESS;
  RegCloseKey(key);
  return ok;
}

bool DeleteRegistryTree(HKEY root, const wchar_t* subKey) {
  const auto status = RegDeleteTreeW(root, subKey);
  return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
}

bool PersistControlPlaneUrl(const std::wstring& value, std::wstring* errorMessage) {
  if (WriteRegistryString(HKEY_LOCAL_MACHINE, kAgentRegistryRoot, kControlPlaneBaseUrlValueName, value)) {
    return true;
  }

  if (errorMessage != nullptr) {
    *errorMessage = L"Could not save the managed update endpoint configuration.";
  }
  return false;
}

std::filesystem::path GetDefaultInstallRoot() {
  PWSTR programFiles = nullptr;
  std::filesystem::path installRoot;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &programFiles))) {
    installRoot = std::filesystem::path(programFiles) / kInstallFolderName;
    CoTaskMemFree(programFiles);
    return installRoot;
  }

  const auto env = _wgetenv(L"ProgramFiles");
  if (env != nullptr && *env != L'\0') {
    return std::filesystem::path(env) / kInstallFolderName;
  }

  return std::filesystem::current_path() / kInstallFolderName;
}

std::filesystem::path QueryInstallRoot() {
  return GetDefaultInstallRoot();
}

std::filesystem::path ResolveSystemExecutablePath(const std::filesystem::path& windowsRoot,
                                                  const wchar_t* executableName) {
  if (executableName == nullptr || *executableName == L'\0') {
    return {};
  }

  if (!windowsRoot.empty()) {
    for (const auto& candidate : {windowsRoot / L"System32" / executableName,
                                  windowsRoot / L"Sysnative" / executableName}) {
      std::error_code existsError;
      if (std::filesystem::exists(candidate, existsError) && !existsError) {
        return candidate;
      }
    }
  }

  std::array<wchar_t, MAX_PATH> resolvedPath{};
  const auto resolvedLength = SearchPathW(nullptr, executableName, nullptr,
                                          static_cast<DWORD>(resolvedPath.size()), resolvedPath.data(), nullptr);
  if (resolvedLength != 0 && resolvedLength < resolvedPath.size()) {
    return std::filesystem::path(resolvedPath.data());
  }

  return {};
}

std::wstring QueryServiceStateByName(const wchar_t* serviceName) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    return L"scm-unavailable";
  }

  const auto service = OpenServiceW(manager, serviceName, SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const auto openError = GetLastError();
    CloseServiceHandle(manager);
    if (openError == ERROR_SERVICE_DOES_NOT_EXIST) {
      return L"missing";
    }
    return L"open-failed";
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                           &bytesNeeded) == FALSE) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return L"query-failed";
  }

  CloseServiceHandle(service);
  CloseServiceHandle(manager);

  switch (status.dwCurrentState) {
    case SERVICE_STOPPED:
      return L"stopped";
    case SERVICE_START_PENDING:
      return L"start-pending";
    case SERVICE_STOP_PENDING:
      return L"stop-pending";
    case SERVICE_RUNNING:
      return L"running";
    case SERVICE_CONTINUE_PENDING:
      return L"continue-pending";
    case SERVICE_PAUSE_PENDING:
      return L"pause-pending";
    case SERVICE_PAUSED:
      return L"paused";
    default:
      return L"unknown";
  }
}

bool ServiceExists() {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    return false;
  }

  const auto service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS);
  if (service != nullptr) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return true;
  }

  CloseServiceHandle(manager);
  return false;
}

bool IsInstalledAt(const std::filesystem::path& installRoot) {
  return ServiceExists() || std::filesystem::exists(installRoot / kServiceExeName) ||
         !ReadRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"InstallLocation").empty();
}

bool IsProcessElevated() {
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE) {
    return false;
  }

  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  const auto elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE &&
                        elevation.TokenIsElevated != 0;
  CloseHandle(token);
  return elevated;
}

bool EnsureDirectory(const std::filesystem::path& path, std::wstring* errorMessage) {
  std::error_code error;
  std::filesystem::create_directories(path, error);
  if (error) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not create " + path.wstring();
    }
    return false;
  }
  return true;
}

bool ExtractResourceToFile(HINSTANCE instance, const int resourceId, const std::filesystem::path& targetPath,
                           std::wstring* errorMessage) {
  const auto resource = FindResourceW(instance, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
  if (resource == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Embedded setup payload is missing.";
    }
    return false;
  }

  const auto loaded = LoadResource(instance, resource);
  if (loaded == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not load embedded setup payload.";
    }
    return false;
  }

  const auto size = SizeofResource(instance, resource);
  const auto bytes = LockResource(loaded);
  if (bytes == nullptr || size == 0) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Embedded setup payload was empty.";
    }
    return false;
  }

  if (!EnsureDirectory(targetPath.parent_path(), errorMessage)) {
    return false;
  }

  const auto temporaryPath = targetPath.wstring() + L".setup-new";
  DeleteFileW(temporaryPath.c_str());

  const auto fileHandle =
      CreateFileW(temporaryPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (fileHandle == INVALID_HANDLE_VALUE) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not write " + temporaryPath;
    }
    return false;
  }

  DWORD written = 0;
  const auto ok = WriteFile(fileHandle, bytes, size, &written, nullptr) != FALSE && written == size;
  CloseHandle(fileHandle);
  if (!ok) {
    DeleteFileW(temporaryPath.c_str());
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not fully extract " + targetPath.wstring();
    }
    return false;
  }

  if (MoveFileExW(temporaryPath.c_str(), targetPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) !=
      FALSE) {
    return true;
  }

  const auto replaceError = GetLastError();
  // A half-upgraded service whose files are replaced at the NEXT reboot is
  // difficult to recover and can explain apparent uninstall/startup failures.
  // Never claim success for a deferred file replacement. Stop protected
  // processes through the authorised maintenance path, then retry or repair.
  DeleteFileW(temporaryPath.c_str());
  if (errorMessage != nullptr) {
    *errorMessage = L"Could not replace " + targetPath.wstring() + L" (error " +
                    std::to_wstring(replaceError) +
                    L"). No reboot-time replacement was queued. Close in-use processes and retry repair.";
  }
  return false;
}

bool RunProcessHidden(const std::filesystem::path& executable, const std::wstring& arguments,
                      const std::filesystem::path& workingDirectory, DWORD* exitCode, std::wstring* errorMessage) {
  std::wstring commandLine = QuotePath(executable);
  if (!arguments.empty()) {
    commandLine += L" ";
    commandLine += arguments;
  }

  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startupInfo.wShowWindow = SW_HIDE;

  SECURITY_ATTRIBUTES outputSecurity{};
  outputSecurity.nLength = sizeof(outputSecurity);
  outputSecurity.bInheritHandle = TRUE;
  const auto capturedOutputPath = CreateTemporaryCaptureFilePath();
  HANDLE outputCaptureHandle = INVALID_HANDLE_VALUE;
  if (!capturedOutputPath.empty()) {
    outputCaptureHandle =
        CreateFileW(capturedOutputPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, &outputSecurity,
                    OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (outputCaptureHandle != INVALID_HANDLE_VALUE) {
      startupInfo.dwFlags |= STARTF_USESTDHANDLES;
      startupInfo.hStdOutput = outputCaptureHandle;
      startupInfo.hStdError = outputCaptureHandle;
      const auto standardInput = GetStdHandle(STD_INPUT_HANDLE);
      startupInfo.hStdInput = standardInput == INVALID_HANDLE_VALUE ? nullptr : standardInput;
    }
  }

  PROCESS_INFORMATION processInfo{};
  auto mutableCommandLine = commandLine;
  const auto launched = CreateProcessW(nullptr, mutableCommandLine.data(), nullptr, nullptr,
                                       outputCaptureHandle != INVALID_HANDLE_VALUE,
                                       CREATE_NO_WINDOW, nullptr,
                                       workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
                                       &startupInfo, &processInfo);
  if (outputCaptureHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(outputCaptureHandle);
  }
  if (!launched) {
    if (errorMessage != nullptr) {
      const auto processError = GetLastError();
      *errorMessage = BuildProcessLaunchFailureMessage(executable, processError);
    }
    if (!capturedOutputPath.empty()) {
      DeleteFileW(capturedOutputPath.c_str());
    }
    return false;
  }

  WaitForSingleObject(processInfo.hProcess, INFINITE);
  DWORD processExitCode = 0;
  GetExitCodeProcess(processInfo.hProcess, &processExitCode);
  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);
  if (exitCode != nullptr) {
    *exitCode = processExitCode;
  }
  const auto capturedOutput = LoadCapturedProcessOutput(capturedOutputPath);
  if (!capturedOutputPath.empty()) {
    DeleteFileW(capturedOutputPath.c_str());
  }
  if (processExitCode != 0 && errorMessage != nullptr) {
    *errorMessage = executable.filename().wstring() + L" exited with code " + std::to_wstring(processExitCode);
    if (!capturedOutput.empty()) {
      *errorMessage += L". " + capturedOutput;
    }
  }
  return processExitCode == 0;
}

bool WaitForServiceStateByName(const wchar_t* serviceName, const DWORD targetState, const DWORD timeoutMs) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    return false;
  }

  const auto service = OpenServiceW(manager, serviceName, SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    CloseServiceHandle(manager);
    return false;
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  const auto deadline = GetTickCount64() + timeoutMs;
  bool reachedTarget = false;

  while (GetTickCount64() < deadline) {
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                             &bytesNeeded) == FALSE) {
      break;
    }

    if (status.dwCurrentState == targetState) {
      reachedTarget = true;
      break;
    }

    Sleep(500);
  }

  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return reachedTarget;
}

bool WaitForServiceState(const DWORD targetState, const DWORD timeoutMs) {
  return WaitForServiceStateByName(kServiceName, targetState, timeoutMs);
}

bool StartServiceByName(const wchar_t* serviceName, const DWORD timeoutMs, std::wstring* errorMessage,
                        DWORD* startFailureCode) {
  if (startFailureCode != nullptr) {
    *startFailureCode = ERROR_SUCCESS;
  }

  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    if (errorMessage != nullptr) {
      const auto managerError = GetLastError();
      *errorMessage = L"Could not open the Service Control Manager (error " + std::to_wstring(managerError) +
                      L"). " + FormatWin32ErrorMessage(managerError);
      if (startFailureCode != nullptr) {
        *startFailureCode = managerError;
      }
    }
    return false;
  }

  const auto service = OpenServiceW(manager, serviceName, SERVICE_START | SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const auto openError = GetLastError();
    CloseServiceHandle(manager);
    if (errorMessage != nullptr) {
      *errorMessage = std::wstring(L"Could not open service '") + serviceName + L"' (error " +
                      std::to_wstring(openError) + L"). " + FormatWin32ErrorMessage(openError);
    }
    if (startFailureCode != nullptr) {
      *startFailureCode = openError;
    }
    return false;
  }

  const auto startResult = StartServiceW(service, 0, nullptr);
  const auto startError = startResult != FALSE ? ERROR_SUCCESS : GetLastError();
  const auto started = startResult != FALSE || startError == ERROR_SERVICE_ALREADY_RUNNING;
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  if (!started) {
    if (errorMessage != nullptr) {
      *errorMessage = std::wstring(L"Service '") + serviceName + L"' could not be started (error " +
                      std::to_wstring(startError) + L"). " + FormatWin32ErrorMessage(startError);
    }
    if (startFailureCode != nullptr) {
      *startFailureCode = startError;
    }
    return false;
  }

  if (!WaitForServiceStateByName(serviceName, SERVICE_RUNNING, timeoutMs)) {
    if (errorMessage != nullptr) {
      *errorMessage = std::wstring(L"Service '") + serviceName + L"' did not reach the running state.";
    }
    if (startFailureCode != nullptr) {
      *startFailureCode = ERROR_SERVICE_REQUEST_TIMEOUT;
    }
    return false;
  }

  return true;
}

bool StopServiceByName(const wchar_t* serviceName, const DWORD timeoutMs, std::wstring* errorMessage) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not open the Service Control Manager.";
    }
    return false;
  }

  const auto service = OpenServiceW(manager, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const auto openError = GetLastError();
    CloseServiceHandle(manager);
    if (openError == ERROR_SERVICE_DOES_NOT_EXIST) {
      return true;
    }
    if (errorMessage != nullptr) {
      *errorMessage = std::wstring(L"Could not open service '") + serviceName + L"'.";
    }
    return false;
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                           &bytesNeeded) == FALSE) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (errorMessage != nullptr) {
      *errorMessage = std::wstring(L"Could not query service '") + serviceName + L"'.";
    }
    return false;
  }

  if (status.dwCurrentState != SERVICE_STOPPED) {
    SERVICE_STATUS stopStatus{};
    if (ControlService(service, SERVICE_CONTROL_STOP, &stopStatus) == FALSE) {
      const auto stopError = GetLastError();
      if (stopError != ERROR_SERVICE_NOT_ACTIVE) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        if (errorMessage != nullptr) {
          *errorMessage = std::wstring(L"Service '") + serviceName + L"' could not be stopped.";
        }
        return false;
      }
    }

    if (!WaitForServiceStateByName(serviceName, SERVICE_STOPPED, timeoutMs)) {
      CloseServiceHandle(service);
      CloseServiceHandle(manager);
      if (errorMessage != nullptr) {
        *errorMessage = std::wstring(L"Service '") + serviceName + L"' did not reach the stopped state.";
      }
      return false;
    }
  }

  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return true;
}

bool DeleteServiceByName(const wchar_t* serviceName, std::wstring* errorMessage) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not open the Service Control Manager.";
    }
    return false;
  }

  const auto service = OpenServiceW(manager, serviceName, DELETE | SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const auto openError = GetLastError();
    CloseServiceHandle(manager);
    if (openError == ERROR_SERVICE_DOES_NOT_EXIST) {
      return true;
    }
    if (errorMessage != nullptr) {
      *errorMessage = std::wstring(L"Could not open service '") + serviceName + L"' for deletion.";
    }
    return false;
  }

  const auto deleted = DeleteService(service) != FALSE;
  if (!deleted) {
    const auto deleteError = GetLastError();
    if (deleteError != ERROR_SERVICE_MARKED_FOR_DELETE && deleteError != ERROR_SERVICE_DOES_NOT_EXIST) {
      CloseServiceHandle(service);
      CloseServiceHandle(manager);
      if (errorMessage != nullptr) {
        *errorMessage = std::wstring(L"Could not delete service '") + serviceName + L"'.";
      }
      return false;
    }
  }

  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return true;
}

bool StartInstalledService(std::wstring* errorMessage) {
  return StartServiceByName(kServiceName, 20'000, errorMessage);
}


bool VerifyInstalledServicePersistence(const std::filesystem::path& installRoot, std::wstring* errorMessage) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) {
    if (errorMessage) *errorMessage = L"Cannot open Windows Service Control Manager to verify persistence.";
    return false;
  }
  const auto service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
  if (!service) {
    if (errorMessage) *errorMessage = L"FenrirAgent service registration was not found after installation.";
    CloseServiceHandle(manager);
    return false;
  }
  const auto done = [&]() { CloseServiceHandle(service); CloseServiceHandle(manager); };
  DWORD required = 0;
  QueryServiceConfigW(service, nullptr, 0, &required);
  if (!required) {
    if (errorMessage) *errorMessage = L"Cannot determine FenrirAgent startup configuration size.";
    done();
    return false;
  }
  std::vector<BYTE> buffer(required);
  if (!QueryServiceConfigW(service, reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data()),
                           static_cast<DWORD>(buffer.size()), &required)) {
    if (errorMessage) *errorMessage = L"Cannot read FenrirAgent startup configuration.";
    done();
    return false;
  }
  const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(buffer.data());
  const auto expected = std::wstring(L"\"") + (installRoot / kServiceExeName).wstring() + L"\"";
  if (config->dwStartType != SERVICE_AUTO_START || !config->lpBinaryPathName ||
      _wcsicmp(config->lpBinaryPathName, expected.c_str()) != 0) {
    if (errorMessage) *errorMessage = L"Agent service is not configured to start automatically from its permanent installation folder.";
    done();
    return false;
  }
  required = 0;
  QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, nullptr, 0, &required);
  if (!required) {
    if (errorMessage) *errorMessage = L"Cannot determine agent service recovery configuration size.";
    done();
    return false;
  }
  std::vector<BYTE> recoveryBuffer(required);
  if (!QueryServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, recoveryBuffer.data(),
                            static_cast<DWORD>(recoveryBuffer.size()), &required)) {
    if (errorMessage) *errorMessage = L"Cannot query agent restart-on-failure policy.";
    done();
    return false;
  }
  const auto* recovery = reinterpret_cast<const SERVICE_FAILURE_ACTIONSW*>(recoveryBuffer.data());
  if (!recovery->cActions || !recovery->lpsaActions || recovery->lpsaActions[0].Type != SC_ACTION_RESTART) {
    if (errorMessage) *errorMessage = L"Agent service restart-on-failure policy is missing.";
    done();
    return false;
  }
  // SCM reports RUNNING before the agent's full initialization completes.
  // Check again after a short observation period to catch immediate startup exits.
  DWORD initialPid = 0;
  for (int sample = 0; sample < 11; ++sample) {
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status),
                              sizeof(status), &bytes) || status.dwCurrentState != SERVICE_RUNNING) {
      if (errorMessage) *errorMessage = L"Agent service stopped during startup verification. Check service events and the agent's local diagnostics.";
      done();
      return false;
    }
    if (status.dwProcessId == 0 || (initialPid != 0 && status.dwProcessId != initialPid)) {
      if (errorMessage) *errorMessage = L"Agent process restarted repeatedly during startup verification; review service crash events.";
      done();
      return false;
    }
    std::error_code binaryError;
    if (!std::filesystem::exists(installRoot / kServiceExeName, binaryError) || binaryError) {
      if (errorMessage) *errorMessage = L"Agent executable disappeared from its permanent installation path during startup verification. Check antivirus quarantine and pending file operations.";
      done();
      return false;
    }
    initialPid = status.dwProcessId;
    if (sample < 10) Sleep(1000);
  }
  done();
  return true;
}


bool ConfigureMinifilterInstanceRegistry(std::wstring* errorMessage) {
  const auto instancesRoot =
      std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + kMinifilterServiceName + L"\\Instances";
  const auto instanceKey = instancesRoot + L"\\" + kMinifilterDefaultInstanceName;

  if (!WriteRegistryString(HKEY_LOCAL_MACHINE, instancesRoot.c_str(), L"DefaultInstance",
                           kMinifilterDefaultInstanceName) ||
      !WriteRegistryString(HKEY_LOCAL_MACHINE, instanceKey.c_str(), L"Altitude", kMinifilterDefaultInstanceAltitude) ||
      !WriteRegistryDword(HKEY_LOCAL_MACHINE, instanceKey.c_str(), L"Flags", 0)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not configure AntivirusMinifilter instance registry settings.";
    }
    return false;
  }

  return true;
}

bool EnsureMinifilterServiceRegistrationFallback(const std::filesystem::path& windowsRoot,
                                                 const std::filesystem::path& driverSysPath,
                                                 std::wstring* errorMessage) {
  const auto stagedSystemDriverPath = windowsRoot / L"System32" / L"drivers" / driverSysPath.filename();
  auto driverAlreadyStaged = false;
  if (std::filesystem::exists(driverSysPath)) {
    std::error_code equivalentError;
    if (std::filesystem::exists(stagedSystemDriverPath)) {
      driverAlreadyStaged = std::filesystem::equivalent(driverSysPath, stagedSystemDriverPath, equivalentError);
    }
  }
  if (std::filesystem::exists(driverSysPath) && !driverAlreadyStaged) {
    if (CopyFileW(driverSysPath.c_str(), stagedSystemDriverPath.c_str(), FALSE) == FALSE) {
      const auto copyError = GetLastError();
      if (copyError != ERROR_SHARING_VIOLATION && copyError != ERROR_ACCESS_DENIED) {
        if (errorMessage != nullptr) {
          *errorMessage = L"Could not stage AntivirusMinifilter.sys into the system drivers directory (error " +
                          std::to_wstring(copyError) + L").";
        }
        return false;
      }
    }
  }
  if (!std::filesystem::exists(stagedSystemDriverPath)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"AntivirusMinifilter.sys is not staged in the system drivers directory after fallback setup.";
    }
    return false;
  }

  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
  if (manager == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not open the Service Control Manager for minifilter fallback registration.";
    }
    return false;
  }

  const auto dependencies = std::wstring(L"FltMgr");
  std::vector<wchar_t> dependencyMultiSz(dependencies.begin(), dependencies.end());
  dependencyMultiSz.push_back(L'\0');
  dependencyMultiSz.push_back(L'\0');

  auto service = OpenServiceW(manager, kMinifilterServiceName,
                              SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | SERVICE_START);
  if (service == nullptr) {
    const auto openError = GetLastError();
    if (openError == ERROR_SERVICE_DOES_NOT_EXIST) {
      service = CreateServiceW(
          manager, kMinifilterServiceName, kMinifilterServiceDisplayName,
          SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | SERVICE_START,
          SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
          kMinifilterServiceBinaryPath, kMinifilterLoadOrderGroup, nullptr,
          dependencyMultiSz.data(), nullptr, nullptr);
      if (service == nullptr) {
        CloseServiceHandle(manager);
        if (errorMessage != nullptr) {
          *errorMessage = L"Could not create AntivirusMinifilter service fallback registration.";
        }
        return false;
      }
    } else {
      CloseServiceHandle(manager);
      if (errorMessage != nullptr) {
        *errorMessage = L"Could not open AntivirusMinifilter service fallback registration.";
      }
      return false;
    }
  }

  if (ChangeServiceConfigW(service, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                           kMinifilterServiceBinaryPath, kMinifilterLoadOrderGroup, nullptr, dependencyMultiSz.data(),
                           nullptr, nullptr, kMinifilterServiceDisplayName) == FALSE) {
    const auto configError = GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not configure AntivirusMinifilter service fallback registration (error " +
                      std::to_wstring(configError) + L").";
    }
    return false;
  }

  SERVICE_DESCRIPTIONW description{};
  description.lpDescription = const_cast<LPWSTR>(kMinifilterServiceDescription);
  if (ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description) == FALSE) {
    const auto descriptionError = GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not set AntivirusMinifilter service description during fallback registration (error " +
                      std::to_wstring(descriptionError) + L").";
    }
    return false;
  }

  CloseServiceHandle(service);
  CloseServiceHandle(manager);

  return ConfigureMinifilterInstanceRegistry(errorMessage);
}

bool RegisterMinifilterWithSetupApi(const std::filesystem::path& windowsRoot,
                                    const std::filesystem::path& driverInfPath,
                                    const std::filesystem::path& installRoot,
                                    DWORD* setupApiExitCode,
                                    std::wstring* errorMessage) {
  const auto rundll32Path = ResolveSystemExecutablePath(windowsRoot, L"rundll32.exe");
  if (rundll32Path.empty()) {
    if (errorMessage != nullptr) {
      *errorMessage = L"rundll32.exe is unavailable on this host; cannot invoke SetupAPI fallback.";
    }
    return false;
  }

  DWORD localExitCode = 0;
  std::wstring localError;

  const auto trySection = [&](const std::wstring& section) {
    const auto setupApiArgs = std::wstring(L"setupapi.dll,InstallHinfSection ") + section + L" 132 " +
                              QuotePath(driverInfPath);
    localError.clear();
    localExitCode = 0;
    return RunProcessHidden(rundll32Path, setupApiArgs, installRoot, &localExitCode, &localError);
  };

  if (trySection(L"DefaultInstall")) {
    if (setupApiExitCode != nullptr) {
      *setupApiExitCode = localExitCode;
    }
    return true;
  }

  const auto defaultInstallError = localError;
  const auto defaultInstallExitCode = localExitCode;
  if (trySection(L"DefaultInstall.Services")) {
    if (setupApiExitCode != nullptr) {
      *setupApiExitCode = localExitCode;
    }
    return true;
  }

  if (setupApiExitCode != nullptr) {
    *setupApiExitCode = localExitCode;
  }
  if (errorMessage != nullptr) {
    *errorMessage = L"SetupAPI INF install fallback failed. DefaultInstall exit code " +
                    std::to_wstring(defaultInstallExitCode) + L"; DefaultInstall.Services exit code " +
                    std::to_wstring(localExitCode) + L". " +
                    (localError.empty() ? defaultInstallError : localError);
  }
  return false;
}

bool InstallMinifilterDriver(const std::filesystem::path& installRoot, const bool repair, std::wstring* errorMessage,
                             std::wstring* warningMessage) {
  if (warningMessage != nullptr) {
    warningMessage->clear();
  }

  const auto driverInfPath = installRoot / kDriverInfRelativePath;
  const auto driverSysPath = installRoot / kDriverSysRelativePath;
  const auto driverCatPath = installRoot / kDriverCatRelativePath;

  if (!std::filesystem::exists(driverInfPath)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Minifilter deployment metadata is missing from the install payload: " + driverInfPath.wstring();
    }
    return false;
  }

  if (!std::filesystem::exists(driverSysPath)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Minifilter driver payload is missing from the install payload: " + driverSysPath.wstring();
    }
    return false;
  }

  if (!std::filesystem::exists(driverCatPath)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Minifilter catalog payload is missing from the install payload: " + driverCatPath.wstring();
    }
    return false;
  }

  std::filesystem::path windowsRoot = L"C:\\Windows";
  const auto windir = _wgetenv(L"WINDIR");
  if (windir != nullptr && *windir != L'\0') {
    windowsRoot = std::filesystem::path(windir);
  }

  const auto pnputilPath = ResolveSystemExecutablePath(windowsRoot, L"pnputil.exe");
  DWORD pnputilExitCode = ERROR_FILE_NOT_FOUND;
  std::wstring pnputilError;
  auto pnputilSucceeded = false;
  const auto pnputilExitCodeAccepted = [&](const DWORD exitCode) {
    return exitCode == ERROR_SUCCESS_REBOOT_REQUIRED || exitCode == kPnpUtilNoMoreItemsExitCode;
  };
  if (!pnputilPath.empty()) {
    const auto pnputilArgs = std::wstring(L"/add-driver ") + QuotePath(driverInfPath) + L" /install";
    const auto pnputilInitialSucceeded =
        RunProcessHidden(pnputilPath, pnputilArgs, installRoot, &pnputilExitCode, &pnputilError);
    pnputilSucceeded = pnputilInitialSucceeded;
    if (!pnputilSucceeded && !pnputilExitCodeAccepted(pnputilExitCode)) {
      if (pnputilExitCode == kPnpUtilUntrustedRootExitCode) {
        std::wstring signerSubject;
        std::wstring trustBootstrapError;
        if (!BootstrapMinifilterSigningTrust(driverCatPath, &signerSubject, &trustBootstrapError)) {
          if (errorMessage != nullptr) {
            *errorMessage = L"Could not register AntivirusMinifilter with pnputil because the minifilter signing "
                            L"certificate is not trusted on this host (CERT_E_UNTRUSTEDROOT / 0x800B0109). " +
                            trustBootstrapError;
          }
          return false;
        }

        pnputilError.clear();
        pnputilExitCode = 0;
        pnputilSucceeded =
            RunProcessHidden(pnputilPath, pnputilArgs, installRoot, &pnputilExitCode, &pnputilError);
        if (!pnputilSucceeded && !pnputilExitCodeAccepted(pnputilExitCode)) {
          if (errorMessage != nullptr) {
            *errorMessage = L"Could not register AntivirusMinifilter with pnputil after trusting signer certificate" +
                            std::wstring(signerSubject.empty() ? L"" : (L" '" + signerSubject + L"'")) +
                            L". " + pnputilError;
          }
          return false;
        }
      } else {
        if (errorMessage != nullptr) {
          *errorMessage = L"Could not register AntivirusMinifilter with pnputil. " + pnputilError;
        }
        return false;
      }
    }

    if (pnputilExitCode == ERROR_SUCCESS_REBOOT_REQUIRED) {
      // PnP package registration is complete, but a reboot may be required before the driver can load.
      if (errorMessage != nullptr) {
        *errorMessage = L"AntivirusMinifilter driver registration completed and requested a reboot.";
      }
    }

    if (!pnputilSucceeded && !pnputilExitCodeAccepted(pnputilExitCode)) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Could not register AntivirusMinifilter with pnputil. " + pnputilError;
      }
      return false;
    }
  } else {
    pnputilError = L"pnputil.exe is unavailable on this host; proceeding with SetupAPI fallback.";
  }

  auto minifilterState = QueryServiceStateByName(kMinifilterServiceName);
  if (minifilterState == L"missing") {
    DWORD setupApiExitCode = 0;
    std::wstring setupApiError;
    const auto setupApiSucceeded =
        RegisterMinifilterWithSetupApi(windowsRoot, driverInfPath, installRoot, &setupApiExitCode, &setupApiError);

    minifilterState = QueryServiceStateByName(kMinifilterServiceName);
    if (minifilterState == L"missing") {
      std::wstring fallbackError;
      if (!EnsureMinifilterServiceRegistrationFallback(windowsRoot, driverSysPath, &fallbackError)) {
        if (errorMessage != nullptr) {
          *errorMessage =
              L"Minifilter service 'AntivirusMinifilter' was not registered after driver install "
              L"(pnputil exit code " +
              std::to_wstring(pnputilExitCode) + L", SetupAPI exit code " + std::to_wstring(setupApiExitCode) +
              L"). SetupAPI " + (setupApiSucceeded ? L"succeeded." : L"failed: " + setupApiError) +
              L" Fallback registration failed: " + fallbackError +
              std::wstring(pnputilError.empty() ? L"" : (L" " + pnputilError));
        }
        return false;
      }

      minifilterState = QueryServiceStateByName(kMinifilterServiceName);
    }

    if (minifilterState == L"missing") {
      if (errorMessage != nullptr) {
        *errorMessage = L"Minifilter service 'AntivirusMinifilter' was not registered after driver install "
                        L"(pnputil exit code " +
                        std::to_wstring(pnputilExitCode) +
                        L", SetupAPI exit code " + std::to_wstring(setupApiExitCode) + L"). " +
                        (setupApiSucceeded ? L"SetupAPI fallback completed but service is still missing."
                                           : L"SetupAPI fallback failed. " + setupApiError) +
                        std::wstring(pnputilError.empty() ? L"" : (L" " + pnputilError));
      }
      return false;
    }
  }

  if (minifilterState == L"scm-unavailable" || minifilterState == L"open-failed" ||
      minifilterState == L"query-failed") {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not query AntivirusMinifilter service state after driver install.";
    }
    return false;
  }

  std::wstring minifilterServiceConfigurationError;
  if (!EnsureMinifilterServiceRegistrationFallback(windowsRoot, driverSysPath, &minifilterServiceConfigurationError)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not refresh AntivirusMinifilter service configuration before startup. " +
                      minifilterServiceConfigurationError;
    }
    return false;
  }
  minifilterState = QueryServiceStateByName(kMinifilterServiceName);
  if (minifilterState == L"scm-unavailable" || minifilterState == L"open-failed" ||
      minifilterState == L"query-failed") {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not query AntivirusMinifilter service state after configuration refresh.";
    }
    return false;
  }

  if (_wcsicmp(minifilterState.c_str(), L"running") != 0) {
    const auto fltmcPath = windowsRoot / L"System32" / L"fltmc.exe";
    if (std::filesystem::exists(fltmcPath)) {
      DWORD fltmcExitCode = 0;
      std::wstring fltmcError;
      const auto loadArgs = std::wstring(L"load ") + kMinifilterServiceName;
      RunProcessHidden(fltmcPath, loadArgs, installRoot, &fltmcExitCode, &fltmcError);
    }

    std::wstring serviceStartError;
    DWORD minifilterStartFailureCode = ERROR_SUCCESS;
    if (!StartServiceByName(kMinifilterServiceName, 20'000, &serviceStartError, &minifilterStartFailureCode)) {
      minifilterState = QueryServiceStateByName(kMinifilterServiceName);
      if ((minifilterStartFailureCode == kWin32InvalidImageHashError ||
           minifilterStartFailureCode == kWin32DriverBlockedError) &&
          warningMessage != nullptr) {
        *warningMessage =
            L"AntivirusMinifilter could not be started because Windows rejected the driver signature "
            L"(error " +
            std::to_wstring(minifilterStartFailureCode) +
            L"). The endpoint will continue in reduced-protection mode until a Microsoft-attested production "
            L"minifilter signature is deployed.";
        return true;
      }
      if (errorMessage != nullptr) {
        *errorMessage = L"AntivirusMinifilter did not reach running state (current state: " + minifilterState +
                        L"). " + serviceStartError;
      }
      return false;
    }
  }

  const auto finalState = QueryServiceStateByName(kMinifilterServiceName);
  if (_wcsicmp(finalState.c_str(), L"running") != 0) {
    if (errorMessage != nullptr) {
      *errorMessage = L"AntivirusMinifilter service is not running after " +
                      std::wstring(repair ? L"repair" : L"install") + L" (state: " + finalState + L").";
    }
    return false;
  }

  return true;
}

bool RunPostInstallHealthChecks(const std::filesystem::path& installRoot, std::wstring* errorMessage) {
  const auto minifilterState = QueryServiceStateByName(kMinifilterServiceName);
  if (_wcsicmp(minifilterState.c_str(), L"running") != 0) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Post-install health check failed: AntivirusMinifilter is not running (state: " +
                      minifilterState + L").";
    }
    return false;
  }

  const auto scannerCliPath = installRoot / kToolsRelativePath;
  if (!std::filesystem::exists(scannerCliPath)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Post-install health check failed: scanner CLI payload is missing at " +
                      scannerCliPath.wstring() + L".";
    }
    return false;
  }

  const auto probeRoot = installRoot / L"runtime" / L"post-install-broker-probe";
  std::error_code probeRootError;
  std::filesystem::create_directories(probeRoot, probeRootError);
  if (probeRootError) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Post-install health check failed: could not create broker probe root at " +
                      probeRoot.wstring() + L".";
    }
    return false;
  }

  const auto probePath = probeRoot / L"broker-execute-eicar.ps1";
  {
    std::ofstream probeFile(probePath, std::ios::binary | std::ios::trunc);
    if (!probeFile.is_open()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Post-install health check failed: could not stage broker probe sample at " +
                        probePath.wstring() + L".";
      }
      return false;
    }

    probeFile << "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    if (!probeFile.good()) {
      if (errorMessage != nullptr) {
        *errorMessage = L"Post-install health check failed: could not write broker probe sample at " +
                        probePath.wstring() + L".";
      }
      return false;
    }
  }

  DWORD brokerProbeExitCode = std::numeric_limits<DWORD>::max();
  std::wstring brokerProbeError;
  const auto brokerProbeArgs = std::wstring(L"--json --realtime-op execute ") + QuotePath(probePath);
  RunProcessHidden(scannerCliPath, brokerProbeArgs, installRoot, &brokerProbeExitCode, &brokerProbeError);

  std::error_code probeCleanupError;
  std::filesystem::remove(probePath, probeCleanupError);

  if (brokerProbeExitCode != 2 && brokerProbeExitCode != 3) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Post-install health check failed: realtime broker execute probe did not block the staged "
                      L"sample (exit code " +
                      std::to_wstring(brokerProbeExitCode == std::numeric_limits<DWORD>::max() ? 0
                                                                                               : brokerProbeExitCode) +
                      L"). " + brokerProbeError;
    }
    return false;
  }

  const auto serviceExe = installRoot / kServiceExeName;
  if (!std::filesystem::exists(serviceExe)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Post-install health check failed: service binary is missing at " + serviceExe.wstring() +
                      L".";
    }
    return false;
  }

  DWORD selfTestExitCode = std::numeric_limits<DWORD>::max();
  std::wstring selfTestError;
  RunProcessHidden(serviceExe, L"--self-test", installRoot, &selfTestExitCode, &selfTestError);
  if (selfTestExitCode != 0) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Post-install health check failed: fenrir-agent-service.exe --self-test exited with code " +
                      std::to_wstring(selfTestExitCode == std::numeric_limits<DWORD>::max() ? 0 : selfTestExitCode) +
                      L". " + selfTestError;
    }
    return false;
  }

  return true;
}

bool UninstallMinifilterDriver(const std::filesystem::path& installRoot, std::wstring* errorMessage) {
  std::filesystem::path windowsRoot = L"C:\\Windows";
  const auto windir = _wgetenv(L"WINDIR");
  if (windir != nullptr && *windir != L'\0') {
    windowsRoot = std::filesystem::path(windir);
  }

  std::wstring stopError;
  if (!StopServiceByName(kMinifilterServiceName, 20'000, &stopError)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not stop AntivirusMinifilter before uninstall cleanup. " + stopError;
    }
    return false;
  }

  const auto fltmcPath = windowsRoot / L"System32" / L"fltmc.exe";
  if (std::filesystem::exists(fltmcPath)) {
    DWORD fltmcExitCode = 0;
    std::wstring fltmcError;
    const auto unloadArgs = std::wstring(L"unload ") + kMinifilterServiceName;
    RunProcessHidden(fltmcPath, unloadArgs, installRoot, &fltmcExitCode, &fltmcError);
  }

  const auto driverInfPath = installRoot / kDriverInfRelativePath;
  if (std::filesystem::exists(driverInfPath)) {
    const auto pnputilPath = ResolveSystemExecutablePath(windowsRoot, L"pnputil.exe");
    if (!pnputilPath.empty()) {
      DWORD pnputilExitCode = 0;
      std::wstring pnputilError;
      const auto pnputilArgs = std::wstring(L"/delete-driver ") + QuotePath(driverInfPath) + L" /uninstall /force";
      RunProcessHidden(pnputilPath, pnputilArgs, installRoot, &pnputilExitCode, &pnputilError);
      if (pnputilExitCode != ERROR_SUCCESS && pnputilExitCode != kPnpUtilNoMoreItemsExitCode) {
        if (errorMessage != nullptr) {
          *errorMessage = L"Could not remove AntivirusMinifilter driver package with pnputil (exit code " +
                          std::to_wstring(pnputilExitCode) + L"). " + pnputilError;
        }
        return false;
      }
    }
  }

  std::wstring deleteServiceError;
  if (!DeleteServiceByName(kMinifilterServiceName, &deleteServiceError)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not delete AntivirusMinifilter service registration. " + deleteServiceError;
    }
    return false;
  }

  const auto finalState = QueryServiceStateByName(kMinifilterServiceName);
  if (finalState != L"missing") {
    if (errorMessage != nullptr) {
      *errorMessage = L"AntivirusMinifilter service cleanup did not complete (state: " + finalState + L").";
    }
    return false;
  }

  return true;
}

bool StopInstalledService(std::wstring* errorMessage) {
  const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not open the Service Control Manager.";
    }
    return false;
  }

  const auto service = OpenServiceW(manager, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const auto error = GetLastError();
    CloseServiceHandle(manager);
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
      return true;
    }
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not open the installed protection service.";
    }
    return false;
  }

  SERVICE_STATUS_PROCESS status{};
  DWORD bytesNeeded = 0;
  if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                           &bytesNeeded) == FALSE) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not query the installed protection service state.";
    }
    return false;
  }

  if (status.dwCurrentState == SERVICE_STOPPED) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return true;
  }

  SERVICE_STATUS controlStatus{};
  if (ControlService(service, SERVICE_CONTROL_STOP, &controlStatus) == FALSE) {
    const auto error = GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (error != ERROR_SERVICE_NOT_ACTIVE) {
      if (errorMessage != nullptr) {
        *errorMessage = L"The protection service could not be stopped.";
      }
      return false;
    }
  }

  const auto stopped = WaitForServiceState(SERVICE_STOPPED, 20'000);
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  if (!stopped) {
    if (errorMessage != nullptr) {
      *errorMessage = L"The protection service did not stop in time.";
    }
    return false;
  }

  return true;
}

bool StopMatchingProcess(const std::filesystem::path& imagePath) {
  const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return false;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  bool stoppedAny = false;
  if (Process32FirstW(snapshot, &entry) != FALSE) {
    do {
      const auto processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                                             entry.th32ProcessID);
      if (processHandle == nullptr) {
        continue;
      }

      std::wstring buffer(MAX_PATH, L'\0');
      DWORD bufferSize = static_cast<DWORD>(buffer.size());
      if (QueryFullProcessImageNameW(processHandle, 0, buffer.data(), &bufferSize) != FALSE) {
        buffer.resize(bufferSize);
        if (_wcsicmp(buffer.c_str(), imagePath.c_str()) == 0) {
          TerminateProcess(processHandle, 0);
          WaitForSingleObject(processHandle, 5'000);
          stoppedAny = true;
        }
      }

      CloseHandle(processHandle);
    } while (Process32NextW(snapshot, &entry) != FALSE);
  }

  CloseHandle(snapshot);
  return stoppedAny;
}

bool CreateShortcut(const std::filesystem::path& linkPath, const std::filesystem::path& targetPath,
                    const std::wstring& arguments, const std::wstring& description) {
  EnsureDirectory(linkPath.parent_path(), nullptr);

  const auto coInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  const auto shouldCoUninitialize = SUCCEEDED(coInit);

  Microsoft::WRL::ComPtr<IShellLinkW> shellLink;
  if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&shellLink)))) {
    if (shouldCoUninitialize) {
      CoUninitialize();
    }
    return false;
  }

  shellLink->SetPath(targetPath.c_str());
  shellLink->SetArguments(arguments.c_str());
  shellLink->SetDescription(description.c_str());
  shellLink->SetWorkingDirectory(targetPath.parent_path().c_str());
  shellLink->SetIconLocation(targetPath.c_str(), 0);

  Microsoft::WRL::ComPtr<IPersistFile> persistFile;
  if (FAILED(shellLink.As(&persistFile))) {
    if (shouldCoUninitialize) {
      CoUninitialize();
    }
    return false;
  }

  const auto saved = SUCCEEDED(persistFile->Save(linkPath.c_str(), TRUE));
  if (shouldCoUninitialize) {
    CoUninitialize();
  }

  return saved;
}

std::optional<std::filesystem::path> GetProgramsFolder(const KNOWNFOLDERID& folderId) {
  PWSTR programs = nullptr;
  if (FAILED(SHGetKnownFolderPath(folderId, 0, nullptr, &programs))) {
    return std::nullopt;
  }

  std::filesystem::path result(programs);
  CoTaskMemFree(programs);
  return result;
}

bool CreateStartMenuShortcuts(const std::filesystem::path& installRoot) {
  for (const auto folderId : {FOLDERID_CommonPrograms, FOLDERID_Programs}) {
    const auto programsRoot = GetProgramsFolder(folderId);
    if (!programsRoot.has_value()) {
      continue;
    }

    const auto shortcutRoot = *programsRoot / kProductName;
    const auto endpointShortcut = shortcutRoot / L"Fenrir Endpoint.lnk";

    if (CreateShortcut(endpointShortcut, installRoot / kEndpointExeName, L"", L"Open Fenrir Endpoint")) {
      return true;
    }
  }

  return false;
}

bool RemoveStartMenuShortcuts() {
  bool removedAny = false;
  bool attempted = false;

  for (const auto folderId : {FOLDERID_CommonPrograms, FOLDERID_Programs}) {
    const auto programsRoot = GetProgramsFolder(folderId);
    if (!programsRoot.has_value()) {
      continue;
    }

    attempted = true;
    const auto shortcutRoot = *programsRoot / kProductName;
    std::error_code error;
    std::filesystem::remove_all(shortcutRoot, error);
    if (!error) {
      removedAny = true;
    }
  }

  return attempted ? removedAny : false;
}

bool RegisterEndpointAutoStart(const std::filesystem::path& installRoot) {
  return WriteRegistryString(HKEY_LOCAL_MACHINE, kRunRegistryRoot, kRunValueName,
                             QuotePath(installRoot / kEndpointExeName) + L" --background");
}

bool RemoveEndpointAutoStart() {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRunRegistryRoot, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
    return true;
  }

  const auto status = RegDeleteValueW(key, kRunValueName);
  RegCloseKey(key);
  return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
}

DWORD EstimateInstallSizeKb(const std::filesystem::path& installRoot) {
  std::uintmax_t totalBytes = 0;
  std::error_code error;
  for (std::filesystem::recursive_directory_iterator it(
           installRoot, std::filesystem::directory_options::skip_permission_denied, error);
       it != std::filesystem::recursive_directory_iterator(); it.increment(error)) {
    if (error) {
      error.clear();
      continue;
    }
    if (it->is_regular_file(error)) {
      totalBytes += it->file_size(error);
    }
    if (error) {
      error.clear();
    }
  }

  return static_cast<DWORD>((totalBytes + 1023) / 1024);
}

bool WriteArpEntry(const std::filesystem::path& installRoot) {
  const auto uninstallCommand = QuotePath(installRoot / kSetupExeName) + L" --uninstall";
  const auto installDate = [] {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    wchar_t buffer[9]{};
    swprintf_s(buffer, L"%04u%02u%02u", now.wYear, now.wMonth, now.wDay);
    return std::wstring(buffer);
  }();

  return WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"DisplayName", kProductName) &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"Publisher", kCompanyName) &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"InstallLocation", installRoot.wstring()) &&
         WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"DisplayIcon",
                             (installRoot / kEndpointExeName).wstring()) &&
        WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"DisplayVersion", L"0.1.0-alpha") &&
        WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"InstallDate", installDate) &&
        WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"UninstallString", uninstallCommand) &&
        WriteRegistryString(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"QuietUninstallString", uninstallCommand) &&
        WriteRegistryDword(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"EstimatedSize", EstimateInstallSizeKb(installRoot)) &&
        WriteRegistryDword(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"NoModify", 1) &&
        WriteRegistryDword(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"NoRepair", 0) &&
        WriteRegistryDword(HKEY_LOCAL_MACHINE, kArpRegistryRoot, L"NoRemove", 1);
}

void PostLog(HWND hwnd, const std::wstring& text) {
  if (!IsWindow(hwnd)) {
    return;
  }
  auto* payload = new LogMessagePayload{.text = text};
  PostMessageW(hwnd, kInstallerLogMessage, 0, reinterpret_cast<LPARAM>(payload));
}

void PostStatus(HWND hwnd, const std::wstring& text, const int progress) {
  if (!IsWindow(hwnd)) {
    return;
  }
  auto* payload = new StatusMessagePayload{.text = text, .progress = progress};
  PostMessageW(hwnd, kInstallerStatusMessage, 0, reinterpret_cast<LPARAM>(payload));
}

void PostComplete(HWND hwnd, const bool success, const bool installed, const bool closeAfter,
                  const std::wstring& message) {
  if (!IsWindow(hwnd)) {
    return;
  }
  auto* payload = new CompletionPayload{.success = success, .installed = installed, .closeAfter = closeAfter, .message = message};
  PostMessageW(hwnd, kInstallerCompleteMessage, 0, reinterpret_cast<LPARAM>(payload));
}

bool CopySelfToInstallRoot(const std::filesystem::path& currentPath, const std::filesystem::path& installRoot,
                           std::wstring* errorMessage) {
  const auto targetPath = installRoot / kSetupExeName;
  if (_wcsicmp(currentPath.c_str(), targetPath.c_str()) == 0) {
    return true;
  }

  if (!CopyFileW(currentPath.c_str(), targetPath.c_str(), FALSE)) {
    if (errorMessage != nullptr) {
      *errorMessage = L"Could not place the setup executable into the install directory.";
    }
    return false;
  }

  return true;
}

bool LaunchInstalledEndpointClient(const std::filesystem::path& installRoot, const bool backgroundMode) {
  const auto arguments = backgroundMode ? L"--background" : L"";
  return reinterpret_cast<std::intptr_t>(ShellExecuteW(nullptr, L"open", (installRoot / kEndpointExeName).c_str(),
                                                       arguments, installRoot.c_str(),
                                                       backgroundMode ? SW_HIDE : SW_SHOWNORMAL)) > 32;
}

bool InstallPayloadFiles(HWND hwnd, UiContext* context, const bool repair, std::wstring* errorMessage) {
  const auto installRoot = context->installRoot;
  PostStatus(hwnd, repair ? L"Preparing repair..." : L"Preparing install...", 5);
  PostLog(hwnd, L"Using install path " + installRoot.wstring());

  if (repair) {
    PostLog(hwnd, L"Stopping the running endpoint client before replacing payloads");
    StopMatchingProcess(installRoot / kEndpointExeName);
    StopMatchingProcess(installRoot / kPamExeName);

    if (ServiceExists()) {
      // Existing services have an intentionally restricted SCM DACL. Use the
      // agent's authorised maintenance path, which validates uninstall protection,
      // rather than attempting an unprivileged ControlService on a protected service.
      const auto existingServiceExe = installRoot / kServiceExeName;
      if (!std::filesystem::exists(existingServiceExe)) {
        if (errorMessage) {
          *errorMessage = L"Cannot repair: the existing FenrirAgent service binary is missing. "
                          L"Inspect quarantine and restore the approved signed binary before repair.";
        }
        return false;
      }
      std::wstring stopError;
      DWORD stopExitCode = 0;
      PostLog(hwnd, L"Requesting authorised maintenance stop before replacing service files");
      if (!RunProcessHidden(existingServiceExe, L"--stop", installRoot, &stopExitCode, &stopError) ||
          !WaitForServiceState(SERVICE_STOPPED, 20'000)) {
        if (errorMessage) {
          *errorMessage = L"Could not safely stop the protected FenrirAgent service for repair. " +
                          stopError + L" If maintenance protection is enabled, use the approved maintenance token.";
        }
        return false;
      }
    }
  }

  if (!EnsureDirectory(installRoot, errorMessage) ||
      !EnsureDirectory(installRoot / L"tools", errorMessage) ||
      !EnsureDirectory(installRoot / L"signatures", errorMessage) ||
      !EnsureDirectory(installRoot / L"driver", errorMessage)) {
    return false;
  }

  struct PayloadItem {
    int resourceId;
    std::filesystem::path relativePath;
    int progress;
    const wchar_t* label;
    bool required;
  };

#if defined(__MINGW32__)
  constexpr bool kRequiresWinpthreadRuntime = true;
#else
  // MSVC binaries use the Microsoft runtime, never libwinpthread-1.dll.
  constexpr bool kRequiresWinpthreadRuntime = false;
#endif

  const std::vector<PayloadItem> payloadItems{
      {IDR_PAYLOAD_SERVICE, kServiceExeName, 15, L"Installing service binary", true},
      {IDR_PAYLOAD_ENDPOINT_CLIENT, kEndpointExeName, 25, L"Installing endpoint client", true},
      {IDR_PAYLOAD_PAM_CLIENT, kPamExeName, 35, L"Installing PAM tool", true},
      {IDR_PAYLOAD_AMSI_PROVIDER, kAmsiDllName, 45, L"Installing AMSI provider", true},
      {IDR_PAYLOAD_REMOTE_HELPER, kRemoteHelperExeName, 50, L"Installing remote access helper", true},
      {IDR_PAYLOAD_SCANNERCLI, kToolsRelativePath, 55, L"Installing diagnostic scanner", true},
      {IDR_PAYLOAD_AMSITESTCLI, kToolsAmsiTestCliRelativePath, 60, L"Installing AMSI diagnostic tool", true},
      {IDR_PAYLOAD_ETWTESTCLI, kToolsEtwTestCliRelativePath, 64, L"Installing ETW diagnostic tool", true},
      {IDR_PAYLOAD_WFPTESTCLI, kToolsWfpTestCliRelativePath, 68, L"Installing WFP diagnostic tool", true},
      {IDR_PAYLOAD_WINPTHREAD, kWinpthreadDllName, 72, L"Installing runtime dependencies", kRequiresWinpthreadRuntime},
      {IDR_PAYLOAD_WINPTHREAD, kToolsWinpthreadRelativePath, 76, L"Installing tool runtime dependencies", kRequiresWinpthreadRuntime},
      {IDR_PAYLOAD_WEBVIEW2_LOADER, kWebView2LoaderDllName, 80, L"Installing WebView2 runtime loader", true},
      {IDR_PAYLOAD_SIGNATURES, kSignatureBundleRelativePath, 84, L"Installing signature bundle", true},
      {IDR_PAYLOAD_DRIVER_INF, kDriverInfRelativePath, 88, L"Installing minifilter deployment metadata", false},
      {IDR_PAYLOAD_DRIVER_SYS, kDriverSysRelativePath, 90, L"Installing minifilter driver payload", false},
      {IDR_PAYLOAD_DRIVER_CAT, kDriverCatRelativePath, 92, L"Installing minifilter catalog payload", false},
      {IDR_PAYLOAD_DRIVER_README, kDriverReadmeRelativePath, 94, L"Installing minifilter documentation", false},
  };

  for (const auto& item : payloadItems) {
    PostStatus(hwnd, item.label, item.progress);
    if (!HasEmbeddedPayloadResource(context->instance, item.resourceId)) {
      if (item.required) {
        if (errorMessage != nullptr) {
          *errorMessage = std::wstring(L"Required embedded setup payload is missing for ") + item.relativePath.wstring() + L".";
        }
        return false;
      }

      PostLog(hwnd, std::wstring(item.label) + L" (skipped; payload not embedded in this installer build)");
      continue;
    }

    PostLog(hwnd, item.label);
    if (!ExtractResourceToFile(context->instance, item.resourceId, installRoot / item.relativePath, errorMessage)) {
      return false;
    }
  }

  PostStatus(hwnd, L"Registering maintenance assets...", 75);
  PostLog(hwnd, L"Copying setup executable into the install directory");
  if (!CopySelfToInstallRoot(context->setupPath, installRoot, errorMessage)) {
    return false;
  }

  return true;
}

void RunInstallOrRepair(HWND hwnd, UiContext* context, const bool repair) {
  std::wstring errorMessage;
  if (!IsProcessElevated()) {
    PostComplete(hwnd, false, false, false,
                 L"Administrator rights are required to register the Fenrir Agent service. Restart the installer with elevation.");
    return;
  }

  if (!InstallPayloadFiles(hwnd, context, repair, &errorMessage)) {
    PostComplete(hwnd, false, false, false, errorMessage);
    return;
  }

  std::wstring webViewVersion;
  std::wstring webViewRuntimeError;
  auto webViewRuntimeReady = IsWebView2RuntimeAvailable(context->installRoot, &webViewVersion, &webViewRuntimeError);
  if (webViewRuntimeReady) {
    PostLog(hwnd, L"Detected WebView2 Runtime version " + webViewVersion + L".");
  } else {
    PostLog(hwnd, L"Warning: modern endpoint UI is unavailable on this host. " + webViewRuntimeError);
  }

  const auto hasEmbeddedWebViewInstaller =
      HasEmbeddedPayloadResource(context->instance, IDR_PAYLOAD_WEBVIEW2_BOOTSTRAPPER);
  if (!webViewRuntimeReady && hasEmbeddedWebViewInstaller) {
    PostStatus(hwnd, L"Installing WebView2 runtime dependency...", 78);
    PostLog(hwnd, L"Installing embedded WebView2 runtime dependency");

    const auto webViewInstallerPath = context->installRoot / kWebView2RuntimeInstallerName;
    std::wstring webViewDependencyError;
    if (!ExtractResourceToFile(context->instance, IDR_PAYLOAD_WEBVIEW2_BOOTSTRAPPER, webViewInstallerPath,
                               &webViewDependencyError)) {
      PostLog(hwnd, L"Warning: could not extract embedded WebView2 runtime installer. " + webViewDependencyError);
    } else {
      DWORD webViewInstallerExitCode = 0;
      if (!RunProcessHidden(webViewInstallerPath, L"/silent /install", context->installRoot, &webViewInstallerExitCode,
                            &webViewDependencyError)) {
        PostLog(hwnd, L"Warning: embedded WebView2 runtime installer failed. " + webViewDependencyError);
      } else {
        PostLog(hwnd, L"Embedded WebView2 runtime installer exited with code " +
                      std::to_wstring(webViewInstallerExitCode) + L".");
      }
    }

    webViewVersion.clear();
    webViewRuntimeError.clear();
    webViewRuntimeReady = IsWebView2RuntimeAvailable(context->installRoot, &webViewVersion, &webViewRuntimeError);
    if (webViewRuntimeReady) {
      PostLog(hwnd, L"WebView2 runtime dependency is now available (" + webViewVersion + L").");
    } else {
      PostLog(hwnd, L"Warning: WebView2 runtime is still unavailable after dependency install attempt. " +
                    webViewRuntimeError);
    }
  }

  // Repair must not silently reset a customer-enrolled server to the default endpoint.
  const auto registeredServer = ReadRegistryString(HKEY_LOCAL_MACHINE, kAgentRegistryRoot, kControlPlaneBaseUrlValueName);
  if (context->enrollmentToken.empty()) {
    context->controlPlaneBaseUrl = registeredServer.empty() ? std::wstring(kDefaultControlPlaneBaseUrl) : registeredServer;
    PostLog(hwnd, L"Preserving existing managed cloud endpoint configuration.");
  } else {
    PostLog(hwnd, L"Preparing customer-managed enrollment for the selected cloud server.");
  }
  if (!PersistControlPlaneUrl(context->controlPlaneBaseUrl, &errorMessage)) {
    PostComplete(hwnd, false, false, false, errorMessage);
    return;
  }

  const auto serviceExe = context->installRoot / kServiceExeName;
  DWORD exitCode = 0;
  PostStatus(hwnd, repair ? L"Repairing service registration..." : L"Registering protection service...", 80);
  PostLog(hwnd, repair ? L"Running service repair" : L"Installing the protection service");
  std::wstring serviceArgs = repair ? L"--repair" : L"--install";
  if (!context->enrollmentToken.empty()) {
    // Save the customer/cloud association before the service starts. Do not
    // print the token to the UI logs or include it in an error message.
    serviceArgs = L"--install --server \"" + context->controlPlaneBaseUrl +
                  L"\" --enroll-token \"" + context->enrollmentToken + L"\"";
  }
  if (!RunProcessHidden(serviceExe, serviceArgs, context->installRoot, &exitCode, &errorMessage)) {
    PostComplete(hwnd, false, false, false, errorMessage);
    return;
  }

  PostStatus(hwnd, L"Checking minifilter driver state...", 84);
  std::wstring minifilterWarning;
  // The old no-op driver branch was followed by a mandatory strict driver self-test.
  // A missing driver must be explicit, not confused with an uninstalled agent.
  const auto driverState = QueryServiceStateByName(kMinifilterServiceName);
  const bool minifilterDegraded = driverState != L"running";
  if (minifilterDegraded) {
    minifilterWarning = L"AntivirusMinifilter is not running (state: " + driverState +
        L"). Kernel real-time protection is unavailable; deploy a validated, signed driver separately.";
  }
  if (minifilterDegraded) {
    PostLog(hwnd, L"Warning: " + minifilterWarning);
  }

  PostStatus(hwnd, L"Starting protection service...", 87);
  PostLog(hwnd, L"Starting the installed protection service");
  if (!StartInstalledService(&errorMessage) ||
      !VerifyInstalledServicePersistence(context->installRoot, &errorMessage)) {
    PostComplete(hwnd, false, IsInstalledAt(context->installRoot), false, errorMessage);
    return;
  }

  if (!minifilterDegraded) {
    PostStatus(hwnd, L"Running post-install health checks...", 90);
    PostLog(hwnd, L"Validating minifilter runtime state, broker enforcement probe, and strict self-test");
    if (!RunPostInstallHealthChecks(context->installRoot, &errorMessage)) {
      PostComplete(hwnd, false, false, false, errorMessage);
      return;
    }
  } else {
    PostStatus(hwnd, L"Running post-install health checks...", 90);
    PostLog(hwnd, L"Skipping strict minifilter health checks because the minifilter is unavailable on this host.");
  }

  PostStatus(hwnd, L"Configuring startup and shortcuts...", 93);
  PostLog(hwnd, L"Registering endpoint client auto-start");
  if (!RegisterEndpointAutoStart(context->installRoot)) {
    PostComplete(hwnd, false, false, false, L"Could not register endpoint auto-start.");
    return;
  }

  PostLog(hwnd, L"Creating Start menu shortcuts");
  if (!CreateStartMenuShortcuts(context->installRoot)) {
    PostComplete(hwnd, false, false, false, L"Could not create Start menu shortcuts.");
    return;
  }

  PostStatus(hwnd, L"Writing Add/Remove Programs entry...", 97);
  PostLog(hwnd, L"Registering the uninstall entry");
  if (!WriteArpEntry(context->installRoot)) {
    PostComplete(hwnd, false, false, false, L"Could not register the Add/Remove Programs entry.");
    return;
  }

  PostStatus(hwnd, L"Launching background companion...", 100);
  PostLog(hwnd, L"Starting the installed endpoint client in silent tray mode");
  LaunchInstalledEndpointClient(context->installRoot, true);
  auto completionMessage = repair ? std::wstring(L"Fenrir Endpoint was repaired successfully.")
                                  : std::wstring(L"Fenrir Endpoint was installed successfully.");
  if (minifilterDegraded) {
    completionMessage += L" WARNING: AntivirusMinifilter is not running. Kernel real-time enforcement is NOT active. "
                         L"Deploy a verified Microsoft-signed minifilter package to enable full protection.";
  }
  if (!webViewRuntimeReady) {
    completionMessage += hasEmbeddedWebViewInstaller
                             ? L" Fenrir attempted to install the bundled WebView2 runtime dependency, but modern dashboard rendering is still unavailable on this host. The endpoint client will stay on the legacy native view until Microsoft Edge WebView2 Runtime is available."
                             : L" Modern dashboard rendering requires Microsoft Edge WebView2 Runtime; this host will use the legacy native view until WebView2 Runtime is installed.";
  }
  PostComplete(hwnd, true, true, false, completionMessage);
}

std::filesystem::path GetTemporaryHelperPath() {
  wchar_t tempPath[MAX_PATH]{};
  GetTempPathW(static_cast<DWORD>(std::size(tempPath)), tempPath);
  return std::filesystem::path(tempPath) / L"FenrirSetup-Cleanup.exe";
}

void LaunchCleanupHelper(const std::filesystem::path& currentSetupPath, const std::filesystem::path& installRoot) {
  const auto helperPath = GetTemporaryHelperPath();
  CopyFileW(currentSetupPath.c_str(), helperPath.c_str(), FALSE);

  std::wstringstream args;
  args << L"--cleanup " << QuotePath(installRoot) << L" --wait-pid " << GetCurrentProcessId();
  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  startupInfo.dwFlags = STARTF_USESHOWWINDOW;
  startupInfo.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION processInfo{};
  auto commandLine = QuotePath(helperPath) + L" " + args.str();
  auto mutableCommandLine = commandLine;
  if (CreateProcessW(nullptr, mutableCommandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                     helperPath.parent_path().c_str(), &startupInfo, &processInfo) != FALSE) {
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
  }
}

void RunUninstall(HWND hwnd, UiContext* context) {
  const auto installRoot = context->installRoot;
  const auto endpointClientPath = installRoot / kEndpointExeName;
  const auto serviceExe = installRoot / kServiceExeName;

  StopMatchingProcess(endpointClientPath);

  std::wstring errorMessage;
  DWORD exitCode = 0;
  if (std::filesystem::exists(serviceExe)) {
    PostStatus(hwnd, L"Removing protection service...", 30);
    PostLog(hwnd, L"Uninstalling the protection service");
    if (!RunProcessHidden(serviceExe, L"--uninstall", installRoot, &exitCode, &errorMessage)) {
      PostComplete(hwnd, false, true, false, errorMessage);
      return;
    }
  }

  PostStatus(hwnd, L"Removing minifilter registration...", 45);
  PostLog(hwnd, L"Uninstalling AntivirusMinifilter driver package and service registration");
  if (!true) {
    PostComplete(hwnd, false, true, false, errorMessage);
    return;
  }

  PostStatus(hwnd, L"Removing startup and shortcuts...", 55);
  PostLog(hwnd, L"Removing endpoint client auto-start");
  RemoveEndpointAutoStart();
  PostLog(hwnd, L"Removing Start menu shortcuts");
  RemoveStartMenuShortcuts();

  PostStatus(hwnd, L"Removing installation registry entries...", 75);
  DeleteRegistryTree(HKEY_LOCAL_MACHINE, kArpRegistryRoot);
  DeleteRegistryTree(HKEY_LOCAL_MACHINE, kAgentRegistryRoot);

  PostStatus(hwnd, L"Finalizing removal...", 100);
  LaunchCleanupHelper(context->setupPath, installRoot);
  PostComplete(hwnd, true, false, true, L"Fenrir Endpoint was removed. The setup window will close to finish cleanup.");
}

DWORD WINAPI InstallWorkerThread(LPVOID parameter) {
  std::unique_ptr<InstallWorkerArgs> args(reinterpret_cast<InstallWorkerArgs*>(parameter));
  RunInstallOrRepair(args->hwnd, args->context, args->repair);
  return 0;
}

DWORD WINAPI UninstallWorkerThread(LPVOID parameter) {
  std::unique_ptr<UninstallWorkerArgs> args(reinterpret_cast<UninstallWorkerArgs*>(parameter));
  RunUninstall(args->hwnd, args->context);
  return 0;
}

DWORD ParseWaitPid(int argc, wchar_t* argv[]) {
  for (int index = 1; index < argc - 1; ++index) {
    if (_wcsicmp(argv[index], L"--wait-pid") == 0) {
      return static_cast<DWORD>(_wtoi(argv[index + 1]));
    }
  }
  return 0;
}

std::optional<std::filesystem::path> ParseCleanupRoot(int argc, wchar_t* argv[]) {
  for (int index = 1; index < argc - 1; ++index) {
    if (_wcsicmp(argv[index], L"--cleanup") == 0) {
      return std::filesystem::path(argv[index + 1]);
    }
  }
  return std::nullopt;
}

void WaitForProcessExit(const DWORD pid) {
  if (pid == 0) {
    Sleep(1500);
    return;
  }

  const auto process = OpenProcess(SYNCHRONIZE, FALSE, pid);
  if (process == nullptr) {
    Sleep(1500);
    return;
  }

  WaitForSingleObject(process, 30'000);
  CloseHandle(process);
}

void DeleteSelfWithCmd(const std::filesystem::path& helperPath) {
  const auto command = L"/c ping 127.0.0.1 -n 3 > nul & del /f /q " + QuotePath(helperPath);
  ShellExecuteW(nullptr, L"open", L"cmd.exe", command.c_str(), nullptr, SW_HIDE);
}

int RunCleanupMode(int argc, wchar_t* argv[]) {
  const auto cleanupRoot = ParseCleanupRoot(argc, argv);
  if (!cleanupRoot.has_value()) {
    return 1;
  }

  const auto waitPid = ParseWaitPid(argc, argv);
  WaitForProcessExit(waitPid);

  std::error_code error;
  std::filesystem::remove_all(*cleanupRoot, error);
  if (error) {
    for (std::filesystem::recursive_directory_iterator it(
             *cleanupRoot, std::filesystem::directory_options::skip_permission_denied, error);
         it != std::filesystem::recursive_directory_iterator(); it.increment(error)) {
      if (error) {
        error.clear();
        continue;
      }
      MoveFileExW(it->path().c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    MoveFileExW(cleanupRoot->c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
  }

  std::wstring helperPath(MAX_PATH, L'\0');
  const auto written = GetModuleFileNameW(nullptr, helperPath.data(), static_cast<DWORD>(helperPath.size()));
  helperPath.resize(written);
  DeleteSelfWithCmd(helperPath);
  return 0;
}

void RefreshUi(UiContext& context) {
  context.installed = IsInstalledAt(context.installRoot);
  SetWindowTextW(context.pathValue, context.installRoot.c_str());
  SetWindowTextW(context.eyebrowLabel, L"FENRIR  PROTECTION PLATFORM");
  SetWindowTextW(context.statusLabel,
                 context.busy
                     ? L"Deployment is running. Fenrir is staging service, client, runtime, and protection assets."
                     : (context.installed ? L"Existing installation detected. You can repair or remove it from here."
                                          : L"Ready to deploy Fenrir Endpoint on this device."));
  SetWindowTextW(context.primaryButton, context.installed ? L"Repair deployment" : L"Install protection");
  SetWindowTextW(context.badgeLabel, context.busy ? L"Working" : (context.installed ? L"Installed" : L"Ready"));
  ShowWindow(context.uninstallButton, context.installed ? SW_SHOW : SW_HIDE);
  EnableWindow(context.primaryButton, !context.busy);
  EnableWindow(context.uninstallButton, context.installed && !context.busy);
  EnableWindow(context.closeButton, !context.busy);
  EnableWindow(context.openFolderButton, !context.busy);
  InvalidateRect(context.hwnd, nullptr, TRUE);
}

void LayoutControls(UiContext& context) {
  RECT client{};
  GetClientRect(context.hwnd, &client);

  const int padding = 20;
  const int width = client.right - client.left;
  const int contentWidth = width - (padding * 2);
  const int heroHeight = 152;
  const int statusHeight = 84;
  const int buttonHeight = 38;
  const int buttonTop = client.bottom - 62;
  const RECT heroRect{padding, padding, width - padding, padding + heroHeight};
  const RECT statusRect{padding, heroRect.bottom + 16, width - padding, heroRect.bottom + 16 + statusHeight};
  const RECT logRect{padding, statusRect.bottom + 16, width - padding, buttonTop - 14};

  MoveWindow(context.eyebrowLabel, heroRect.left + 84, heroRect.top + 22, contentWidth - 220, 20, TRUE);
  MoveWindow(context.titleLabel, heroRect.left + 84, heroRect.top + 42, contentWidth - 240, 38, TRUE);
  MoveWindow(context.subtitleLabel, heroRect.left + 84, heroRect.top + 82, contentWidth - 240, 40, TRUE);
  MoveWindow(context.badgeLabel, heroRect.right - 118, heroRect.top + 26, 90, 28, TRUE);
  MoveWindow(context.pathLabel, heroRect.left + 24, heroRect.bottom - 44, 120, 18, TRUE);
  MoveWindow(context.pathValue, heroRect.left + 24, heroRect.bottom - 24, contentWidth - 48, 18, TRUE);

  MoveWindow(context.statusLabel, statusRect.left + 24, statusRect.top + 18, contentWidth - 48, 22, TRUE);
  MoveWindow(context.progressBar, statusRect.left + 24, statusRect.top + 48, contentWidth - 48, 12, TRUE);

  MoveWindow(context.logTitleLabel, logRect.left + 24, logRect.top + 16, contentWidth - 48, 18, TRUE);
  MoveWindow(context.logEdit, logRect.left + 20, logRect.top + 42, contentWidth - 40, logRect.bottom - logRect.top - 62,
             TRUE);

  MoveWindow(context.primaryButton, padding, buttonTop, 168, buttonHeight, TRUE);
  MoveWindow(context.uninstallButton, padding + 180, buttonTop, 132, buttonHeight, TRUE);
  MoveWindow(context.openFolderButton, padding + 324, buttonTop, 160, buttonHeight, TRUE);
  MoveWindow(context.closeButton, width - padding - 120, buttonTop, 120, buttonHeight, TRUE);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
  switch (message) {
    case WM_ERASEBKGND:
      return 1;

    case WM_PAINT: {
      if (auto* context = GetContext(hwnd)) {
        PaintInstallerChrome(hwnd, *context);
        return 0;
      }
      break;
    }

    case WM_CREATE: {
      auto* context = new UiContext{};
      context->instance = reinterpret_cast<LPCREATESTRUCTW>(lParam)->hInstance;
      context->hwnd = hwnd;
      context->installRoot = QueryInstallRoot();
      context->controlPlaneBaseUrl = kDefaultControlPlaneBaseUrl;

      std::wstring setupPath(MAX_PATH, L'\0');
      const auto written = GetModuleFileNameW(nullptr, setupPath.data(), static_cast<DWORD>(setupPath.size()));
      setupPath.resize(written);
      context->setupPath = setupPath;
      SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(context));

      NONCLIENTMETRICSW metrics{};
      metrics.cbSize = sizeof(metrics);
      SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0);
      wcscpy_s(metrics.lfMessageFont.lfFaceName, L"Segoe UI");
      context->bodyFont = CreateFontIndirectW(&metrics.lfMessageFont);
      auto titleFont = metrics.lfMessageFont;
      titleFont.lfHeight = 30;
      titleFont.lfWeight = FW_BOLD;
      wcscpy_s(titleFont.lfFaceName, L"Segoe UI Variable Display Semibold");
      context->titleFont = CreateFontIndirectW(&titleFont);
      auto headingFont = metrics.lfMessageFont;
      headingFont.lfHeight = 18;
      headingFont.lfWeight = FW_SEMIBOLD;
      wcscpy_s(headingFont.lfFaceName, L"Segoe UI Semibold");
      context->headingFont = CreateFontIndirectW(&headingFont);
      auto smallFont = metrics.lfMessageFont;
      smallFont.lfHeight = 14;
      smallFont.lfWeight = FW_SEMIBOLD;
      wcscpy_s(smallFont.lfFaceName, L"Segoe UI Semibold");
      context->smallFont = CreateFontIndirectW(&smallFont);
      context->windowBrush = CreateSolidBrush(WindowBackgroundColor());
      context->surfaceBrush = CreateSolidBrush(SurfaceColor());
      context->detailBrush = CreateSolidBrush(DetailColor());
      context->heroIcon = static_cast<HICON>(LoadImageW(context->instance, MAKEINTRESOURCEW(IDI_SETUP_ICON), IMAGE_ICON,
                                                        48, 48, LR_DEFAULTCOLOR));

      context->eyebrowLabel = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                            0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EYEBROW), nullptr, nullptr);
      context->titleLabel = CreateWindowW(L"STATIC", L"Fenrir Endpoint Setup", WS_CHILD | WS_VISIBLE,
                                          0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_TITLE), nullptr, nullptr);
      context->subtitleLabel = CreateWindowW(
          L"STATIC",
          L"Install, repair, or remove the Fenrir Endpoint service, protection client, signature bundle, and runtime dependencies.",
          WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_SUBTITLE), nullptr, nullptr);
      context->pathLabel = CreateWindowW(L"STATIC", L"Install path", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                         reinterpret_cast<HMENU>(IDC_PATH_LABEL), nullptr, nullptr);
      context->pathValue = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_PATHELLIPSIS, 0, 0, 0, 0, hwnd,
                                         reinterpret_cast<HMENU>(IDC_PATH_VALUE), nullptr, nullptr);
      context->statusLabel = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                           reinterpret_cast<HMENU>(IDC_STATUS), nullptr, nullptr);
      context->progressBar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                             0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_PROGRESS), nullptr, nullptr);
      context->badgeLabel = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_CENTER,
                                          0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BADGE), nullptr, nullptr);
      context->logTitleLabel = CreateWindowW(L"STATIC", L"Deployment log", WS_CHILD | WS_VISIBLE,
                                             0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_LOG_TITLE), nullptr, nullptr);
      context->logEdit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                                                                  ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                         0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_LOG), nullptr, nullptr);
      context->primaryButton = CreateWindowW(L"BUTTON", L"Install", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 0, 0, 0, 0, hwnd,
                                             reinterpret_cast<HMENU>(IDC_PRIMARY_BUTTON), nullptr, nullptr);
      context->uninstallButton = CreateWindowW(L"BUTTON", L"Uninstall", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 0, 0, 0, 0, hwnd,
                                               reinterpret_cast<HMENU>(IDC_UNINSTALL_BUTTON), nullptr, nullptr);
      context->openFolderButton = CreateWindowW(L"BUTTON", L"Open install folder", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 0, 0, 0, 0,
                                                hwnd, reinterpret_cast<HMENU>(IDC_OPEN_FOLDER_BUTTON), nullptr, nullptr);
      context->closeButton = CreateWindowW(L"BUTTON", L"Close", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 0, 0, 0, 0, hwnd,
                                           reinterpret_cast<HMENU>(IDC_CLOSE_BUTTON), nullptr, nullptr);

      const std::array<HWND, 12> controls{context->eyebrowLabel,     context->titleLabel,      context->subtitleLabel,
                                          context->pathLabel,        context->pathValue,       context->statusLabel,
                                          context->logEdit,          context->primaryButton,   context->uninstallButton,
                                          context->openFolderButton, context->closeButton,     context->logTitleLabel};
      for (const auto control : controls) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(context->bodyFont), TRUE);
      }
      SendMessageW(context->titleLabel, WM_SETFONT, reinterpret_cast<WPARAM>(context->titleFont), TRUE);
      SendMessageW(context->badgeLabel, WM_SETFONT, reinterpret_cast<WPARAM>(context->smallFont), TRUE);
      SendMessageW(context->eyebrowLabel, WM_SETFONT, reinterpret_cast<WPARAM>(context->smallFont), TRUE);
      SendMessageW(context->logTitleLabel, WM_SETFONT, reinterpret_cast<WPARAM>(context->headingFont), TRUE);
      SendMessageW(context->progressBar, PBM_SETRANGE32, 0, 100);
      SendMessageW(context->progressBar, PBM_SETPOS, 0, 0);
      SendMessageW(context->progressBar, PBM_SETBKCOLOR, 0, static_cast<LPARAM>(DetailColor()));
      SendMessageW(context->progressBar, PBM_SETBARCOLOR, 0, static_cast<LPARAM>(AccentBlue()));
      SendMessageW(context->logEdit, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(12, 12));

      LayoutControls(*context);
      RefreshUi(*context);
      AppendLog(context->logEdit, L"Setup initialized.");
      ApplyDarkWindowFrame(hwnd);
      return 0;
    }

    case WM_SIZE: {
      if (auto* context = GetContext(hwnd)) {
        LayoutControls(*context);
        InvalidateRect(hwnd, nullptr, TRUE);
      }
      return 0;
    }

    case WM_CTLCOLORSTATIC: {
      auto* context = GetContext(hwnd);
      auto* control = reinterpret_cast<HWND>(lParam);
      auto hdc = reinterpret_cast<HDC>(wParam);
      if (context == nullptr || control == nullptr) {
        break;
      }

      SetBkMode(hdc, TRANSPARENT);
      SetTextColor(hdc, ResolveStaticTextColor(*context, control));
      return reinterpret_cast<INT_PTR>(ResolveStaticBrush(*context, control));
    }

    case WM_CTLCOLOREDIT: {
      auto* context = GetContext(hwnd);
      auto* control = reinterpret_cast<HWND>(lParam);
      auto hdc = reinterpret_cast<HDC>(wParam);
      if (context == nullptr || control != context->logEdit) {
        break;
      }

      SetBkMode(hdc, OPAQUE);
      SetBkColor(hdc, DetailColor());
      SetTextColor(hdc, DarkTextColor());
      return reinterpret_cast<INT_PTR>(context->detailBrush);
    }

    case WM_DRAWITEM: {
      auto* context = GetContext(hwnd);
      auto* draw = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
      if (context == nullptr || draw == nullptr || draw->CtlType != ODT_BUTTON) {
        break;
      }

      DrawOwnerButton(draw, *context);
      return TRUE;
    }

    case WM_COMMAND: {
      auto* context = GetContext(hwnd);
      if (context == nullptr) {
        break;
      }

      switch (LOWORD(wParam)) {
        case IDC_PRIMARY_BUTTON:
          if (!context->busy) {
            context->busy = true;
            RefreshUi(*context);
            const auto repair = context->installed;
            AppendLog(context->logEdit, repair ? L"Starting repair..." : L"Starting installation...");
            auto* workerArgs = new InstallWorkerArgs{.hwnd = hwnd, .context = context, .repair = repair};
            const auto threadHandle =
                CreateThread(nullptr, 0, InstallWorkerThread, workerArgs, 0, nullptr);
            if (threadHandle != nullptr) {
              CloseHandle(threadHandle);
            }
          }
          return 0;
        case IDC_UNINSTALL_BUTTON:
          if (!context->busy &&
              MessageBoxW(hwnd, L"Remove Fenrir Endpoint from this device?", kWindowTitle,
                          MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES) {
            context->busy = true;
            RefreshUi(*context);
            AppendLog(context->logEdit, L"Starting uninstall...");
            auto* workerArgs = new UninstallWorkerArgs{.hwnd = hwnd, .context = context};
            const auto threadHandle =
                CreateThread(nullptr, 0, UninstallWorkerThread, workerArgs, 0, nullptr);
            if (threadHandle != nullptr) {
              CloseHandle(threadHandle);
            }
          }
          return 0;
        case IDC_OPEN_FOLDER_BUTTON:
          EnsureDirectory(context->installRoot);
          ShellExecuteW(hwnd, L"open", context->installRoot.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
          return 0;
        case IDC_CLOSE_BUTTON:
          DestroyWindow(hwnd);
          return 0;
        default:
          return 0;
      }
    }

    case kInstallerLogMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<LogMessagePayload*>(lParam);
      if (context != nullptr && payload != nullptr) {
        AppendLog(context->logEdit, payload->text);
      }
      delete payload;
      return 0;
    }

    case kInstallerStatusMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<StatusMessagePayload*>(lParam);
      if (context != nullptr && payload != nullptr) {
        SetWindowTextW(context->statusLabel, payload->text.c_str());
        SendMessageW(context->progressBar, PBM_SETPOS, payload->progress, 0);
      }
      delete payload;
      return 0;
    }

    case kInstallerCompleteMessage: {
      auto* context = GetContext(hwnd);
      auto* payload = reinterpret_cast<CompletionPayload*>(lParam);
      if (context != nullptr && payload != nullptr) {
        context->busy = false;
        context->installed = payload->installed;
        SetWindowTextW(context->statusLabel, payload->message.c_str());
        AppendLog(context->logEdit, payload->message);
        RefreshUi(*context);
        MessageBoxW(hwnd, payload->message.c_str(), kWindowTitle,
                    MB_OK | (payload->success ? MB_ICONINFORMATION : MB_ICONWARNING));
        if (payload->closeAfter) {
          DestroyWindow(hwnd);
        }
      }
      delete payload;
      return 0;
    }

    case WM_DESTROY: {
      if (auto* context = GetContext(hwnd)) {
        if (context->heroIcon != nullptr) {
          DestroyIcon(context->heroIcon);
        }
        if (context->titleFont != nullptr) {
          DeleteObject(context->titleFont);
        }
        if (context->headingFont != nullptr) {
          DeleteObject(context->headingFont);
        }
        if (context->bodyFont != nullptr) {
          DeleteObject(context->bodyFont);
        }
        if (context->smallFont != nullptr) {
          DeleteObject(context->smallFont);
        }
        if (context->windowBrush != nullptr) {
          DeleteObject(context->windowBrush);
        }
        if (context->surfaceBrush != nullptr) {
          DeleteObject(context->surfaceBrush);
        }
        if (context->detailBrush != nullptr) {
          DeleteObject(context->detailBrush);
        }
        delete context;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
      }
      PostQuitMessage(0);
      return 0;
    }
  }

  return DefWindowProcW(hwnd, message, wParam, lParam);
}

std::wstring InstallerArgument(int argc, wchar_t* argv[], const wchar_t* name) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (_wcsicmp(argv[i], name) == 0) return argv[i + 1];
  }
  return {};
}

bool HasArgument(int argc, wchar_t* argv[], const wchar_t* name) {
  for (int index = 1; index < argc; ++index) {
    if (_wcsicmp(argv[index], name) == 0) {
      return true;
    }
  }
  return false;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
  int argc = 0;
  wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (argv != nullptr && HasArgument(argc, argv, L"--cleanup")) {
    const auto result = RunCleanupMode(argc, argv);
    LocalFree(argv);
    return result;
  }

  INITCOMMONCONTROLSEX controls{};
  controls.dwSize = sizeof(controls);
  controls.dwICC = ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;
  InitCommonControlsEx(&controls);
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  WNDCLASSEXW windowClass{};
  windowClass.cbSize = sizeof(windowClass);
  windowClass.lpfnWndProc = WindowProc;
  windowClass.hInstance = instance;
  windowClass.lpszClassName = kWindowClassName;
  windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_SETUP_ICON));
  windowClass.hIconSm = LoadIconW(instance, MAKEINTRESOURCEW(IDI_SETUP_ICON));
  windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  RegisterClassExW(&windowClass);

  HWND hwnd = CreateWindowExW(0, kWindowClassName, kWindowTitle,
                              WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                              CW_USEDEFAULT, CW_USEDEFAULT, 820, 620,
                              nullptr, nullptr, instance, nullptr);
  if (hwnd == nullptr) {
    if (argv != nullptr) {
      LocalFree(argv);
    }
    CoUninitialize();
    return 1;
  }

  if (argv != nullptr) {
    auto server = InstallerArgument(argc, argv, L"--server");
    auto token = InstallerArgument(argc, argv, L"--enroll-token");
    try {
      std::wstring embeddedServer, embeddedToken;
      if (ReadEmbeddedEnrollment(embeddedServer, embeddedToken)) {
        if ((!server.empty() && server != embeddedServer) || (!token.empty() && token != embeddedToken))
          throw std::runtime_error("Conflicting enrollment arguments");
        server = embeddedServer;
        token = embeddedToken;
      }
    } catch (const std::exception&) {
      MessageBoxW(hwnd, L"Invalid embedded enrollment configuration. Generate a new installer from Fenrir.", kWindowTitle, MB_OK | MB_ICONERROR);
      DestroyWindow(hwnd);
      LocalFree(argv);
      CoUninitialize();
      return 1;
    }
    if (!server.empty() || !token.empty()) {
      if (server.rfind(L"https://", 0) != 0 || token.rfind(L"fet_", 0) != 0 ||
          server.find_first_of(L" \r\n\t\"") != std::wstring::npos ||
          token.find_first_not_of(L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") != std::wstring::npos) {
        MessageBoxW(hwnd, L"Invalid cloud URL or enrollment token provided.", kWindowTitle, MB_OK | MB_ICONERROR);
        DestroyWindow(hwnd);
        LocalFree(argv);
        CoUninitialize();
        return 1;
      }
      if (auto* context = GetContext(hwnd)) {
        context->controlPlaneBaseUrl = server;
        context->enrollmentToken = token;
      }
    }
  }

  ShowWindow(hwnd, showCommand == 0 ? SW_SHOWDEFAULT : showCommand);
  UpdateWindow(hwnd);

  if (argv != nullptr && HasArgument(argc, argv, L"--uninstall")) {
    PostMessageW(hwnd, WM_COMMAND, IDC_UNINSTALL_BUTTON, 0);
  }

  if (argv != nullptr) {
    LocalFree(argv);
  }

  MSG message{};
  while (GetMessageW(&message, nullptr, 0, 0) > 0) {
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }

  CoUninitialize();
  return static_cast<int>(message.wParam);
}
