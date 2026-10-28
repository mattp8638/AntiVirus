cmake_minimum_required(VERSION 3.24)

project(AntiVirusAgentService LANGUAGES C CXX)

# Source fingerprint stamped by the cloud image build (deploy/Dockerfile); agents self-update when it differs
# from the server's. Local builds are "dev" and never self-update.
set(FENRIR_BUILD_ID "dev" CACHE STRING "Agent source fingerprint")
if(NOT FENRIR_BUILD_ID MATCHES "^[a-z0-9]+$")
  message(FATAL_ERROR "FENRIR_BUILD_ID must be lowercase letters and digits")
endif()
add_compile_definitions(FENRIR_BUILD_ID="${FENRIR_BUILD_ID}")

# Windows SDK min/max macros corrupt std::min/std::max declarations across
# MSVC builds. Keep NOMINMAX on every C++ Windows target and dependency.
add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN WINVER=0x0A00 _WIN32_WINNT=0x0A00 NTDDI_VERSION=0x0A000000)

# Source files contain Unicode phishing-homoglyph rules: MSVC must decode
# repository source as UTF-8 rather than the runner's system code page.
if(MSVC)
  add_compile_options(/utf-8)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(ANTIVIRUS_WINDOWS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
set(ANTIVIRUS_DEV_OUTPUT_ROOT "${ANTIVIRUS_WINDOWS_ROOT}/out/dev" CACHE PATH
    "Fenrir development-stage output root.")
set(ANTIVIRUS_INSTALL_OUTPUT_ROOT "${ANTIVIRUS_WINDOWS_ROOT}/out/install" CACHE PATH
    "Fenrir installer output root.")
set(ANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD OFF CACHE BOOL
  "Require staged minifilter INF/SYS/CAT payloads in the development output root.")
set(ANTIVIRUS_WEBVIEW2_BOOTSTRAPPER "" CACHE FILEPATH
  "Optional path to a Microsoft Edge WebView2 runtime installer to embed in FenrirSetup.")
set(ANTIVIRUS_ENABLE_BUILD_VALIDATION ON CACHE BOOL
  "Enable build-time minifilter package validation target.")
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}" ANTIVIRUS_DEV_OUTPUT_ROOT)
file(TO_CMAKE_PATH "${ANTIVIRUS_INSTALL_OUTPUT_ROOT}" ANTIVIRUS_INSTALL_OUTPUT_ROOT)
set(ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT "${ANTIVIRUS_DEV_OUTPUT_ROOT}/tools")
file(MAKE_DIRECTORY "${ANTIVIRUS_DEV_OUTPUT_ROOT}")
file(MAKE_DIRECTORY "${ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT}")
file(MAKE_DIRECTORY "${ANTIVIRUS_INSTALL_OUTPUT_ROOT}")

function(antivirus_apply_portable_runtime target_name)
  if(MINGW)
    # -static links the GCC, C++ and winpthread runtimes into the binary, so a clean
    # Windows PC needs no extra DLLs (libwinpthread-1.dll etc.). Windows system DLLs stay dynamic.
    get_target_property(target_type ${target_name} TYPE)
    if(target_type STREQUAL "EXECUTABLE" OR target_type STREQUAL "SHARED_LIBRARY")
      target_link_options(${target_name} PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
  endif()
endfunction()

function(antivirus_set_runtime_output target_name output_dir)
  set_target_properties(${target_name} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${output_dir}"
  )

  if(CMAKE_CONFIGURATION_TYPES)
    foreach(config ${CMAKE_CONFIGURATION_TYPES})
      string(TOUPPER "${config}" config_upper)
      set_target_properties(${target_name} PROPERTIES
        "RUNTIME_OUTPUT_DIRECTORY_${config_upper}" "${output_dir}"
      )
    endforeach()
  endif()
endfunction()

add_library(antivirus-sqlite3 STATIC
  ../../../third_party/sqlite/sqlite-amalgamation-3510300/sqlite3.c
)

target_include_directories(antivirus-sqlite3 PUBLIC
  ../../../third_party/sqlite/sqlite-amalgamation-3510300
)
target_compile_definitions(antivirus-sqlite3 PRIVATE
  SQLITE_DQS=0
  SQLITE_THREADSAFE=1
  SQLITE_OMIT_LOAD_EXTENSION
)

add_library(antivirus-agent-core STATIC
  ../sensor/etw/src/ProcessEtwSensor.cpp
  ../sensor/wfp/src/NetworkIsolationManager.cpp
  src/AmsiEvidenceRecorder.cpp
  src/AmsiScanEngine.cpp
  src/AgentConfig.cpp
  src/AgentService.cpp
  src/CommandJournalStore.cpp
  src/ControlPlaneClient.cpp
  src/ContextAwareness.cpp
  src/CryptoUtils.cpp
  src/DestinationEnforcementBridge.cpp
  src/DestinationEventRecorder.cpp
  src/DestinationProtection.cpp
  src/DestinationVerdictEngine.cpp
  src/DeviceInventoryCollector.cpp
  src/EndpointClient.cpp
  src/EvidenceRecorder.cpp
  src/FileDeltaTracker.cpp
  src/FileInventory.cpp
  src/FileSnapshotCollector.cpp
  src/HardeningManager.cpp
  src/LocalScanRunner.cpp
  src/LocalControlChannel.cpp
  src/LocalSecurity.cpp
  src/LocalStateStore.cpp
  src/PatchOrchestrator.cpp
  src/PhishingHeuristics.cpp
  src/ProcessDeltaTracker.cpp
  src/ProcessInventory.cpp
  src/ProcessSnapshotCollector.cpp
  src/ReputationLookupPhase1.cpp
  src/QuarantineStore.cpp
  src/RealtimeProtectionBroker.cpp
  src/RemediationEngine.cpp
  src/RuntimeTrustValidator.cpp
  src/RuntimeDatabase.cpp
  src/ScanEngine.cpp
  src/SelfTestRunner.cpp
  src/StringUtils.cpp
  src/SupportBundleService.cpp
  src/ServiceInventory.cpp
  src/ServiceSnapshotCollector.cpp
  src/TelemetryQueueStore.cpp
  src/UpdaterService.cpp
  src/WscCoexistenceManager.cpp
  src/BehaviorRules.cpp
  src/DeviceControl.cpp
  src/ExtendedPolicy.cpp
  src/MlStaticModel.cpp
  src/ProcessGuard.cpp
  src/YaraScanner.cpp
  src/EventEnvelope.cpp
  src/RmmExecutors.cpp
  src/WebSocketClient.cpp
  src/NetworkProbe.cpp
  src/BundleArchive.cpp
  src/FirewallPolicy.cpp
  src/LocalAdminRotation.cpp
  src/RansomwareDetector.cpp
  src/RansomwareShield.cpp
  src/BruteForceTracker.cpp
  src/BruteForceGuard.cpp
  src/AdMonitor.cpp
  src/AdEventRules.cpp
  src/RegistryWatcher.cpp
  src/CrashReporter.cpp
  src/SystemProfile.cpp
)

target_include_directories(antivirus-agent-core PUBLIC include ../shared/include ../sensor/etw/include ../sensor/wfp/include)

# The Windows system-profile collector (src/SystemProfileScript.ps1) is embedded like the agent window's page:
# short raw-string chunks, so it ships inside the service binary and cannot be swapped on disk.
set(SYSTEM_PROFILE_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/src/SystemProfileScript.ps1")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${SYSTEM_PROFILE_SCRIPT}")
file(READ "${SYSTEM_PROFILE_SCRIPT}" SYSTEM_PROFILE_CONTENT)
string(LENGTH "${SYSTEM_PROFILE_CONTENT}" SYSTEM_PROFILE_LENGTH)
set(SYSTEM_PROFILE_CHUNKS "")
set(SYSTEM_PROFILE_OFFSET 0)
while(SYSTEM_PROFILE_OFFSET LESS SYSTEM_PROFILE_LENGTH)
  string(SUBSTRING "${SYSTEM_PROFILE_CONTENT}" ${SYSTEM_PROFILE_OFFSET} 6000 SYSTEM_PROFILE_PART)
  string(APPEND SYSTEM_PROFILE_CHUNKS "    R\"FENRIRPS(${SYSTEM_PROFILE_PART})FENRIRPS\",\n")
  math(EXPR SYSTEM_PROFILE_OFFSET "${SYSTEM_PROFILE_OFFSET} + 6000")
endwhile()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/generated/SystemProfileScript.h.tmp"
  "#pragma once\n// Generated from src/SystemProfileScript.ps1 by CMake. Do not edit.\n"
  "inline const char* const kSystemProfileScriptParts[] = {\n${SYSTEM_PROFILE_CHUNKS}};\n")
configure_file("${CMAKE_CURRENT_BINARY_DIR}/generated/SystemProfileScript.h.tmp" "${CMAKE_CURRENT_BINARY_DIR}/generated/SystemProfileScript.h" COPYONLY)
target_include_directories(antivirus-agent-core PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(antivirus-agent-core PUBLIC antivirus-sqlite3 winhttp ole32 oleaut32 bcrypt advapi32 tdh crypt32 wintrust fwpuclnt iphlpapi shell32 ws2_32 wtsapi32 userenv netapi32 urlmon wevtapi)
antivirus_apply_portable_runtime(antivirus-agent-core)

# Remote access helper: started by the service in the signed-in user's session.
add_executable(fenrir-remote WIN32
  ../tools/remotehelper/src/RemoteHelperMain.cpp
  src/WebSocketClient.cpp
  src/ExtendedPolicy.cpp
  src/BehaviorRules.cpp
  src/StringUtils.cpp
)
target_include_directories(fenrir-remote PRIVATE include ../shared/include)
target_link_libraries(fenrir-remote PRIVATE winhttp gdiplus ole32 wtsapi32 advapi32 shell32 user32 gdi32)
if(MINGW)
  target_link_options(fenrir-remote PRIVATE -municode)
endif()
antivirus_set_runtime_output(fenrir-remote "${ANTIVIRUS_DEV_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(fenrir-remote)

add_library(antivirus-amsi-provider-core STATIC
  ../provider/amsi/src/AntiVirusAmsiProvider.cpp
)

target_include_directories(antivirus-amsi-provider-core PRIVATE
  include
  ../provider/amsi/include
)
target_link_libraries(antivirus-amsi-provider-core PRIVATE antivirus-agent-core ole32 advapi32)
antivirus_apply_portable_runtime(antivirus-amsi-provider-core)

add_library(antivirus-amsi-provider SHARED
  ../provider/amsi/src/AntiVirusAmsiProviderDll.cpp
)

target_include_directories(antivirus-amsi-provider PRIVATE
  include
  ../provider/amsi/include
)
target_link_libraries(antivirus-amsi-provider PRIVATE antivirus-amsi-provider-core antivirus-agent-core ole32 advapi32)
set_target_properties(antivirus-amsi-provider PROPERTIES OUTPUT_NAME "fenrir-amsi-provider" PREFIX "")
if(MSVC)
  target_link_options(antivirus-amsi-provider PRIVATE
    "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/../provider/amsi/AmsiExports.def")
endif()
antivirus_set_runtime_output(antivirus-amsi-provider "${ANTIVIRUS_DEV_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(antivirus-amsi-provider)

add_executable(antivirus-agent-service
  src/ServiceMain.cpp
)

target_link_libraries(antivirus-agent-service PRIVATE antivirus-agent-core advapi32)
if(MINGW)
  target_link_options(antivirus-agent-service PRIVATE -municode)
endif()
set_target_properties(antivirus-agent-service PROPERTIES OUTPUT_NAME "fenrir-agent-service")
antivirus_set_runtime_output(antivirus-agent-service "${ANTIVIRUS_DEV_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(antivirus-agent-service)

add_executable(antivirus-endpoint-client WIN32
  ../tools/endpointui/src/endpointui.rc
  ../tools/endpointui/src/EndpointClientMain.cpp
)

target_include_directories(antivirus-endpoint-client PRIVATE ../tools/endpointui/src include ../third_party/webview2/include)
# The agent window's page lives in tools/endpointui/web/protection-centre.html (plain ASCII). It is embedded as
# short raw-string chunks because MSVC limits a single string literal to about 64 KB.
set(ENDPOINT_UI_PAGE "${CMAKE_CURRENT_SOURCE_DIR}/../tools/endpointui/web/protection-centre.html")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${ENDPOINT_UI_PAGE}")
file(READ "${ENDPOINT_UI_PAGE}" ENDPOINT_UI_PAGE_CONTENT)
# Every occurrence of a placeholder is filled in at runtime, so each must appear exactly once (a copy in a
# comment once doubled the page past WebView2's 2 MB NavigateToString limit and left the window blank).
foreach(placeholder __FENRIR_LOGO_URI__ __FENRIR_INITIAL_STATE__)
  string(REGEX MATCHALL "${placeholder}" placeholder_hits "${ENDPOINT_UI_PAGE_CONTENT}")
  list(LENGTH placeholder_hits placeholder_count)
  if(NOT placeholder_count EQUAL 1)
    message(FATAL_ERROR "protection-centre.html must contain ${placeholder} exactly once (found ${placeholder_count})")
  endif()
endforeach()
string(LENGTH "${ENDPOINT_UI_PAGE_CONTENT}" ENDPOINT_UI_PAGE_LENGTH)
set(ENDPOINT_UI_PAGE_CHUNKS "")
set(ENDPOINT_UI_PAGE_OFFSET 0)
while(ENDPOINT_UI_PAGE_OFFSET LESS ENDPOINT_UI_PAGE_LENGTH)
  string(SUBSTRING "${ENDPOINT_UI_PAGE_CONTENT}" ${ENDPOINT_UI_PAGE_OFFSET} 6000 ENDPOINT_UI_PAGE_PART)
  string(APPEND ENDPOINT_UI_PAGE_CHUNKS "    LR\"FENRIRPAGE(${ENDPOINT_UI_PAGE_PART})FENRIRPAGE\",\n")
  math(EXPR ENDPOINT_UI_PAGE_OFFSET "${ENDPOINT_UI_PAGE_OFFSET} + 6000")
endwhile()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/generated/EndpointUiPage.h.tmp"
  "#pragma once\n// Generated from tools/endpointui/web/protection-centre.html by CMake. Do not edit.\n"
  "inline const wchar_t* const kEndpointUiPageParts[] = {\n${ENDPOINT_UI_PAGE_CHUNKS}};\n")
configure_file("${CMAKE_CURRENT_BINARY_DIR}/generated/EndpointUiPage.h.tmp" "${CMAKE_CURRENT_BINARY_DIR}/generated/EndpointUiPage.h" COPYONLY)
target_include_directories(antivirus-endpoint-client PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(antivirus-endpoint-client PRIVATE antivirus-agent-core comctl32 ole32 uxtheme dwmapi)
target_compile_definitions(antivirus-endpoint-client PRIVATE UNICODE _UNICODE)
if(MINGW)
  target_link_options(antivirus-endpoint-client PRIVATE -municode)
endif()
set_target_properties(antivirus-endpoint-client PROPERTIES OUTPUT_NAME "fenrir-endpoint-client")
antivirus_set_runtime_output(antivirus-endpoint-client "${ANTIVIRUS_DEV_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(antivirus-endpoint-client)

file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/webview2/runtime/x64/WebView2Loader.dll" WEBVIEW2_LOADER_DLL)
if(NOT EXISTS "${WEBVIEW2_LOADER_DLL}")
  message(FATAL_ERROR "Could not locate WebView2Loader.dll in the vendored WebView2 runtime.")
endif()
add_custom_command(TARGET antivirus-endpoint-client POST_BUILD
  BYPRODUCTS "${ANTIVIRUS_DEV_OUTPUT_ROOT}/WebView2Loader.dll"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${WEBVIEW2_LOADER_DLL}"
          "$<TARGET_FILE_DIR:antivirus-endpoint-client>/WebView2Loader.dll"
)

add_executable(antivirus-pam-client WIN32
  ../tools/pamui/src/pamui.rc
  ../tools/pamui/src/PamClientMain.cpp
)

target_include_directories(antivirus-pam-client PRIVATE ../tools/pamui/src include)
target_link_libraries(antivirus-pam-client PRIVATE comdlg32 comctl32 shell32)
target_compile_definitions(antivirus-pam-client PRIVATE UNICODE _UNICODE)
if(MINGW)
  target_link_options(antivirus-pam-client PRIVATE -municode)
endif()
set_target_properties(antivirus-pam-client PROPERTIES OUTPUT_NAME "fenrir-pam")
antivirus_set_runtime_output(antivirus-pam-client "${ANTIVIRUS_DEV_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(antivirus-pam-client)

add_executable(antivirus-scannercli
  ../tools/scannercli/src/ScannerCliMain.cpp
)

target_include_directories(antivirus-scannercli PRIVATE include)
target_link_libraries(antivirus-scannercli PRIVATE antivirus-agent-core)
if(MINGW)
  target_link_options(antivirus-scannercli PRIVATE -municode)
endif()
set_target_properties(antivirus-scannercli PROPERTIES OUTPUT_NAME "fenrir-scannercli")
antivirus_set_runtime_output(antivirus-scannercli "${ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(antivirus-scannercli)

add_executable(antivirus-amsitestcli
  ../tools/amsitestcli/src/AmsiTestCliMain.cpp
)

target_include_directories(antivirus-amsitestcli PRIVATE
  include
  ../provider/amsi/include
)
target_link_libraries(antivirus-amsitestcli PRIVATE antivirus-amsi-provider-core antivirus-agent-core ole32)
if(MINGW)
  target_link_options(antivirus-amsitestcli PRIVATE -municode)
endif()
set_target_properties(antivirus-amsitestcli PROPERTIES OUTPUT_NAME "fenrir-amsitestcli")
antivirus_set_runtime_output(antivirus-amsitestcli "${ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(antivirus-amsitestcli)

add_executable(antivirus-etwtestcli
  ../tools/etwtestcli/src/EtwTestCliMain.cpp
)

target_include_directories(antivirus-etwtestcli PRIVATE
  include
  ../sensor/etw/include
)
target_link_libraries(antivirus-etwtestcli PRIVATE antivirus-agent-core)
if(MINGW)
  target_link_options(antivirus-etwtestcli PRIVATE -municode)
endif()
set_target_properties(antivirus-etwtestcli PROPERTIES OUTPUT_NAME "fenrir-etwtestcli")
antivirus_set_runtime_output(antivirus-etwtestcli "${ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(antivirus-etwtestcli)

add_executable(antivirus-wfptestcli
  ../tools/wfptestcli/src/WfpTestCliMain.cpp
)

target_include_directories(antivirus-wfptestcli PRIVATE
  include
  ../sensor/wfp/include
)
target_link_libraries(antivirus-wfptestcli PRIVATE antivirus-agent-core)
if(MINGW)
  target_link_options(antivirus-wfptestcli PRIVATE -municode)
endif()
set_target_properties(antivirus-wfptestcli PROPERTIES OUTPUT_NAME "fenrir-wfptestcli")
antivirus_set_runtime_output(antivirus-wfptestcli "${ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(antivirus-wfptestcli)

set(INSTALLER_NATIVE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../installer/native)
set(INSTALLER_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/installer-generated)
file(MAKE_DIRECTORY ${INSTALLER_GENERATED_DIR})

get_filename_component(ANTIVIRUS_CXX_COMPILER_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
find_file(SETUP_WINPTHREAD_DLL
  NAMES libwinpthread-1.dll
  PATHS
    "${ANTIVIRUS_CXX_COMPILER_DIR}"
    "${ANTIVIRUS_CXX_COMPILER_DIR}/../bin"
  NO_DEFAULT_PATH
)

if(MINGW AND NOT SETUP_WINPTHREAD_DLL)
  execute_process(COMMAND "${CMAKE_CXX_COMPILER}" -print-file-name=libwinpthread-1.dll
    OUTPUT_VARIABLE SETUP_WINPTHREAD_DLL OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

if(MINGW AND NOT EXISTS "${SETUP_WINPTHREAD_DLL}")
  message(FATAL_ERROR "Could not locate libwinpthread-1.dll next to the configured MinGW compiler.")
endif()

file(TO_CMAKE_PATH "${INSTALLER_NATIVE_DIR}/include/SetupResourceIds.h" SETUP_RESOURCE_HEADER)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/fenrir-agent-service.exe" SETUP_SERVICE_EXE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/fenrir-endpoint-client.exe" SETUP_ENDPOINT_CLIENT_EXE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/fenrir-pam.exe" SETUP_PAM_EXE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/fenrir-remote.exe" SETUP_REMOTE_HELPER_EXE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/WebView2Loader.dll" SETUP_WEBVIEW2_LOADER_DLL)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/fenrir-amsi-provider.dll" SETUP_AMSI_PROVIDER_DLL)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT}/fenrir-scannercli.exe" SETUP_SCANNERCLI_EXE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT}/fenrir-amsitestcli.exe" SETUP_AMSITESTCLI_EXE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT}/fenrir-etwtestcli.exe" SETUP_ETWTESTCLI_EXE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_TOOLS_OUTPUT_ROOT}/fenrir-wfptestcli.exe" SETUP_WFPTESTCLI_EXE)
file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../signatures/default-signatures.tsv" SETUP_SIGNATURES_FILE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/driver/AntivirusMinifilter.inf" SETUP_DRIVER_INF_FILE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/driver/AntivirusMinifilter.sys" SETUP_DRIVER_SYS_FILE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/driver/AntivirusMinifilter.cat" SETUP_DRIVER_CAT_FILE)
file(TO_CMAKE_PATH "${ANTIVIRUS_DEV_OUTPUT_ROOT}/driver/README.md" SETUP_DRIVER_README_FILE)
set(SETUP_WINPTHREAD_RESOURCE_LINE "")
set(SETUP_WINPTHREAD_RESOURCE_DEPENDENCY "")
if(MINGW)
  file(TO_CMAKE_PATH "${SETUP_WINPTHREAD_DLL}" SETUP_WINPTHREAD_DLL_CMAKE)
  set(SETUP_WINPTHREAD_RESOURCE_LINE "IDR_PAYLOAD_WINPTHREAD RCDATA \"${SETUP_WINPTHREAD_DLL_CMAKE}\"")
  set(SETUP_WINPTHREAD_RESOURCE_DEPENDENCY "${SETUP_WINPTHREAD_DLL_CMAKE}")
endif()

if(ANTIVIRUS_REQUIRE_MINIFILTER_PAYLOAD)
  foreach(required_driver_payload
      "${SETUP_DRIVER_INF_FILE}"
      "${SETUP_DRIVER_SYS_FILE}"
      "${SETUP_DRIVER_CAT_FILE}")
    if(NOT EXISTS "${required_driver_payload}")
      message(FATAL_ERROR "Required staged minifilter payload is missing: ${required_driver_payload}")
    endif()
  endforeach()
endif()

set(SETUP_DRIVER_INF_RESOURCE_LINE "")
set(SETUP_DRIVER_README_RESOURCE_LINE "")
set(SETUP_DRIVER_INF_DEPENDENCY "")
set(SETUP_DRIVER_README_DEPENDENCY "")
if(EXISTS "${SETUP_DRIVER_INF_FILE}")
  set(SETUP_DRIVER_INF_RESOURCE_LINE
      "IDR_PAYLOAD_DRIVER_INF RCDATA \"${SETUP_DRIVER_INF_FILE}\"")
  set(SETUP_DRIVER_INF_DEPENDENCY "${SETUP_DRIVER_INF_FILE}")
endif()
if(EXISTS "${SETUP_DRIVER_README_FILE}")
  set(SETUP_DRIVER_README_RESOURCE_LINE
      "IDR_PAYLOAD_DRIVER_README RCDATA \"${SETUP_DRIVER_README_FILE}\"")
  set(SETUP_DRIVER_README_DEPENDENCY "${SETUP_DRIVER_README_FILE}")
endif()

set(SETUP_DRIVER_SYS_RESOURCE_LINE "")
set(SETUP_DRIVER_CAT_RESOURCE_LINE "")
set(SETUP_DRIVER_SYS_DEPENDENCY "")
set(SETUP_DRIVER_CAT_DEPENDENCY "")
if(EXISTS "${SETUP_DRIVER_SYS_FILE}")
  set(SETUP_DRIVER_SYS_RESOURCE_LINE
      "IDR_PAYLOAD_DRIVER_SYS RCDATA \"${SETUP_DRIVER_SYS_FILE}\"")
  set(SETUP_DRIVER_SYS_DEPENDENCY "${SETUP_DRIVER_SYS_FILE}")
endif()
if(EXISTS "${SETUP_DRIVER_CAT_FILE}")
  set(SETUP_DRIVER_CAT_RESOURCE_LINE
      "IDR_PAYLOAD_DRIVER_CAT RCDATA \"${SETUP_DRIVER_CAT_FILE}\"")
  set(SETUP_DRIVER_CAT_DEPENDENCY "${SETUP_DRIVER_CAT_FILE}")
endif()

set(SETUP_WEBVIEW2_BOOTSTRAPPER_RESOURCE_LINE "")
set(SETUP_WEBVIEW2_BOOTSTRAPPER_RESOURCE_DEPENDENCY "")
if(ANTIVIRUS_WEBVIEW2_BOOTSTRAPPER)
  if(NOT EXISTS "${ANTIVIRUS_WEBVIEW2_BOOTSTRAPPER}")
    message(FATAL_ERROR "Configured ANTIVIRUS_WEBVIEW2_BOOTSTRAPPER was not found: ${ANTIVIRUS_WEBVIEW2_BOOTSTRAPPER}")
  endif()

  file(TO_CMAKE_PATH "${ANTIVIRUS_WEBVIEW2_BOOTSTRAPPER}" SETUP_WEBVIEW2_BOOTSTRAPPER_EXE)
  set(SETUP_WEBVIEW2_BOOTSTRAPPER_RESOURCE_LINE
      "IDR_PAYLOAD_WEBVIEW2_BOOTSTRAPPER RCDATA \"${SETUP_WEBVIEW2_BOOTSTRAPPER_EXE}\"")
  set(SETUP_WEBVIEW2_BOOTSTRAPPER_RESOURCE_DEPENDENCY "${SETUP_WEBVIEW2_BOOTSTRAPPER_EXE}")
endif()

file(GENERATE OUTPUT ${INSTALLER_GENERATED_DIR}/SetupPayload.rc CONTENT
"#include \"${SETUP_RESOURCE_HEADER}\"\n\
IDR_PAYLOAD_SERVICE RCDATA \"${SETUP_SERVICE_EXE}\"\n\
IDR_PAYLOAD_ENDPOINT_CLIENT RCDATA \"${SETUP_ENDPOINT_CLIENT_EXE}\"\n\
IDR_PAYLOAD_PAM_CLIENT RCDATA \"${SETUP_PAM_EXE}\"\n\
IDR_PAYLOAD_REMOTE_HELPER RCDATA \"${SETUP_REMOTE_HELPER_EXE}\"\n\
IDR_PAYLOAD_WEBVIEW2_LOADER RCDATA \"${SETUP_WEBVIEW2_LOADER_DLL}\"\n\
${SETUP_WEBVIEW2_BOOTSTRAPPER_RESOURCE_LINE}\n\
IDR_PAYLOAD_AMSI_PROVIDER RCDATA \"${SETUP_AMSI_PROVIDER_DLL}\"\n\
IDR_PAYLOAD_SCANNERCLI RCDATA \"${SETUP_SCANNERCLI_EXE}\"\n\
IDR_PAYLOAD_AMSITESTCLI RCDATA \"${SETUP_AMSITESTCLI_EXE}\"\n\
IDR_PAYLOAD_ETWTESTCLI RCDATA \"${SETUP_ETWTESTCLI_EXE}\"\n\
IDR_PAYLOAD_WFPTESTCLI RCDATA \"${SETUP_WFPTESTCLI_EXE}\"\n\
IDR_PAYLOAD_SIGNATURES RCDATA \"${SETUP_SIGNATURES_FILE}\"\n\
${SETUP_DRIVER_INF_RESOURCE_LINE}\n\
${SETUP_DRIVER_README_RESOURCE_LINE}\n\
${SETUP_DRIVER_SYS_RESOURCE_LINE}\n\
${SETUP_DRIVER_CAT_RESOURCE_LINE}\n\
${SETUP_WINPTHREAD_RESOURCE_LINE}\n")

set(SETUP_PAYLOAD_RC ${INSTALLER_GENERATED_DIR}/SetupPayload.rc)
set(SETUP_PAYLOAD_DEPENDENCIES
  ${SETUP_SERVICE_EXE}
  ${SETUP_ENDPOINT_CLIENT_EXE}
  ${SETUP_PAM_EXE}
  ${SETUP_REMOTE_HELPER_EXE}
  ${SETUP_WEBVIEW2_LOADER_DLL}
  ${SETUP_AMSI_PROVIDER_DLL}
  ${SETUP_SCANNERCLI_EXE}
  ${SETUP_AMSITESTCLI_EXE}
  ${SETUP_ETWTESTCLI_EXE}
  ${SETUP_WFPTESTCLI_EXE}
  ${SETUP_SIGNATURES_FILE}
  ${SETUP_WINPTHREAD_RESOURCE_DEPENDENCY}
)
foreach(optional_driver_dependency SETUP_DRIVER_INF_DEPENDENCY SETUP_DRIVER_README_DEPENDENCY)
  if(${optional_driver_dependency})
    list(APPEND SETUP_PAYLOAD_DEPENDENCIES "${${optional_driver_dependency}}")
  endif()
endforeach()
if(SETUP_DRIVER_SYS_DEPENDENCY)
  list(APPEND SETUP_PAYLOAD_DEPENDENCIES ${SETUP_DRIVER_SYS_DEPENDENCY})
endif()
if(SETUP_DRIVER_CAT_DEPENDENCY)
  list(APPEND SETUP_PAYLOAD_DEPENDENCIES ${SETUP_DRIVER_CAT_DEPENDENCY})
endif()
if(SETUP_WEBVIEW2_BOOTSTRAPPER_RESOURCE_DEPENDENCY)
  list(APPEND SETUP_PAYLOAD_DEPENDENCIES ${SETUP_WEBVIEW2_BOOTSTRAPPER_RESOURCE_DEPENDENCY})
endif()
set_source_files_properties(${SETUP_PAYLOAD_RC} PROPERTIES
  OBJECT_DEPENDS "${SETUP_PAYLOAD_DEPENDENCIES}"
)

add_executable(antivirus-setup WIN32
  ${INSTALLER_NATIVE_DIR}/src/setup.rc
  ${INSTALLER_NATIVE_DIR}/src/SetupMain.cpp
  ${INSTALLER_NATIVE_DIR}/src/FullRemoval.cpp
  ${SETUP_PAYLOAD_RC}
)

add_dependencies(antivirus-setup
  antivirus-agent-service
  fenrir-remote
  antivirus-endpoint-client
  antivirus-pam-client
  antivirus-amsi-provider
  antivirus-scannercli
  antivirus-amsitestcli
  antivirus-etwtestcli
  antivirus-wfptestcli
)

target_include_directories(antivirus-setup PRIVATE
  ${INSTALLER_NATIVE_DIR}/include
  ${INSTALLER_NATIVE_DIR}/src
)
target_link_libraries(antivirus-setup PRIVATE comctl32 ole32 shell32 advapi32 crypt32 wintrust dwmapi fwpuclnt netapi32 setupapi)
# Keep the runtime fully static. A trailing -Bdynamic here overrides -static
# for implicit runtime libraries and makes setup require libwinpthread-1.dll
# before it can extract any embedded payload.
target_compile_definitions(antivirus-setup PRIVATE UNICODE _UNICODE)
if(MINGW)
  target_link_options(antivirus-setup PRIVATE -municode -static)
endif()
set_target_properties(antivirus-setup PROPERTIES OUTPUT_NAME "FenrirSetup")
antivirus_set_runtime_output(antivirus-setup "${ANTIVIRUS_INSTALL_OUTPUT_ROOT}")
antivirus_apply_portable_runtime(antivirus-setup)

find_program(ANTIVIRUS_POWERSHELL_EXECUTABLE NAMES pwsh powershell)
if(ANTIVIRUS_ENABLE_BUILD_VALIDATION AND ANTIVIRUS_POWERSHELL_EXECUTABLE)
  get_filename_component(ANTIVIRUS_REPO_ROOT "${ANTIVIRUS_WINDOWS_ROOT}/.." ABSOLUTE)
  set(ANTIVIRUS_VALIDATE_MINIFILTER_SCRIPT
      "${ANTIVIRUS_WINDOWS_ROOT}/tools/scannercli/ValidateMinifilterPackage.ps1")

  add_custom_target(antivirus-validate-minifilter-package
    COMMAND "${ANTIVIRUS_POWERSHELL_EXECUTABLE}"
            -NoProfile
            -ExecutionPolicy Bypass
            -File "${ANTIVIRUS_VALIDATE_MINIFILTER_SCRIPT}"
            -WorkspaceRoot "${ANTIVIRUS_REPO_ROOT}"
            -DriverRoot "${ANTIVIRUS_DEV_OUTPUT_ROOT}/driver"
            -WorkingRoot "${ANTIVIRUS_REPO_ROOT}/tmp-phase1-minifilter-package"
            -RequireSignedArtifacts:$true
            -RequireServiceInstalled:$false
            -RequireServiceRunning:$false
            -RequireBrokerProbe:$false
            -RequireLiveInterception:$false
    WORKING_DIRECTORY "${ANTIVIRUS_REPO_ROOT}"
    DEPENDS antivirus-setup
    COMMENT "Running minifilter package validation target."
    VERBATIM
  )

  add_custom_target(antivirus-build-validated
    DEPENDS antivirus-setup antivirus-validate-minifilter-package
  )
elseif(ANTIVIRUS_ENABLE_BUILD_VALIDATION)
  message(STATUS "ANTIVIRUS_ENABLE_BUILD_VALIDATION is ON, but no PowerShell executable was found; validation target will not be created.")
endif()

# Portable unit tests and the ML inspection tool (also built on Linux in CI).
add_executable(fenrir-mltest ../tools/mltestcli/src/MlTestCliMain.cpp src/MlStaticModel.cpp)
target_include_directories(fenrir-mltest PRIVATE include)
add_executable(fenrir-behavior-tests ../tests/BehaviorRulesTests.cpp src/BehaviorRules.cpp)
target_include_directories(fenrir-behavior-tests PRIVATE include)
add_executable(fenrir-remote-sas-tests ../tests/RemoteSasRequestTests.cpp)
target_include_directories(fenrir-remote-sas-tests PRIVATE include)
antivirus_apply_portable_runtime(fenrir-remote-sas-tests)
add_executable(fenrir-remote-pipe-tests ../tests/RemotePipeIoTests.cpp)
target_include_directories(fenrir-remote-pipe-tests PRIVATE include)
antivirus_apply_portable_runtime(fenrir-remote-pipe-tests)
add_executable(fenrir-policy-tests ../tests/PolicyAndDeviceControlTests.cpp src/ExtendedPolicy.cpp src/BehaviorRules.cpp src/DeviceControl.cpp src/FirewallPolicy.cpp src/LocalAdminRotation.cpp src/RansomwareDetector.cpp src/BruteForceTracker.cpp)
target_link_libraries(fenrir-policy-tests PRIVATE bcrypt netapi32 advapi32)
add_executable(fenrir-admonitor-tests ../tests/AdMonitorTests.cpp src/AdEventRules.cpp)
target_include_directories(fenrir-admonitor-tests PRIVATE include)
add_executable(fenrir-rmm-tests ../tests/RmmExecutorTests.cpp src/RmmExecutors.cpp src/ExtendedPolicy.cpp src/BehaviorRules.cpp src/StringUtils.cpp src/CryptoUtils.cpp)
target_include_directories(fenrir-rmm-tests PRIVATE include ../shared/include)
target_link_libraries(fenrir-rmm-tests PRIVATE wtsapi32 userenv urlmon advapi32 bcrypt crypt32 wintrust)
antivirus_apply_portable_runtime(fenrir-rmm-tests)
target_include_directories(fenrir-policy-tests PRIVATE include)
