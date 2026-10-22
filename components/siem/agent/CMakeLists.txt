cmake_minimum_required(VERSION 3.20)
project(tamsilcms-agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(CURL CONFIG REQUIRED)

message(STATUS "OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
message(STATUS "CMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}")

# Common libraries for agent targets
set(AGENT_LIBS OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)

message(STATUS "Legacy single-binary target removed; use service binaries instead.")

# Add IPC and service component subdirectories so the full agent builds
add_subdirectory(ipc)
add_subdirectory(src/stubs)
add_subdirectory(src/core)
add_subdirectory(src/launcher)

# Many service binaries are work-in-progress and may have missing implementations.
# Allow opting into building all services; keep it OFF by default so `package`
# succeeds without compiling unfinished targets.
option(BUILD_ALL_SERVICES "Build all agent service binaries (execution, sensor, userhelper, watchdog)" ON)
if(BUILD_ALL_SERVICES)
    add_subdirectory(src/execution)
    add_subdirectory(src/sensor)
    add_subdirectory(src/userhelper)
    add_subdirectory(src/watchdog)
    add_subdirectory(src/winservice)
else()
    message(STATUS "Skipping optional service targets; set -DBUILD_ALL_SERVICES=ON to build them")
endif()


# Install and packaging rules
include(InstallRequiredSystemLibraries)

# Install executables if they exist
if(TARGET agent_core)
    install(TARGETS agent_core RUNTIME DESTINATION bin)
endif()
if(TARGET evidence_test)
    install(TARGETS evidence_test RUNTIME DESTINATION bin)
endif()
if(TARGET tamsilcms)
    install(TARGETS tamsilcms RUNTIME DESTINATION bin)
endif()
if(TARGET agent_execution)
    install(TARGETS agent_execution RUNTIME DESTINATION bin)
endif()
if(TARGET agent_sensor)
    install(TARGETS agent_sensor RUNTIME DESTINATION bin)
endif()
if(TARGET agent_userhelper)
    install(TARGETS agent_userhelper RUNTIME DESTINATION bin)
endif()
if(TARGET agent_watchdog)
    install(TARGETS agent_watchdog RUNTIME DESTINATION bin)
endif()

install(FILES agent_config.ini agent.env DESTINATION config)

# Try to copy runtime DLLs from vcpkg prefixes (all entries of CMAKE_PREFIX_PATH)
if(CMAKE_PREFIX_PATH)
    foreach(prefix ${CMAKE_PREFIX_PATH})
        set(VCPKG_BIN_DIR "${prefix}/bin")
        if(EXISTS "${VCPKG_BIN_DIR}")
            file(GLOB VCPKG_DLLS RELATIVE "${VCPKG_BIN_DIR}" "${VCPKG_BIN_DIR}/*.dll")
            if(VCPKG_DLLS)
                foreach(dll ${VCPKG_DLLS})
                    install(FILES "${VCPKG_BIN_DIR}/${dll}" DESTINATION bin)
                endforeach()
            endif()
            file(GLOB LIBCURL_DLLS RELATIVE "${VCPKG_BIN_DIR}" "${VCPKG_BIN_DIR}/libcurl*.dll")
            if(LIBCURL_DLLS)
                foreach(dll ${LIBCURL_DLLS})
                    install(FILES "${VCPKG_BIN_DIR}/${dll}" DESTINATION bin)
                endforeach()
            endif()
        endif()

        set(VCPKG_DEBUG_BIN_DIR "${prefix}/debug/bin")
        if(EXISTS "${VCPKG_DEBUG_BIN_DIR}")
            file(GLOB VCPKG_DEBUG_DLLS RELATIVE "${VCPKG_DEBUG_BIN_DIR}" "${VCPKG_DEBUG_BIN_DIR}/*.dll")
            if(VCPKG_DEBUG_DLLS)
                foreach(dll ${VCPKG_DEBUG_DLLS})
                    install(FILES "${VCPKG_DEBUG_BIN_DIR}/${dll}" DESTINATION bin)
                endforeach()
            endif()
            file(GLOB LIBCURL_DEBUG_DLLS RELATIVE "${VCPKG_DEBUG_BIN_DIR}" "${VCPKG_DEBUG_BIN_DIR}/libcurl*.dll")
            if(LIBCURL_DEBUG_DLLS)
                foreach(dll ${LIBCURL_DEBUG_DLLS})
                    install(FILES "${VCPKG_DEBUG_BIN_DIR}/${dll}" DESTINATION bin)
                endforeach()
            endif()
        endif()
    endforeach()
endif()

# CPack (ZIP) packaging
set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_NAME "tamsilcms-agent")
set(CPACK_PACKAGE_VENDOR "TamsilCMS")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
include(CPack)
