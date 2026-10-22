# Cross-compile the Windows agent from Linux:
#   cmake -B build-mingw -S agent/windows/service -DCMAKE_TOOLCHAIN_FILE=agent/windows/cmake/mingw-w64-x86_64.cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc-posix)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++-posix)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(SETUP_WINPTHREAD_DLL /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll CACHE FILEPATH "MinGW runtime shipped by the installer")
