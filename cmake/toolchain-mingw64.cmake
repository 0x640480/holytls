# MinGW-w64 cross-compile toolchain — Windows x86_64, static.
#
# Usage (from the repo root, toolchain installed: mingw-w64 + ninja):
#   cmake -B build-mingw -G Ninja \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake \
#     -DCMAKE_BUILD_TYPE=Release \
#     -DHOLYTLS_BUILD_TESTS=OFF -DHOLYTLS_BUILD_EXAMPLES=ON
#   ninja -C build-mingw
#
# Produces self-contained .exe/.a — no libgcc/libstdc++/winpthread/codec DLLs.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

set(_tool x86_64-w64-mingw32)
set(CMAKE_C_COMPILER   ${_tool}-gcc)
set(CMAKE_CXX_COMPILER ${_tool}-g++)   # CXX is only used to build BoringSSL
set(CMAKE_RC_COMPILER  ${_tool}-windres)
set(CMAKE_AR           ${_tool}-ar)
set(CMAKE_RANLIB       ${_tool}-ranlib)

# Find headers/libs in the MinGW sysroot; keep host programs (go, perl, used by
# the BoringSSL build) resolving on the host.
set(CMAKE_FIND_ROOT_PATH /usr/${_tool})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Target a recent Windows API (libuv/BoringSSL need it) and force MinGW's
# C99/ANSI stdio so printf("%llu"/"%zu") work (the default msvcrt printf does
# not). Applied to the whole build — our code and every FetchContent dep.
set(CMAKE_C_FLAGS_INIT   "-D_WIN32_WINNT=0x0A00 -D__USE_MINGW_ANSI_STDIO=1")
set(CMAKE_CXX_FLAGS_INIT "-D_WIN32_WINNT=0x0A00 -D__USE_MINGW_ANSI_STDIO=1")

# Static runtime: pull libgcc, libstdc++ (BoringSSL is C++) and winpthread
# (needed by _Thread_local) into the binaries.
set(_static "-static -static-libgcc -static-libstdc++")
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_static}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_static}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_static}")
