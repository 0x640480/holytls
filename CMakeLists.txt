cmake_minimum_required(VERSION 3.20)
project(holytls LANGUAGES C CXX)  # CXX only for building BoringSSL (a dep)

# Top-level vs pulled in via add_subdirectory/FetchContent. As a subproject we
# build only the library (no tests/examples) and don't force global settings
# (CMAKE_BUILD_TYPE / FETCHCONTENT_QUIET / cache BUILD_*) onto the parent build.
if(NOT DEFINED PROJECT_IS_TOP_LEVEL)  # the built-in is CMake >= 3.21
  set(PROJECT_IS_TOP_LEVEL OFF)
  if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(PROJECT_IS_TOP_LEVEL ON)
  endif()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(HOLYTLS_ASAN "Build with Address/UB sanitizers" OFF)
option(HOLYTLS_ARENA_STATS "Compile in arena allocation counters (for benchmarks)" OFF)
option(HOLYTLS_BUILD_TESTS "Build the test suite" ${PROJECT_IS_TOP_LEVEL})
option(HOLYTLS_BUILD_EXAMPLES "Build the examples" ${PROJECT_IS_TOP_LEVEL})
option(HOLYTLS_FUZZ "Build coverage-guided libFuzzer harnesses (clang only)" OFF)
# The flat C ABI shared library (capi/) that language bindings (Python/cffi, …)
# load. A SHARED lib must statically absorb holytls + all deps, so every static
# dep needs position-independent code — turn PIC on globally before FetchContent
# configures them.
option(HOLYTLS_BUILD_CAPI "Build the libholytls_capi shared library (FFI ABI)" ${PROJECT_IS_TOP_LEVEL})
if(HOLYTLS_BUILD_CAPI)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
# When cross-compiling (e.g. MinGW-w64) there are no system codecs to find — build
# zlib/brotli/zstd from source instead. Defaults ON for Windows targets.
option(HOLYTLS_FETCH_CODECS
  "Build zlib/brotli/zstd from source instead of finding system libs" ${WIN32})

set(HOLYTLS_WARN -Wall -Wextra -Wpedantic -Wshadow)

# ---------------------------------------------------------------------------
# Dependencies (fetched at configure time, built static, linked in).
#   libuv    : event loop / non-blocking sockets
#   nghttp2  : HTTP/2 framing
#   ngtcp2   : QUIC transport      nghttp3 : HTTP/3 framing + QPACK
#   BoringSSL: TLS (ClientHello impersonation) — needs Go + perl to build
# ---------------------------------------------------------------------------
include(FetchContent)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
# Build the deps static. As a subproject, use a NORMAL var (scopes to holytls +
# its FetchContent deps) so we don't clobber a parent build's cached settings.
set(BUILD_SHARED_LIBS OFF)
if(PROJECT_IS_TOP_LEVEL)
  set(FETCHCONTENT_QUIET OFF)
  set(BUILD_TESTING OFF CACHE BOOL "" FORCE)  # keep the deps' tests out of our build
else()
  set(BUILD_TESTING OFF)
endif()
# nghttp2/ngtcp2/nghttp3 each define a `check` custom target — allow the dupes.
set_property(GLOBAL PROPERTY ALLOW_DUPLICATE_CUSTOM_TARGETS TRUE)

set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)
FetchContent_Declare(libuv
  GIT_REPOSITORY https://github.com/libuv/libuv.git GIT_TAG v1.52.1 GIT_SHALLOW TRUE)

set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
# nghttp2 is patched (cmake/patches) to re-emit the RFC 7540 HEADERS-frame
# priority that nghttp2 dropped in its RFC 9218 transition — browsers (Chrome,
# Firefox) still send it, so a profile's HEADERS priority is reproduced exactly.
# Applied idempotently at populate time (same mechanism as the BoringSSL patch).
find_package(Git REQUIRED)
FetchContent_Declare(nghttp2
  GIT_REPOSITORY https://github.com/nghttp2/nghttp2.git GIT_TAG v1.69.0 GIT_SHALLOW TRUE
  PATCH_COMMAND ${CMAKE_COMMAND}
    -DGIT_EXECUTABLE=${GIT_EXECUTABLE}
    -DPATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/cmake/patches/nghttp2-rfc7540-headers-priority.patch
    -DSRC_DIR=<SOURCE_DIR>
    -DLABEL=nghttp2
    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/apply_patch.cmake)

# ngtcp2 (QUIC) + nghttp3 (HTTP/3) — core libs only, TLS-agnostic. ngtcp2's own
# BoringSSL crypto helper is compiled by us below (its CMake detection link-tests
# against not-yet-built FetchContent libs).
set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ENABLE_OPENSSL OFF CACHE BOOL "" FORCE)
set(ENABLE_BORINGSSL OFF CACHE BOOL "" FORCE)
set(ENABLE_GNUTLS OFF CACHE BOOL "" FORCE)
set(ENABLE_WOLFSSL OFF CACHE BOOL "" FORCE)
set(ENABLE_PICOTLS OFF CACHE BOOL "" FORCE)
set(ENABLE_OSSL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(ngtcp2
  GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git GIT_TAG v1.23.0 GIT_SHALLOW TRUE)
FetchContent_Declare(nghttp3
  GIT_REPOSITORY https://github.com/ngtcp2/nghttp3.git GIT_TAG v1.9.0 GIT_SHALLOW TRUE)

# picohttpparser (HTTP/1.1 response parsing) — a 2-file MIT/Perl lib that ships no
# CMake of its own; MakeAvailable only populates its source dir.
FetchContent_Declare(picohttpparser
  GIT_REPOSITORY https://github.com/h2o/picohttpparser.git
  GIT_TAG f4d94b48b31e0abae029ebeafcfd9ca0680ede58 GIT_SHALLOW TRUE)

# yyjson (the project-wide JSON library) — single src/yyjson.c + .h, MIT.
FetchContent_Declare(yyjson
  GIT_REPOSITORY https://github.com/ibireme/yyjson.git
  GIT_TAG 0.12.0 GIT_SHALLOW TRUE)

# BoringSSL — lexiforest fork (default) for exact JA4 parity. Needs Go + perl.
# The fork is patched (cmake/patches) to add a force_tls13_legacy_ext knob:
# Firefox emits extended_master_secret + renegotiation_info even in its TLS1.3-
# only QUIC ClientHello, which stock BoringSSL (and the fork) suppress. The patch
# is applied idempotently at populate time; stock google/boringssl is untouched.
option(HOLYTLS_BORINGSSL_FORK "Use the lexiforest/boringssl impersonation fork" ON)
if(HOLYTLS_BORINGSSL_FORK)
  find_package(Git REQUIRED)
  FetchContent_Declare(boringssl
    GIT_REPOSITORY https://github.com/lexiforest/boringssl.git
    GIT_TAG 77dc0ca663ad0bdc6fd5006cbd398bc27d0af4ab GIT_SHALLOW TRUE
    PATCH_COMMAND ${CMAKE_COMMAND}
      -DGIT_EXECUTABLE=${GIT_EXECUTABLE}
      -DPATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/cmake/patches/boringssl-firefox-tls13-legacy-ext.patch
      -DSRC_DIR=<SOURCE_DIR>
      -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/apply_boringssl_patch.cmake)
else()
  FetchContent_Declare(boringssl
    GIT_REPOSITORY https://github.com/google/boringssl.git
    GIT_TAG 0.20251124.0 GIT_SHALLOW TRUE)
endif()

# Windows (MinGW): skip BoringSSL's NASM-dependent asm for a clean cross-build.
# asm can be re-enabled later for perf (nasm is available).
if(WIN32)
  set(OPENSSL_NO_ASM ON CACHE BOOL "" FORCE)
endif()

# Compression codecs from source when cross-compiling (no system libs): zlib
# (required for gzip/deflate + TLS cert compression) + brotli + zstd, static.
if(HOLYTLS_FETCH_CODECS)
  set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(zlib
    GIT_REPOSITORY https://github.com/madler/zlib.git GIT_TAG v1.3.1 GIT_SHALLOW TRUE)
  set(BROTLI_DISABLE_TESTS ON CACHE BOOL "" FORCE)
  FetchContent_Declare(brotli
    GIT_REPOSITORY https://github.com/google/brotli.git GIT_TAG v1.1.0 GIT_SHALLOW TRUE)
  set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
  set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
  set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
  set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git GIT_TAG v1.5.6
    GIT_SHALLOW TRUE SOURCE_SUBDIR build/cmake)
endif()

# yyjson ships its own CMake: MakeAvailable creates a static `yyjson` target (built
# with yyjson's own flags, separate from our strict warnings) + propagates its include.
FetchContent_MakeAvailable(libuv nghttp2 boringssl ngtcp2 nghttp3 picohttpparser
  yyjson)
if(HOLYTLS_FETCH_CODECS)
  FetchContent_MakeAvailable(zlib brotli zstd)
endif()

# picohttpparser as a separate static lib with relaxed warnings (its SSE/code
# trips -Wpedantic/-Wshadow); the unity TU keeps full warnings.
add_library(picohttpparser STATIC ${picohttpparser_SOURCE_DIR}/picohttpparser.c)
target_include_directories(picohttpparser PUBLIC ${picohttpparser_SOURCE_DIR})
target_compile_options(picohttpparser PRIVATE -Wall -Wextra)

add_library(holytls_deps INTERFACE)
if(TARGET uv_a)
  target_link_libraries(holytls_deps INTERFACE uv_a)
else()
  target_link_libraries(holytls_deps INTERFACE uv)
endif()
if(TARGET nghttp2_static)
  target_link_libraries(holytls_deps INTERFACE nghttp2_static)
else()
  target_link_libraries(holytls_deps INTERFACE nghttp2)
endif()
target_include_directories(holytls_deps INTERFACE
  ${nghttp2_SOURCE_DIR}/lib/includes ${nghttp2_BINARY_DIR}/lib/includes)

# BoringSSL: ssl + crypto (linking propagates the include dir).
target_link_libraries(holytls_deps INTERFACE ssl crypto)
target_include_directories(holytls_deps INTERFACE ${boringssl_SOURCE_DIR}/include)
if(HOLYTLS_BORINGSSL_FORK)
  target_compile_definitions(holytls_deps INTERFACE HOLYTLS_TLS_FORK)
endif()

# ngtcp2 core (QUIC transport).
if(TARGET ngtcp2_static)
  target_link_libraries(holytls_deps INTERFACE ngtcp2_static)
else()
  target_link_libraries(holytls_deps INTERFACE ngtcp2)
endif()
target_include_directories(holytls_deps INTERFACE
  ${ngtcp2_SOURCE_DIR}/lib/includes ${ngtcp2_BINARY_DIR}/lib/includes)

# nghttp3 (HTTP/3 framing + standalone QPACK).
if(TARGET nghttp3_static)
  target_link_libraries(holytls_deps INTERFACE nghttp3_static)
else()
  target_link_libraries(holytls_deps INTERFACE nghttp3)
endif()
target_include_directories(holytls_deps INTERFACE
  ${nghttp3_SOURCE_DIR}/lib/includes ${nghttp3_BINARY_DIR}/lib/includes)

# ngtcp2 BoringSSL crypto helper — compiled here (not via ngtcp2's CMake, whose
# BoringSSL detection link-tests against not-yet-built FetchContent libs). The
# fork's classic SSL_QUIC_METHOD matches ngtcp2's boringssl.c.
add_library(ngtcp2_crypto_boringssl STATIC
  ${ngtcp2_SOURCE_DIR}/crypto/boringssl/boringssl.c
  ${ngtcp2_SOURCE_DIR}/crypto/shared.c)
target_include_directories(ngtcp2_crypto_boringssl PUBLIC
  ${ngtcp2_SOURCE_DIR}/lib/includes ${ngtcp2_BINARY_DIR}/lib/includes
  ${ngtcp2_SOURCE_DIR}/lib ${ngtcp2_SOURCE_DIR}/crypto/includes
  ${ngtcp2_SOURCE_DIR}/crypto ${boringssl_SOURCE_DIR}/include)
target_compile_definitions(ngtcp2_crypto_boringssl PUBLIC NGTCP2_STATICLIB)
target_link_libraries(ngtcp2_crypto_boringssl PUBLIC ssl crypto)
target_link_libraries(holytls_deps INTERFACE ngtcp2_crypto_boringssl)
target_link_libraries(holytls_deps INTERFACE picohttpparser)
target_link_libraries(holytls_deps INTERFACE yyjson)

# Compression codecs (zlib for gzip/deflate + TLS cert compression; brotli/zstd
# add `br`/`zstd`). From-source static libs when cross-compiling
# (HOLYTLS_FETCH_CODECS, the Windows default) or the host's system libs (Linux).
if(HOLYTLS_FETCH_CODECS)
  target_compile_definitions(holytls_deps INTERFACE HOLYTLS_HAVE_ZLIB)
  target_link_libraries(holytls_deps INTERFACE zlibstatic)
  target_include_directories(holytls_deps INTERFACE
    ${zlib_SOURCE_DIR} ${zlib_BINARY_DIR})  # zlib.h + the generated zconf.h
  target_compile_definitions(holytls_deps INTERFACE HOLYTLS_HAVE_BROTLI)
  target_link_libraries(holytls_deps INTERFACE brotlidec brotlicommon)
  target_compile_definitions(holytls_deps INTERFACE HOLYTLS_HAVE_ZSTD)
  target_link_libraries(holytls_deps INTERFACE libzstd_static)
else()
  function(holytls_find_codec out_var)
    find_library(${out_var} NAMES ${ARGN})
    if(NOT ${out_var})
      foreach(n ${ARGN})
        file(GLOB _hits /usr/lib/*/lib${n}.so* /usr/lib/lib${n}.so* /lib/*/lib${n}.so*)
        if(_hits)
          list(GET _hits 0 _first)
          set(${out_var} ${_first} CACHE FILEPATH "" FORCE)
          break()
        endif()
      endforeach()
    endif()
  endfunction()
  holytls_find_codec(HOLYTLS_ZLIB z)
  holytls_find_codec(HOLYTLS_BROTLIDEC brotlidec)
  holytls_find_codec(HOLYTLS_ZSTD zstd)
  if(HOLYTLS_ZLIB)
    target_compile_definitions(holytls_deps INTERFACE HOLYTLS_HAVE_ZLIB)
    target_link_libraries(holytls_deps INTERFACE ${HOLYTLS_ZLIB})
  endif()
  if(HOLYTLS_BROTLIDEC)
    target_compile_definitions(holytls_deps INTERFACE HOLYTLS_HAVE_BROTLI)
    target_link_libraries(holytls_deps INTERFACE ${HOLYTLS_BROTLIDEC})
  endif()
  if(HOLYTLS_ZSTD)
    target_compile_definitions(holytls_deps INTERFACE HOLYTLS_HAVE_ZSTD)
    target_link_libraries(holytls_deps INTERFACE ${HOLYTLS_ZSTD})
  endif()
endif()

# Windows: keep <windows.h> (pulled by uv.h) from dragging in wincrypt.h / wingdi.h,
# whose macros (X509_NAME, OCSP_REQUEST, PKCS7_*, ERROR, …) collide with BoringSSL's
# identifiers in our TU. We use BoringSSL for crypto, so excluding them is safe.
# (INTERFACE → applies to holytls + the examples, not the dep builds.)
# Plus the system libs the static link needs: winsock (our inet_pton + libuv),
# IP helper / userenv / dbghelp (libuv), bcrypt + crypt32 (BoringSSL). Linked last
# so GNU ld resolves them as leaf libraries.
if(WIN32)
  target_compile_definitions(holytls_deps INTERFACE NOCRYPT NOGDI)
  target_link_libraries(holytls_deps INTERFACE
    ws2_32 iphlpapi userenv dbghelp bcrypt crypt32 ntdll)
endif()

# ---------------------------------------------------------------------------
# The unity library: one TU (src/holytls.c) that #includes every subsystem .c.
# ---------------------------------------------------------------------------
add_library(holytls STATIC src/holytls.c)
target_include_directories(holytls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(holytls PUBLIC holytls_deps)
target_compile_options(holytls PRIVATE ${HOLYTLS_WARN})

if(HOLYTLS_ASAN)
  target_compile_options(holytls PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(holytls PUBLIC -fsanitize=address,undefined)
endif()

# Fuzzing: instrument the library for libFuzzer coverage + ASan/UBSan so the
# harnesses (below) catch the bugs the inputs trigger. Implies sanitizers, so
# don't combine with -DHOLYTLS_ASAN=ON (would double the flags).
if(HOLYTLS_FUZZ)
  if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "HOLYTLS_FUZZ requires Clang for libFuzzer (-fsanitize=fuzzer)")
  endif()
  target_compile_options(holytls PUBLIC
    -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
  target_link_options(holytls PUBLIC -fsanitize=address,undefined)
endif()

# Arena allocation counters — PUBLIC so targets linking holytls (the benchmark)
# also see the define for arena_stats(). Off by default = zero hot-path overhead.
if(HOLYTLS_ARENA_STATS)
  target_compile_definitions(holytls PUBLIC HOLYTLS_ARENA_STATS)
endif()

# ---------------------------------------------------------------------------
# Flat C ABI shared library (capi/holytls_capi.c) — the surface language
# bindings (Python/cffi, Go/cgo, …) bind against. SHARED so foreign runtimes can
# dlopen/link one self-contained object; PRIVATE-links holytls so the whole
# static stack (TLS engine + libuv + nghttp2/ngtcp2/nghttp3 + codecs) is absorbed
# into it and no holytls symbols leak out (only the holytls_* ABI is exported).
# ---------------------------------------------------------------------------
if(HOLYTLS_BUILD_CAPI)
  add_library(holytls_capi SHARED capi/holytls_capi.c)
  target_include_directories(holytls_capi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/capi)
  target_link_libraries(holytls_capi PRIVATE holytls)
  target_compile_options(holytls_capi PRIVATE ${HOLYTLS_WARN})
  if(WIN32)
    # MinGW/MSVC: export everything (the Windows norm); the import lib lists the
    # holytls_* ABI either way.
    set_target_properties(holytls_capi PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
  else()
    # ELF: export ONLY the holytls_* ABI and localize every absorbed static
    # symbol (TLS/libuv/http internals), so the .so can't clash with a host app
    # that also links OpenSSL/libuv. A version script promotes the named globals;
    # do NOT also set -fvisibility=hidden here (it would demote holytls_* to
    # local before the script could export them).
    target_link_options(holytls_capi PRIVATE
      -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/capi/holytls_capi.map)
  endif()
  if(HOLYTLS_ASAN)
    target_compile_options(holytls_capi PRIVATE -fsanitize=address,undefined)
    target_link_options(holytls_capi PRIVATE -fsanitize=address,undefined)
  endif()
endif()

# Extra ${ARGN} sources are added to the test executable (e.g. a shared helper
# like tests/support/loopback_server.c). The tests/ dir is on the include path so
# such helpers resolve as "support/...".
function(holytls_test name)
  add_executable(${name} tests/${name}.c ${ARGN})
  target_link_libraries(${name} PRIVATE holytls)
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_compile_options(${name} PRIVATE ${HOLYTLS_WARN})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

# Like holytls_test, but for tests that use the `defer` macro (base/defer.h): the
# GCC path uses nested functions (a GNU extension), so relax -Wpedantic for that
# one TU (the appended flag wins over HOLYTLS_WARN's -Wpedantic).
function(holytls_test_defer name)
  holytls_test(${name} ${ARGN})
  target_compile_options(${name} PRIVATE -Wno-pedantic)
endfunction()

if(HOLYTLS_BUILD_TESTS)
enable_testing()
holytls_test(base_test)
holytls_test(arena_thread_test)
holytls_test(base64_test)
holytls_test(str8_test)
holytls_test(ring_alloc_test)
holytls_test(pool_test)
holytls_test(cookie_test)
holytls_test(psl_test)
holytls_test(sec_ch_ua_test)
holytls_test(manager_test)
holytls_test(ech_test)
holytls_test(sec_fetch_test)
holytls_test(loop_test)
holytls_test(h2_test)
holytls_test(h2_arena_test)
holytls_test(ja4_test)
holytls_test(profile_test)
holytls_test(conn_test)
holytls_test(h3_control_test)
holytls_test(fingerprint_h3_test)
holytls_test(core_test)
holytls_test(sync_api_test)
holytls_test_defer(sync_api_live_test)
holytls_test_defer(client_live_test)
holytls_test_defer(altsvc_live_test)
holytls_test_defer(top_sites_live_test)
holytls_test_defer(trackme_local_test)
holytls_test(header_order_test)
holytls_test_defer(header_order_live_test)
holytls_test_defer(header_template_live_test)
holytls_test_defer(redirect_live_test)
holytls_test_defer(pool_live_test)
holytls_test_defer(session_live_test)
holytls_test_defer(ech_live_test)
holytls_test_defer(sec_fetch_live_test)
holytls_test_defer(resumption_live_test)
holytls_test(zero_rtt_live_test)
holytls_test_defer(zero_rtt_h3_live_test)
holytls_test(session_serial_test)
holytls_test_defer(session_persist_live_test)
holytls_test_defer(key_log_test)
holytls_test(key_log_live_test)
holytls_test(cert_pin_test)
holytls_test_defer(cert_pin_live_test)
holytls_test(hook_test)
holytls_test_defer(hook_live_test)
holytls_test(timing_test)
holytls_test_defer(timing_live_test)
holytls_test(dns_cache_test)
holytls_test_defer(dns_cache_live_test)
holytls_test(http_version_test)
holytls_test_defer(http_version_live_test)
holytls_test(proxy_test)
holytls_test(response_test)
holytls_test(stream_decode_test)
holytls_test(ws_frame_test)
# Offline tests sharing the in-process loopback origin (tests/support).
holytls_test(request_test       tests/support/loopback_server.c)
holytls_test(header_order_pool_test tests/support/loopback_server.c)
holytls_test(pool_h1_test       tests/support/loopback_server.c)
holytls_test(pool_h2_body_test  tests/support/loopback_server.c)
holytls_test(stream_test        tests/support/loopback_server.c)
holytls_test(ws_h2_test         tests/support/loopback_server.c)
holytls_test(ws_pmd_test        tests/support/loopback_server.c)
holytls_test(mtls_test          tests/support/loopback_server.c)
holytls_test(timeout_test       tests/support/loopback_server.c)
holytls_test(proxy_loopback_test tests/support/loopback_server.c)
holytls_test(proxy_switch_test  tests/support/loopback_server.c)
holytls_test(proxy_live_test)
holytls_test_defer(defer_test)
holytls_test(h1_test)
holytls_test_defer(h1_live_test)
holytls_test_defer(ws_live_test)
holytls_test_defer(tls_stream_live_test)
holytls_test(json_test)
endif()  # HOLYTLS_BUILD_TESTS

# Cross-client benchmark harness (bench/c). Opt-in; links the holytls lib like a
# test. Pair with -DHOLYTLS_ARENA_STATS=ON to populate the alloc counters it
# reports. Built/run via bench/ (see bench/README.md), not part of the test suite.
option(HOLYTLS_BUILD_BENCH "Build the cross-client benchmark C harness" OFF)
if(HOLYTLS_BUILD_BENCH)
  add_executable(bench_holytls bench/c/bench_holytls.c)
  target_link_libraries(bench_holytls PRIVATE holytls)
  target_compile_options(bench_holytls PRIVATE ${HOLYTLS_WARN})
endif()

if(HOLYTLS_BUILD_EXAMPLES)
# Each example is a single self-contained .c under examples/:
#   quickstart  — minimal async GET + response accessors
#   fingerprint — verify the byte-exact JA3/JA4/Akamai fingerprint via tls.peet.ws
#   post_json   — POST a JSON body + custom headers (RequestParams), parse the reply
#   session     — cookie jar + redirect following + pooling (+ optional PROXY)
#   stealth     — dual H2/H3, real ECH, resumption + 0-RTT (full Chrome fidelity)
set(HOLYTLS_EXAMPLES quickstart fingerprint post_json session stealth)
foreach(ex ${HOLYTLS_EXAMPLES})
  add_executable(${ex} examples/${ex}.c)
  target_link_libraries(${ex} PRIVATE holytls)
  target_compile_options(${ex} PRIVATE ${HOLYTLS_WARN})
endforeach()
endif()  # HOLYTLS_BUILD_EXAMPLES

# ---------------------------------------------------------------------------
# Fuzz harnesses (fuzz/). Each target consumes attacker-controlled bytes:
#   -DHOLYTLS_FUZZ=ON (clang): real coverage-guided libFuzzer binaries.
#   else, under HOLYTLS_BUILD_TESTS: standalone replay binaries (any compiler)
#   that run their seed corpus as a ctest — a cheap per-push check that the
#   harnesses compile and don't crash on known inputs (ASan-checked in the
#   sanitizer build). The repo root is on the include path for "fuzz/fuzz.h".
# ---------------------------------------------------------------------------
set(HOLYTLS_FUZZ_TARGETS url alt_svc base64 cookie decompress persist persist_client)
if(HOLYTLS_FUZZ)
  foreach(t ${HOLYTLS_FUZZ_TARGETS})
    add_executable(fuzz_${t} fuzz/fuzz_${t}.c)
    target_link_libraries(fuzz_${t} PRIVATE holytls)
    target_include_directories(fuzz_${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(fuzz_${t} PRIVATE
      -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer ${HOLYTLS_WARN})
    target_link_options(fuzz_${t} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
elseif(HOLYTLS_BUILD_TESTS)
  foreach(t ${HOLYTLS_FUZZ_TARGETS})
    add_executable(fuzz_${t} fuzz/fuzz_${t}.c fuzz/standalone.c)
    target_link_libraries(fuzz_${t} PRIVATE holytls)
    target_include_directories(fuzz_${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(fuzz_${t} PRIVATE ${HOLYTLS_WARN})
    file(GLOB _seeds ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/corpus/${t}/*)
    add_test(NAME fuzz_${t}_seeds COMMAND fuzz_${t} ${_seeds})
  endforeach()
endif()
