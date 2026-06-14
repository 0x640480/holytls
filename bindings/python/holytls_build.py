"""cffi out-of-line API-mode builder for the holytls Python binding.

This compiles a small extension module (``holytls._holytls_cffi``) that
``#include``s the flat C ABI header (``capi/holytls_capi.h``) and links the
prebuilt ``libholytls_capi`` shared library. API mode (not ABI/dlopen) means the
C compiler cross-checks our declarations against the real header at build time,
so the binding can't silently drift from the library's ABI.

Build the native library first, then this:

    cmake -B build-capi -G Ninja -DHOLYTLS_BUILD_CAPI=ON \
        -DHOLYTLS_BUILD_TESTS=OFF -DHOLYTLS_BUILD_EXAMPLES=OFF
    cmake --build build-capi --target holytls_capi
    pip install ./bindings/python          # picks up build-capi automatically

Override discovery with env vars when the layout differs:
    HOLYTLS_CAPI_INCLUDE  dir holding holytls_capi.h   (default: <repo>/capi)
    HOLYTLS_CAPI_LIBDIR   dir holding libholytls_capi  (default: first existing
                          of <repo>/build-capi, <repo>/build)
"""
import os
import re
import shutil

from cffi import FFI

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", ".."))


def _capi_include():
    env = os.environ.get("HOLYTLS_CAPI_INCLUDE")
    if env:
        return env
    return os.path.join(_REPO, "capi")


def _capi_libdir():
    env = os.environ.get("HOLYTLS_CAPI_LIBDIR")
    if env:
        return env
    for cand in ("build-capi", "build"):
        d = os.path.join(_REPO, cand)
        if os.path.isdir(d):
            return d
    return os.path.join(_REPO, "build-capi")


def _read_cdef(header_path):
    """Turn the C header into a cffi-parseable cdef.

    cffi's cdef() is not a preprocessor: strip the ``#`` directives (include
    guards, ``#ifdef __cplusplus``) and the ``extern "C"`` wrapper lines (both
    the opening ``extern "C" {`` and the ``}  // extern "C"`` closer contain the
    token), leaving plain typedefs/structs/enums/prototypes it can parse.
    """
    with open(header_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    keep = []
    for line in lines:
        if re.match(r"\s*#", line):
            continue
        if 'extern "C"' in line:
            continue
        keep.append(line)
    return "".join(keep)


ffibuilder = FFI()

_INCLUDE = _capi_include()
_LIBDIR = _capi_libdir()
_HEADER = os.path.join(_INCLUDE, "holytls_capi.h")

ffibuilder.cdef(_read_cdef(_HEADER))

ffibuilder.set_source(
    "holytls._holytls_cffi",
    '#include "holytls_capi.h"',
    include_dirs=[_INCLUDE],
    library_dirs=[_LIBDIR],
    libraries=["holytls_capi"],
    # Runtime resolution order for libholytls_capi: the absolute build dir (works
    # for a from-source install on the build host), then $ORIGIN — which finds
    # the copy staged beside this extension by _stage_native_lib() below.
    runtime_library_dirs=[_LIBDIR] if os.name != "nt" else [],
    extra_link_args=(["-Wl,-rpath,$ORIGIN"] if os.name == "posix" else []),
)


def _stage_native_lib():
    """Copy the native shared library next to the compiled extension so the
    baked-in $ORIGIN rpath resolves it even if the build dir is later removed,
    and so a built wheel can bundle it (see package-data in pyproject.toml). The
    absolute build-dir rpath remains a dev fallback. A fully portable wheel would
    still need auditwheel/delocate to vendor the codec deps — out of scope here.
    """
    pkg_dir = os.path.join(_HERE, "holytls")
    for name in ("libholytls_capi.so", "libholytls_capi.dylib", "holytls_capi.dll"):
        src = os.path.join(_LIBDIR, name)
        if os.path.isfile(src):
            try:
                shutil.copy2(src, pkg_dir)
            except OSError:
                pass
            break


# Runs at import time too (cffi imports this module for `cffi_modules`), so the
# library is staged whenever the binding is built.
_stage_native_lib()


if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
