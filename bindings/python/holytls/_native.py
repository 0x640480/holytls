"""Loads the compiled cffi extension and exposes ``ffi`` / ``lib``.

The extension is built out-of-line by ``holytls_build.py`` (API mode). If it is
missing, the package wasn't compiled against the native ``libholytls_capi`` yet
— raise a message that points at the build steps instead of a bare ImportError.
"""

try:
    from holytls._holytls_cffi import ffi, lib  # type: ignore
except ImportError as exc:  # pragma: no cover - exercised only on a broken install
    # Two distinct failures land here: the cffi extension was never compiled, OR
    # it was compiled but the native libholytls_capi shared library can't be
    # found at load time (its build dir was moved/removed and the staged copy is
    # missing). Both are fixed by rebuilding + reinstalling.
    raise ImportError(
        "holytls's native layer could not be loaded — either the cffi extension\n"
        "(_holytls_cffi) isn't built, or libholytls_capi could not be found at\n"
        f"load time (original error: {exc}).\n"
        "Build the C ABI library, then (re)install the binding:\n"
        "    cmake -B build-capi -G Ninja -DHOLYTLS_BUILD_CAPI=ON \\\n"
        "        -DHOLYTLS_BUILD_TESTS=OFF -DHOLYTLS_BUILD_EXAMPLES=OFF\n"
        "    cmake --build build-capi --target holytls_capi\n"
        "    pip install ./bindings/python\n"
    ) from exc

__all__ = ["ffi", "lib"]
