# Minimal setup.py whose only job is to wire cffi's out-of-line builder into the
# build. Project metadata lives in pyproject.toml; cffi_modules points at the
# ffibuilder in holytls_build.py, which compiles holytls/_holytls_cffi against
# the prebuilt libholytls_capi (see that file's docstring for env-var overrides).
from setuptools import setup

setup(cffi_modules=["holytls_build.py:ffibuilder"])
