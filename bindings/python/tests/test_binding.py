"""Offline integrity tests for the holytls Python binding.

These never touch the network (CI stays deterministic, like the C ctest suite):
they prove the cffi extension links + loads against the real C ABI, the profile
registry is exposed, client construction works across every ``http_version``
mode + profile, and the API contracts hold (the removed ``dual=`` kwarg, error
paths, enum coercion). Actual H2/H3 negotiation is covered by the C live tests
and ``test_live.py`` (gated on ``HOLYTLS_LIVE``).

Run (after building libholytls_capi + installing the binding)::

    pytest bindings/python/tests
"""
import pytest

import holytls
from holytls import Client, HolyTLSError, HttpVersion, Method, Profile


def test_version_is_nonempty_string():
    # Exercises a native call (holytls_capi_version) -> proves the .so loaded.
    assert isinstance(holytls.version(), str) and holytls.version()


def test_available_profiles_registry():
    profs = holytls.available_profiles()
    assert profs[0] == "chrome149"  # registry default (newest) is first
    for name in ("chrome149", "chrome148", "firefox151"):
        assert name in profs


# http_version is THE HTTP/3 selector; every accepted form must construct.
@pytest.mark.parametrize(
    "http_version",
    [None, "h2", "auto", "h3", "h1", "http2", "http3",
     HttpVersion.AUTO, HttpVersion.HTTP_1, HttpVersion.HTTP_2, HttpVersion.HTTP_3, 2],
)
def test_client_constructs_for_every_mode(http_version):
    with Client(http_version=http_version) as c:
        assert c is not None


def test_default_client_constructs():
    # Bare Client() is the lean H2-only default (no QUIC) — must just work.
    with Client() as c:
        assert c is not None


@pytest.mark.parametrize(
    "profile",
    ["chrome149", "chrome148", "firefox151", "firefox",
     Profile.CHROME, Profile.CHROME_148, Profile.CHROME_149, Profile.FIREFOX_151],
)
def test_client_constructs_for_every_profile(profile):
    with Client(profile=profile) as c:
        assert c is not None


def test_dual_kwarg_is_removed():
    # Regression lock: the old capability knob is gone; http_version is the only
    # HTTP/3 selector now. Passing dual= must be a hard error, not silently ignored.
    with pytest.raises(TypeError):
        Client(dual=True)
    with pytest.raises(TypeError):
        Client(dual=False)


def test_unknown_profile_raises():
    with pytest.raises(HolyTLSError):
        Client(profile="netscape-navigator")


def test_httpversion_coerce():
    assert HttpVersion.coerce("auto") == HttpVersion.AUTO
    assert HttpVersion.coerce("h2") == HttpVersion.HTTP_2
    assert HttpVersion.coerce("http3") == HttpVersion.HTTP_3
    assert HttpVersion.coerce("h1") == HttpVersion.HTTP_1
    assert int(HttpVersion.HTTP_2) == 2  # ABI value, used as the native default


def test_profile_firefox_alias_and_coerce():
    assert Profile.FIREFOX == Profile.FIREFOX_151  # FIREFOX aliases the newest
    assert Profile.coerce("firefox") == Profile.FIREFOX_151
    assert Profile.coerce("firefox151") == Profile.FIREFOX_151


def test_method_coerce():
    assert Method.coerce("get") == Method.GET
    assert Method.coerce("POST") == Method.POST


def test_close_is_idempotent():
    c = Client()
    c.close()
    c.close()  # double close must not crash or double-free
