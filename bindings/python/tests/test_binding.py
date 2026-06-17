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
import inspect

import pytest

import holytls
from holytls import Client, HolyTLSError, HttpVersion, Method, Profile, Session

try:
    from holytls import AsyncClient
except ImportError:  # pragma: no cover - AsyncClient is always present today
    AsyncClient = None


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


def test_session_redirect_controls_construct():
    # Bug #2: a Session can express "do not follow redirects". Both knobs are
    # decoupled — an explicit max_redirects=0 is honored (no silent ->10), and
    # follow_redirects=False disables following independent of the budget.
    with Client() as c:
        for s in (
            Session(c, follow_redirects=False),
            Session(c, max_redirects=0),
            Session(c, follow_redirects=True, max_redirects=5),
        ):
            assert s is not None
            s.close()


def test_session_set_cookie_seeds_jar():
    # Seed an out-of-band cookie (e.g. a solver's PerimeterX _px3) into the jar:
    # works on an open session, exercises every option, and is rejected after
    # close. Offline smoke only — there is no jar-read API, so test_live.py proves
    # the seeded cookie is actually attached to the next request.
    with Client() as c:
        s = Session(c, cookies=True)
        s.set_cookie("_px3", "seedval", domain="example.com")
        s.set_cookie("_pxvid", "v", domain="example.com", path="/api",
                     expires=2000000000, host_only=True, secure=True,
                     http_only=True, same_site=1)
        s.set_cookie("_px3", "replaced", domain="example.com")  # re-seed replaces
        s.close()
        with pytest.raises(HolyTLSError):
            s.set_cookie("late", "x", domain="example.com")  # closed -> raises


def test_session_set_cookie_requires_domain():
    # `domain` is keyword-only and required — a cookie needs a domain to match.
    with Client() as c:
        with Session(c) as s:
            with pytest.raises(TypeError):
                s.set_cookie("n", "v")  # missing required domain=


def test_header_order_kwarg_is_accepted():
    # The per-request header_order= surfaces on every request entry point, and
    # the client-level form constructs (string or sequence).
    for fn in (Client.request, Session.request):
        assert "header_order" in inspect.signature(fn).parameters
    if AsyncClient is not None:
        assert "header_order" in inspect.signature(AsyncClient.request).parameters
    with Client(header_order="user-agent, accept") as c:
        assert c is not None
    with Client(header_order=["user-agent", "accept"]) as c:
        assert c is not None


def test_http_version_kwarg_is_accepted():
    # The per-request http_version= surfaces on every request entry point, and a
    # forced-H1 request plumbs through end to end (offline: a dead port resolves
    # ok=0 without crashing — live negotiation is in test_live.py).
    for fn in (Client.request, Session.request):
        assert "http_version" in inspect.signature(fn).parameters
    if AsyncClient is not None:
        assert "http_version" in inspect.signature(AsyncClient.request).parameters
    with Client(http_version="h2", timeout_ms=2000) as c:
        r = c.get("https://127.0.0.1:1/", http_version="h1")  # forced, refused
        assert not r.ok and r.error
