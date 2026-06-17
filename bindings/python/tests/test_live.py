"""Live behavior tests for the holytls Python binding (network-gated).

Mirrors the C live-test convention: skipped unless ``HOLYTLS_LIVE=1`` so CI stays
deterministic. These lock the Python-layer HTTP/3 selection end-to-end — that the
single ``http_version`` knob actually drives the wire protocol (forced ``h3``
builds + negotiates QUIC; default/``auto`` are H2-first like Chrome).

Run::

    HOLYTLS_LIVE=1 pytest bindings/python/tests/test_live.py
"""
import os

import pytest

import holytls
from holytls import Client, Session

pytestmark = pytest.mark.skipif(
    not os.environ.get("HOLYTLS_LIVE"),
    reason="network-gated; set HOLYTLS_LIVE=1 to run",
)

H2_URL = "https://tls.browserleaks.com/json"
H3_URL = "https://quic.browserleaks.com/json"


def test_forced_h3_negotiates_quic():
    # Forced h3 proves the QUIC transport was built (derived from the mode) and
    # used on the first request, with no alt-svc warmup.
    with Client(http_version="h3", timeout_ms=30000) as c:
        r = c.get(H3_URL)
        assert r.ok, r.error
        assert r.alpn == "h3"


def test_default_is_h2_only():
    with Client(timeout_ms=30000) as c:
        r = c.get(H2_URL)
        assert r.ok, r.error
        assert r.alpn == "h2"


def test_auto_first_request_is_h2():
    # Chrome-faithful: the first request to an origin is H2; H3 is used only
    # after the origin advertises alt-svc: h3 (a later request).
    with Client(http_version="auto", timeout_ms=30000) as c:
        r = c.get(H2_URL)
        assert r.ok, r.error
        assert r.alpn == "h2"


def test_per_request_http_version():
    # The client default is H2; a per-request http_version="h1" negotiates
    # http/1.1 for that one request, and a subsequent default request is still
    # h2 — the override doesn't disturb the client.
    with Client(http_version="h2", timeout_ms=30000) as c:
        r1 = c.get("https://www.cloudflare.com/", http_version="h1")
        assert r1.ok, r1.error
        assert r1.alpn == "http/1.1"
        r2 = c.get("https://www.cloudflare.com/")  # inherits the H2 default
        assert r2.ok and r2.alpn == "h2"


def test_session_set_cookie_is_sent():
    # A cookie seeded out-of-band (no Set-Cookie ever delivered it) is attached
    # to the next request by the jar — the PerimeterX _px3/_pxvid use case.
    # httpbin /cookies echoes the request's Cookie header back as JSON.
    with Client(timeout_ms=30000) as c:
        s = Session(c, cookies=True)
        s.set_cookie("_px3", "seedval", domain="httpbin.org")
        r = s.get("https://httpbin.org/cookies")
        assert r.ok, r.error
        assert r.json().get("cookies", {}).get("_px3") == "seedval"
        s.close()
