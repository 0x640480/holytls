"""Tests for the asyncio binding (`AsyncClient`).

Offline tests drive coroutines with ``asyncio.run`` (no ``pytest-asyncio``
dependency, so the CI python job needs no change) and never touch the network.
The live tests (gated on ``HOLYTLS_LIVE``, like the C suite + test_live.py) prove
the bridge actually drives the wire and that ``gather`` runs concurrently on the
one native loop.
"""
import asyncio
import os
import time

import pytest

import holytls
from holytls import AsyncClient, HolyTLSError, HttpVersion


def test_asyncclient_exported():
    assert holytls.AsyncClient is AsyncClient


def test_construct_and_aclose():
    async def run():
        c = AsyncClient()
        await c.aclose()
        await c.aclose()  # idempotent double-close must not crash
    asyncio.run(run())


def test_async_context_manager():
    async def run():
        async with AsyncClient(http_version="auto") as c:
            assert c is not None
    asyncio.run(run())


@pytest.mark.parametrize("http_version", [None, "h2", "auto", "h3", "h1",
                                          HttpVersion.AUTO, HttpVersion.HTTP_3])
def test_construct_every_mode(http_version):
    async def run():
        async with AsyncClient(http_version=http_version):
            pass
    asyncio.run(run())


@pytest.mark.parametrize("profile", ["chrome149", "chrome148", "firefox151"])
def test_construct_every_profile(profile):
    async def run():
        async with AsyncClient(profile=profile):
            pass
    asyncio.run(run())


def test_dual_kwarg_is_removed():
    # Same single-knob contract as the sync Client: no `dual`, http_version only.
    with pytest.raises(TypeError):
        AsyncClient(dual=True)


def test_request_after_close_raises():
    async def run():
        c = AsyncClient()
        await c.aclose()
        with pytest.raises(HolyTLSError):
            await c.get("https://example.com")
    asyncio.run(run())


def test_unknown_profile_raises():
    with pytest.raises(HolyTLSError):
        AsyncClient(profile="netscape-navigator")


# --------------------------------------------------------------------------- #
# Live (network-gated)                                                         #
# --------------------------------------------------------------------------- #

_LIVE = pytest.mark.skipif(
    not os.environ.get("HOLYTLS_LIVE"),
    reason="network-gated; set HOLYTLS_LIVE=1 to run",
)

H2_URL = "https://tls.browserleaks.com/json"
H3_URL = "https://quic.browserleaks.com/json"


@_LIVE
def test_live_await_get():
    async def run():
        async with AsyncClient(timeout_ms=30000) as c:
            r = await c.get(H2_URL)
            assert r.ok, r.error
            assert r.alpn == "h2"
    asyncio.run(run())


@_LIVE
def test_live_gather_is_concurrent():
    async def run():
        async with AsyncClient(timeout_ms=30000) as c:
            urls = [H2_URL] * 8
            t0 = time.monotonic()
            rs = await asyncio.gather(*[c.get(u) for u in urls])
            dt = time.monotonic() - t0
            assert len(rs) == 8 and all(r.ok and r.status_code == 200 for r in rs)
            # 8 concurrent requests on one loop must be far faster than 8 serial
            # round-trips; a generous bound that still proves overlap.
            assert dt < 8.0, f"gather took {dt:.1f}s — not concurrent?"
    asyncio.run(run())


@_LIVE
def test_live_forced_h3():
    async def run():
        async with AsyncClient(http_version="h3", timeout_ms=30000) as c:
            r = await c.get(H3_URL)
            assert r.ok, r.error
            assert r.alpn == "h3"
    asyncio.run(run())
