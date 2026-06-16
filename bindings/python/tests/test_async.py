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
# Offline batching (no network): exercise the batched submit (one              #
# submit_many per gather) + batched completion drain end to end. A closed      #
# loopback port resolves fast as a connection-refused (ok=0) Response, never   #
# an exception or a hang — so every future must resolve, proving the bridge    #
# correlates req_id->future correctly across the batch.                        #
# --------------------------------------------------------------------------- #

_DEAD = "https://127.0.0.1:1/"  # port 1: refused -> fast ok=0 completion


def _is_response(x):
    return not isinstance(x, BaseException) and hasattr(x, "ok")


def test_gather_batched_offline():
    async def run():
        async with AsyncClient(timeout_ms=3000) as c:
            rs = await asyncio.gather(*[c.get(_DEAD) for _ in range(64)])
            assert len(rs) == 64  # none lost or duplicated
            assert all(_is_response(r) and not r.ok and r.error for r in rs)
    asyncio.run(run())


def test_lone_request_offline():
    # N=1: the request still flows through the deferred-_flush path (one tick).
    async def run():
        async with AsyncClient(timeout_ms=3000) as c:
            r = await c.get(_DEAD)
            assert _is_response(r) and not r.ok and r.error
    asyncio.run(run())


def test_cancel_within_gather_offline():
    # Cancel half the batch after it's submitted; survivors must still complete
    # and the whole thing tears down cleanly (no hang, no stray exception type).
    async def run():
        async with AsyncClient(timeout_ms=3000) as c:
            tasks = [asyncio.ensure_future(c.get(_DEAD)) for _ in range(16)]
            await asyncio.sleep(0.02)  # let them park, _flush, and start in-flight
            for t in tasks[:8]:
                t.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            assert len(results) == 16
            for r in results:
                assert _is_response(r) or isinstance(r, asyncio.CancelledError)
    asyncio.run(run())


def test_close_during_inflight_offline():
    # aclose() while a batch is in flight: every future resolves (completed,
    # failed-closed, or cancelled) — never hangs, never leaks an awaiter.
    async def run():
        c = AsyncClient(timeout_ms=5000)
        tasks = [asyncio.ensure_future(c.get(_DEAD)) for _ in range(16)]
        await asyncio.sleep(0)  # park + _flush (submit the whole batch)
        await c.aclose()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        assert len(results) == 16
        for r in results:
            assert _is_response(r) or isinstance(
                r, (HolyTLSError, asyncio.CancelledError)
            )
    asyncio.run(run())


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
            urls = [H2_URL] * 32  # one batched submit_many for the whole gather
            t0 = time.monotonic()
            rs = await asyncio.gather(*[c.get(u) for u in urls])
            dt = time.monotonic() - t0
            assert len(rs) == 32 and all(r.ok and r.status_code == 200 for r in rs)
            # 32 concurrent requests on one loop must be far faster than 32 serial
            # round-trips; a generous bound that still proves overlap.
            assert dt < 12.0, f"gather took {dt:.1f}s — not concurrent?"
    asyncio.run(run())


@_LIVE
def test_live_forced_h3():
    async def run():
        async with AsyncClient(http_version="h3", timeout_ms=30000) as c:
            r = await c.get(H3_URL)
            assert r.ok, r.error
            assert r.alpn == "h3"
    asyncio.run(run())
