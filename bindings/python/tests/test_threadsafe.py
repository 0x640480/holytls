"""Thread-safety tests for the shared ``Client``.

A ``Client``'s direct requests run on a background libuv loop, so one Client is
safe to drive from many threads at once. These tests exercise that:

  * OFFLINE (always run, deterministic): concurrent requests to a refused
    loopback port hammer the real submit/complete/Event bridge + the shared
    in-flight map from many threads (a race would crash/hang, not just fail);
    many threads concurrently open+close Sessions on one Client (concurrent
    private sub-client mint/free); and the runtime-config guard.
  * LIVE (``HOLYTLS_LIVE=1``): a ThreadPoolExecutor hammering one shared Client
    with real requests, ``get_many`` ordering, and a Session per worker thread.

For a data-race check, run the offline tests under ASan/TSan (build the capi
with ``-DHOLYTLS_ASAN=ON`` and install the binding against it).

Run::

    pytest bindings/python/tests/test_threadsafe.py
    HOLYTLS_LIVE=1 pytest bindings/python/tests/test_threadsafe.py
"""
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

import holytls
from holytls import Client, HolyTLSError, Session

live = pytest.mark.skipif(
    not os.environ.get("HOLYTLS_LIVE"),
    reason="network-gated; set HOLYTLS_LIVE=1 to run",
)

# A loopback port nothing listens on -> immediate connection-refused, no DNS, no
# external traffic. Lets the offline tests drive the concurrent request bridge
# deterministically (every call returns a Response with ok=False, fast).
REFUSED = "https://127.0.0.1:1/"


# -- offline (deterministic) -------------------------------------------------

def test_shared_client_concurrent_requests_offline():
    # 16 threads x N requests on ONE shared Client, all to a refused port. This
    # pounds the thread-safe path: holytls_async_submit_many from many threads,
    # the loop-thread completion callback, the per-request Event, and the shared
    # _inflight map. A race would crash/abort/hang; success = every call returns
    # a Response (ok=False here) and nothing deadlocks.
    with Client(timeout_ms=4000) as c:
        def fetch(_):
            r = c.get(REFUSED)
            assert r is not None
            assert r.ok is False  # connection refused -> transport failure
            return True

        with ThreadPoolExecutor(max_workers=16) as ex:
            results = list(ex.map(fetch, range(96)))
        assert len(results) == 96 and all(results)


def test_shared_client_get_many_offline():
    # get_many on the shared client: submitted together, all complete, returned
    # in order (here all refused).
    with Client(timeout_ms=4000) as c:
        rs = c.get_many([REFUSED] * 8)
        assert len(rs) == 8
        assert all(r is not None and r.ok is False for r in rs)


def test_concurrent_sessions_on_shared_client_offline():
    # Many threads each open+close Sessions on ONE shared Client with no
    # requests. Each Session mints a private single-threaded sub-client, so this
    # exercises concurrent sub-client mint/free off a shared Client. The shared
    # Client is built first (single-threaded), so any one-time global init is
    # done before the threads start.
    with Client() as c:
        def worker(_):
            for _ in range(5):
                s = Session(c)
                s.close()
            return True

        with ThreadPoolExecutor(max_workers=6) as ex:
            assert all(ex.map(worker, range(6)))


def test_concurrent_session_requests_offline():
    # Sessions share the Client's background loop (holytls_async_session_submit),
    # each with its own cookie jar. Many threads, each its own Session, all
    # issuing requests to a refused port — exercises the session-submit bridge +
    # per-session jars interleaved on the one shared loop. A race would crash/hang.
    with Client(timeout_ms=4000) as c:
        def work(_):
            with Session(c) as s:
                for _ in range(3):
                    r = s.get(REFUSED)
                    assert r is not None and r.ok is False
            return True

        with ThreadPoolExecutor(max_workers=8) as ex:
            assert all(ex.map(work, range(8)))


def test_runtime_mutators_allowed_before_first_request():
    # Config mutators apply while the background loop hasn't started (the normal
    # configure-then-use pattern). A parseable proxy/address returns True.
    with Client() as c:
        assert c.add_proxy("http://127.0.0.1:8080") is True
        assert c.set_local_address("127.0.0.1") is True


def test_runtime_mutators_raise_once_loop_started():
    # Once the background loop is live, runtime mutation is not thread-safe and
    # must raise (pointing at the constructor kwargs). _ensure_started flips the
    # loop on with no I/O — the deterministic stand-in for "after first request".
    with Client() as c:
        c._ensure_started()
        with pytest.raises(HolyTLSError):
            c.add_proxy("http://127.0.0.1:8081")
        with pytest.raises(HolyTLSError):
            c.set_local_address("127.0.0.1")
        with pytest.raises(HolyTLSError):
            c.set_header_order("accept, user-agent")


def test_double_close_is_safe():
    c = Client()
    c.get_many([REFUSED])  # start the loop
    c.close()
    c.close()  # idempotent, no crash
    with pytest.raises(HolyTLSError):
        c.get(REFUSED)  # closed -> raises, no hang


def test_close_without_any_request_is_safe():
    # A Client that never issued a request never started its loop thread; close
    # must free the native client directly without a join.
    c = Client()
    c.close()
    c.close()


# -- live (network-gated) ----------------------------------------------------

LIVE_URL = "https://tls.browserleaks.com/json"


@live
def test_shared_client_threadpool_hammer_live():
    with Client(timeout_ms=30000) as c:
        def fetch(_):
            r = c.get(LIVE_URL)
            assert r.ok, r.error
            assert r.status_code == 200
            return r.status_code

        with ThreadPoolExecutor(max_workers=16) as ex:
            results = list(ex.map(fetch, range(64)))
        assert len(results) == 64 and all(s == 200 for s in results)


@live
def test_get_many_in_order_live():
    with Client(timeout_ms=30000) as c:
        rs = c.get_many([LIVE_URL] * 5)
        assert len(rs) == 5 and all(r.ok for r in rs)


@live
def test_session_per_thread_live():
    with Client(timeout_ms=30000) as c:
        def work(_):
            with Session(c) as s:
                r = s.get(LIVE_URL)
                return r.ok

        with ThreadPoolExecutor(max_workers=8) as ex:
            assert all(ex.map(work, range(8)))


@live
def test_mutator_raises_after_real_request_live():
    with Client(timeout_ms=30000) as c:
        r = c.get(LIVE_URL)
        assert r.ok
        with pytest.raises(HolyTLSError):
            c.add_proxy("http://127.0.0.1:8080")
