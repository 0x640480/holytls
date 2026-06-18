"""Thread-safety tests for the shared ``Client``.

Direct requests run on a background libuv loop, so one Client is safe to drive
from many threads. Offline tests (always run) hammer the real submit/complete/
Event bridge from many threads against a refused loopback port — deterministic,
and a race would crash or hang, not just fail. Live tests (``HOLYTLS_LIVE=1``)
repeat the key cases against a real server. Run the offline tests under ASan to
check for data races (build the capi with ``-DHOLYTLS_ASAN=ON``).
"""
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from holytls import Client, HolyTLSError, Session

live = pytest.mark.skipif(
    not os.environ.get("HOLYTLS_LIVE"),
    reason="network-gated; set HOLYTLS_LIVE=1 to run",
)

# A loopback port nothing listens on: immediate connection-refused, no DNS, no
# external traffic — so the offline tests exercise the concurrent bridge
# deterministically (every call returns a Response with ok=False, fast).
REFUSED = "https://127.0.0.1:1/"


# -- offline (deterministic) -------------------------------------------------

def test_concurrent_requests_on_shared_client():
    # 16 threads hammering one shared Client: many-thread submit, the loop-thread
    # completion callback, per-request Events, the shared _inflight map. A race
    # crashes/hangs; success = every call returns a Response and nothing deadlocks.
    with Client(timeout_ms=4000) as c:
        def fetch(_):
            r = c.get(REFUSED)
            assert r is not None and r.ok is False
            return True

        with ThreadPoolExecutor(max_workers=16) as ex:
            assert all(ex.map(fetch, range(96)))


def test_get_many_on_shared_client():
    # The batch path: submitted together, all complete.
    with Client(timeout_ms=4000) as c:
        rs = c.get_many([REFUSED] * 8)
        assert len(rs) == 8 and all(r is not None and r.ok is False for r in rs)


def test_concurrent_sessions_on_shared_client():
    # Each thread opens its own Session (own cookie jar) and issues requests; they
    # share the Client's one loop via holytls_async_session_submit. Covers
    # concurrent Session create/close + the session-submit bridge interleaved.
    with Client(timeout_ms=4000) as c:
        def work(_):
            with Session(c) as s:
                for _ in range(3):
                    assert s.get(REFUSED).ok is False
            return True

        with ThreadPoolExecutor(max_workers=8) as ex:
            assert all(ex.map(work, range(8)))


def test_runtime_mutators_guarded_by_loop_start():
    # Config mutators work before the loop starts (configure-then-use) and raise
    # once it is live. _ensure_started flips the loop on with no I/O.
    with Client() as c:
        assert c.add_proxy("http://127.0.0.1:8080") is True
        assert c.set_local_address("127.0.0.1") is True
        c._ensure_started()
        for mutate in (lambda: c.add_proxy("http://127.0.0.1:8081"),
                       lambda: c.set_local_address("127.0.0.1"),
                       lambda: c.set_header_order("accept, user-agent")):
            with pytest.raises(HolyTLSError):
                mutate()


def test_close_is_idempotent():
    # Both close paths: a started client (stop + join the loop thread) and one
    # that never started (direct free). Double-close is a no-op; use-after-close
    # raises rather than hanging.
    started = Client()
    started.get_many([REFUSED])  # starts the loop
    started.close()
    started.close()
    with pytest.raises(HolyTLSError):
        started.get(REFUSED)

    never_started = Client()
    never_started.close()
    never_started.close()


# -- live (network-gated) ----------------------------------------------------

LIVE_URL = "https://tls.browserleaks.com/json"


@live
def test_threadpool_hammer_live():
    with Client(timeout_ms=30000) as c:
        def fetch(_):
            r = c.get(LIVE_URL)
            assert r.ok and r.status_code == 200, r.error
            return r.status_code

        with ThreadPoolExecutor(max_workers=16) as ex:
            assert list(ex.map(fetch, range(64))) == [200] * 64


@live
def test_get_many_live():
    with Client(timeout_ms=30000) as c:
        rs = c.get_many([LIVE_URL] * 5)
        assert len(rs) == 5 and all(r.ok for r in rs)


@live
def test_session_per_thread_live():
    with Client(timeout_ms=30000) as c:
        def work(_):
            with Session(c) as s:
                return s.get(LIVE_URL).ok

        with ThreadPoolExecutor(max_workers=8) as ex:
            assert all(ex.map(work, range(8)))
