"""asyncio-native client (`AsyncClient`) over the same flat C ABI.

A single background thread runs holytls's libuv loop; requests are submitted
WITHOUT blocking and resolved on your asyncio loop, so ``await asyncio.gather(...)``
runs many requests concurrently on the one loop — true network parallelism, no
thread-per-request. All native client state is touched only on the loop thread;
the asyncio thread only enqueues submits + resolves futures (the C side bridges
the two with a mutex'd queue + uv_async).
"""
import asyncio
import itertools
import threading
from typing import List, Optional, Sequence, Tuple, Union

from holytls._client import (
    _apply_config,
    _encode_body,
    _fill_request,
    _normalize_headers,
    _profile_name,
    _response_from_c_lazy,
    available_profiles,
)
from holytls._models import (
    FetchMode,
    HeaderInput,
    HolyTLSError,
    HttpVersion,
    Method,
    Profile,
    Response,
)
from holytls._native import ffi, lib

# Max completions processed per _drain tick before yielding to the loop (bounds
# the GIL hold for a huge burst; lazy bodies keep each item cheap, so generous).
_DRAIN_MAX = 128


class AsyncClient:
    """An asyncio-native, Chrome-fingerprinted HTTP client.

    Mirrors :class:`Client`, but every request is a coroutine. A dedicated
    background thread drives holytls's libuv loop; submission is non-blocking and
    completions resolve on your event loop, so::

        async with holytls.AsyncClient(http_version="auto") as c:
            r = await c.get("https://example.com")
            results = await asyncio.gather(*[c.get(u) for u in urls])  # concurrent

    runs all the requests at once on the single native loop. Drive one
    AsyncClient from one asyncio loop; use ``async with`` (or ``await aclose()``)
    for a clean shutdown.
    """

    def __init__(
        self,
        profile: Union[Profile, str, int] = Profile.CHROME,
        *,
        verify: bool = True,
        timeout_ms: int = 30000,
        max_redirects: int = 0,
        http_version: Union[HttpVersion, str, int, None] = None,
        proxy: Optional[str] = None,
        proxies: Optional[Sequence[str]] = None,
        verify_proxy: bool = True,
        ech: bool = False,
        resumption: bool = False,
        early_data: bool = False,
        max_conns_per_origin: int = 0,
        dns_cache_ttl_ms: Optional[int] = None,
        header_order: Optional[Union[str, Sequence[str]]] = None,
        override_default_headers: bool = False,
        local_address: Optional[str] = None,
        cert: Optional[Union[str, Tuple[str, str]]] = None,
        cert_password: Optional[str] = None,
        ca_file: Optional[str] = None,
        key_log_file: Optional[str] = None,
    ):
        name = _profile_name(profile)
        mode = (
            HttpVersion.coerce(http_version)
            if http_version is not None
            else HttpVersion.HTTP_2
        )
        self._ac = lib.holytls_async_client_new_named(
            name.encode("utf-8"), int(mode), 1 if verify else 0
        )
        if self._ac == ffi.NULL:
            avail = available_profiles()
            if name and name not in avail:
                raise HolyTLSError(f"unknown profile {profile!r}; available: {avail}")
            raise HolyTLSError("failed to create native async client (out of memory)")

        # Apply config against the inner client BEFORE the loop thread starts —
        # config touches client state and is not thread-safe.
        base = lib.holytls_async_client_base(self._ac)
        try:
            _apply_config(
                base,
                timeout_ms=timeout_ms,
                max_redirects=max_redirects,
                ech=ech,
                resumption=resumption,
                early_data=early_data,
                max_conns_per_origin=max_conns_per_origin,
                dns_cache_ttl_ms=dns_cache_ttl_ms,
                override_default_headers=override_default_headers,
                header_order=header_order,
                proxy=proxy,
                proxies=proxies,
                verify_proxy=verify_proxy,
                local_address=local_address,
                cert=cert,
                cert_password=cert_password,
                ca_file=ca_file,
                key_log_file=key_log_file,
            )
        except BaseException:
            lib.holytls_async_client_free(self._ac)  # no thread started yet
            self._ac = ffi.NULL
            raise

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._inflight: dict = {}  # req_id -> asyncio.Future
        self._next_id = itertools.count(1)
        # Submit batching: request() parks marshalled requests here and schedules
        # ONE _flush per event-loop tick, so an asyncio.gather of N becomes one
        # holytls_async_submit_many (one FFI call + one lock + one uv_async_send)
        # instead of N. Touched only on the asyncio thread.
        self._pending: list = []  # [(c_req, keep, req_id, fut), ...]
        self._flush_scheduled = False
        # Completion batching: _on_complete (loop thread) parks finished responses
        # here and schedules ONE _drain, collapsing N call_soon_threadsafe into ~1.
        # Single-producer (loop thread) / single-consumer (asyncio thread); see
        # _drain for the lock-free ordering + its GIL-atomicity assumption.
        self._completions: list = []  # [(req_id, c_resp), ...]
        self._drain_scheduled = False
        self._carry: list = []  # bounded-drain leftover (asyncio-thread-only)
        # ONE lifetime cffi callback dispatches every completion by req_id.
        self._cb = ffi.callback(
            "void(void *, uint64_t, holytls_response *)", self._on_complete
        )
        self._closed = False
        self._thread = threading.Thread(
            target=lib.holytls_async_run, args=(self._ac,),
            name="holytls-loop", daemon=True,
        )
        self._thread.start()

    def _check(self) -> None:
        if self._closed or self._ac == ffi.NULL:
            raise HolyTLSError("async client is closed")

    # -- completion plumbing -------------------------------------------------

    def _on_complete(self, user, req_id, c_resp):
        # Runs on the libuv LOOP THREAD. Do the minimum: park the response and
        # schedule ONE _drain (collapsing N call_soon_threadsafe -> ~1 for a batch
        # of completions). Never raise (cffi swallows it).
        loop = self._loop
        if loop is None or loop.is_closed():
            lib.holytls_response_free(c_resp)  # nobody to deliver to -> free
            return
        # list.append is GIL-atomic; the loop thread is the sole producer.
        self._completions.append((int(req_id), c_resp))
        if not self._drain_scheduled:
            self._drain_scheduled = True
            try:
                loop.call_soon_threadsafe(self._drain)
            except RuntimeError:  # loop closed/closing between the checks
                self._drain_scheduled = False
                # The response stays in _completions; aclose frees leftovers.

    def _drain(self):
        # Runs on the ASYNCIO THREAD (sole consumer). Clear the flag BEFORE
        # swapping the batch out: a completion appended after the swap then sees
        # _drain_scheduled False and schedules a fresh _drain — so no completion is
        # ever stranded with no drain pending (swap-then-clear would silently lose
        # a wakeup and hang an awaiter). Relies on CPython GIL-atomicity of the
        # list rebind + bool store; for a no-GIL build, guard (append+schedule) and
        # (clear+swap) with a threading.Lock.
        self._drain_scheduled = False
        batch = self._completions
        self._completions = []
        # Carry forward any leftover from a prior bounded tick (asyncio-thread-only,
        # so it never races the loop-thread producer of _completions).
        if self._carry:
            batch = self._carry + batch
            self._carry = []
        # Bound the work per tick so a huge burst can't hold the GIL in one shot
        # (lazy bodies make each item cheap, but the eager header decode still
        # costs O(headers)); re-schedule the remainder for the next tick.
        if len(batch) > _DRAIN_MAX:
            self._carry = batch[_DRAIN_MAX:]
            batch = batch[:_DRAIN_MAX]
            if not self._drain_scheduled:
                self._drain_scheduled = True
                self._loop.call_soon(self._drain)
        for req_id, c_resp in batch:
            fut = self._inflight.pop(req_id, None)
            if fut is None or fut.cancelled():
                lib.holytls_response_free(c_resp)  # awaiter gone -> free
                continue
            try:
                # LAZY: decode the cheap meta now, defer the body copy to first
                # .content access — so this drain never memcpys a body under the
                # GIL (which would starve the loop thread). The Response owns
                # c_resp (ffi.gc) and frees it exactly once.
                resp = _response_from_c_lazy(c_resp)
            except BaseException as e:  # noqa: BLE001 - surfaced on the future
                if not fut.done():
                    fut.set_exception(e)
                continue
            if not fut.done():
                fut.set_result(resp)

    # -- requests ------------------------------------------------------------

    async def request(
        self,
        method: Union[Method, str, int],
        url: str,
        *,
        headers: HeaderInput = None,
        data=None,
        json=None,
        form=None,
        files=None,
        proxy: Optional[str] = None,
        fetch_mode: FetchMode = FetchMode.DEFAULT,
        allow_redirects: bool = True,
        header_order: Optional[Union[str, Sequence[str]]] = None,
    ) -> Response:
        self._check()
        loop = asyncio.get_running_loop()
        self._loop = loop  # set before submit -> visible to _on_complete
        hdrs = _normalize_headers(headers)
        body, hdrs = _encode_body(data, json, form, files, hdrs)
        keep: list = []
        c_req = ffi.new("holytls_request *")
        keep.append(c_req)
        _fill_request(
            c_req,
            method=Method.coerce(method),
            url=url,
            headers=hdrs,
            body=body,
            fetch_mode=fetch_mode,
            no_redirects=not allow_redirects,
            keep=keep,
            proxy=proxy,
            header_order=header_order,
        )
        fut = loop.create_future()
        req_id = next(self._next_id)
        self._inflight[req_id] = fut  # register BEFORE submit -> no lost wakeup
        # Defer the submit: park it and schedule ONE _flush this tick. A gather's
        # N coroutines all append before _flush fires -> one submit_many for all N.
        # `keep` (and c_req) must outlive _flush's submit_many, so hold them here.
        self._pending.append((c_req, keep, req_id, fut))
        if not self._flush_scheduled:
            self._flush_scheduled = True
            loop.call_soon(self._flush)
        try:
            return await fut
        except asyncio.CancelledError:
            # Drop our registration; _flush skips already-cancelled futures, and if
            # one was already submitted a late response is freed by _drain.
            self._inflight.pop(req_id, None)
            raise

    def _flush(self):
        # Runs on the ASYNCIO THREAD; MUST be sync (no await). Coalesce every
        # request parked since the last tick into ONE holytls_async_submit_many.
        self._flush_scheduled = False
        pending = self._pending
        self._pending = []
        # Skip cancelled/done futures: avoids a wasted request AND never submits a
        # req_id whose _inflight entry request() already popped. Build BOTH the
        # reqs[] and req_ids[] arrays from this one `live` list so they never
        # desync (reqs[i] <-> ids[i] is always the same request).
        live = [e for e in pending if not e[3].done()]
        if not live:
            return
        if self._closed:  # aclose ran between append and _flush (same thread)
            for _c, _k, rid, fut in live:
                self._inflight.pop(rid, None)
                if not fut.done():
                    fut.set_exception(HolyTLSError("async client closed"))
            return
        n = len(live)
        reqs = ffi.new("holytls_request[]", n)
        ids = ffi.new("uint64_t[]", n)
        keeps = []  # pin every per-request keep across the C call
        for i, (c_req, keep, rid, _fut) in enumerate(live):
            reqs[i] = c_req[0]  # struct-copy: pointer fields keep referencing keep
            ids[i] = rid
            keeps.append(keep)
        ok = lib.holytls_async_submit_many(self._ac, reqs, n, ids, self._cb, ffi.NULL)
        # submit_many deep-copied synchronously; reqs/ids/keeps may drop now.
        if not ok:
            for _c, _k, rid, fut in live:
                self._inflight.pop(rid, None)
                if not fut.done():
                    fut.set_exception(HolyTLSError("async client is closed"))

    async def get(self, url: str, **kwargs) -> Response:
        return await self.request(Method.GET, url, **kwargs)

    async def post(self, url: str, **kwargs) -> Response:
        return await self.request(Method.POST, url, **kwargs)

    async def put(self, url: str, **kwargs) -> Response:
        return await self.request(Method.PUT, url, **kwargs)

    async def delete(self, url: str, **kwargs) -> Response:
        return await self.request(Method.DELETE, url, **kwargs)

    async def head(self, url: str, **kwargs) -> Response:
        return await self.request(Method.HEAD, url, **kwargs)

    async def patch(self, url: str, **kwargs) -> Response:
        return await self.request(Method.PATCH, url, **kwargs)

    async def options(self, url: str, **kwargs) -> Response:
        return await self.request(Method.OPTIONS, url, **kwargs)

    async def get_many(self, urls: Sequence[str], **kwargs) -> List[Response]:
        """Concurrent GET of many URLs on the one loop (a thin gather wrapper)."""
        return await asyncio.gather(*[self.get(u, **kwargs) for u in urls])

    # -- lifecycle -----------------------------------------------------------

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True  # a _flush queued during the join below sees this + bails
        lib.holytls_async_stop(self._ac)  # reject new submits, wake loop to stop
        # Join the loop thread WITHOUT blocking the event loop. After this returns,
        # no producer remains (no _on_complete can fire, no native completion).
        await asyncio.get_running_loop().run_in_executor(None, self._thread.join)
        # Fail any requests parked but never submitted (nothing was sent past stop,
        # so there is no native memory to free for these — just their futures).
        for _c, _k, rid, fut in self._pending:
            self._inflight.pop(rid, None)
            if not fut.done():
                fut.set_exception(HolyTLSError("async client closed"))
        self._pending = []
        self._flush_scheduled = False
        # Free any completions parked but never drained (loop died before _drain):
        # these are owned native responses Python must free (the C free path below
        # doesn't know about them). Drain BOTH the producer queue and the bounded-
        # drain carry.
        for _rid, c_resp in self._completions:
            lib.holytls_response_free(c_resp)
        for _rid, c_resp in self._carry:
            lib.holytls_response_free(c_resp)
        self._completions = []
        self._carry = []
        self._drain_scheduled = False
        # Fail any futures still unresolved (in-flight at stop, or registered but
        # never flushed).
        for fut in list(self._inflight.values()):
            if not fut.done():
                fut.set_exception(HolyTLSError("async client closed"))
        self._inflight.clear()
        lib.holytls_async_client_free(self._ac)  # safe: thread joined, in_callback==0
        self._ac = ffi.NULL
        self._cb = None  # release the cffi callback (no more completions can fire)

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    def __del__(self):
        # Best-effort only: we can't join/await here. Stop the loop thread so it
        # doesn't spin; the daemon thread + native client are reclaimed at process
        # exit. Use `async with` / `await aclose()` for a deterministic shutdown.
        if not getattr(self, "_closed", True) and getattr(self, "_ac", ffi.NULL) != ffi.NULL:
            try:
                lib.holytls_async_stop(self._ac)
            except Exception:
                pass
