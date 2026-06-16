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
    _response_from_c,
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
        # Runs on the libuv LOOP THREAD. Do the minimum: hop to the asyncio loop;
        # all marshalling + freeing happens there. Never raise (cffi swallows it).
        loop = self._loop
        if loop is None or loop.is_closed():
            lib.holytls_response_free(c_resp)  # nobody to deliver to -> free
            return
        try:
            loop.call_soon_threadsafe(self._deliver, int(req_id), c_resp)
        except RuntimeError:  # loop already closed/closing between the checks
            lib.holytls_response_free(c_resp)

    def _deliver(self, req_id, c_resp):
        # Runs on the ASYNCIO THREAD.
        fut = self._inflight.pop(req_id, None)
        if fut is None or fut.cancelled():
            lib.holytls_response_free(c_resp)  # awaiter gone -> free
            return
        try:
            resp = _response_from_c(c_resp)  # marshals AND frees c_resp (finally)
        except BaseException as e:  # noqa: BLE001 - surfaced on the future
            if not fut.done():
                fut.set_exception(e)
            return
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
        ok = lib.holytls_async_submit(self._ac, c_req, req_id, self._cb, ffi.NULL)
        # holytls_async_submit deep-copied the request synchronously, so `keep`
        # (and c_req) need not outlive this call.
        if not ok:
            self._inflight.pop(req_id, None)
            raise HolyTLSError("async client is closed")
        try:
            return await fut
        except asyncio.CancelledError:
            # Drop our registration; if a response still lands, _deliver frees it.
            self._inflight.pop(req_id, None)
            raise

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
        self._closed = True
        lib.holytls_async_stop(self._ac)  # reject new submits, wake loop to stop
        # Join the loop thread WITHOUT blocking the event loop.
        await asyncio.get_running_loop().run_in_executor(None, self._thread.join)
        # Fail any futures still unresolved (their submits were cancelled in C or
        # their in-flight requests were abandoned at stop).
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
