"""The high-level Client / Session API over the holytls C ABI.

Marshalling rules that keep this memory-safe across the FFI boundary:
  * Every cdata we pass into a blocking C call (url/header/body buffers, the
    request struct) is held in a local list until the call returns — the call is
    synchronous, so nothing the GC could reclaim mid-flight.
  * Every holytls_response* the library returns is copied into a Python
    ``Response`` and then freed with holytls_response_free in a ``finally`` — the
    native side owns no Python memory and we own no native memory past the call.
"""

from __future__ import annotations

import binascii
import json as _json
import os
from typing import List, Optional, Sequence, Tuple, Union
from urllib.parse import urlencode

from holytls._models import (
    ConnectionClosed,
    FetchMode,
    Headers,
    HeaderInput,
    HolyTLSError,
    HttpVersion,
    Method,
    Profile,
    Response,
    Timing,
    WebSocketError,
)
from holytls._native import ffi, lib


def _normalize_headers(headers: HeaderInput) -> List[Tuple[str, str]]:
    if headers is None:
        return []
    if hasattr(headers, "items"):
        return [(str(k), str(v)) for k, v in headers.items()]
    return [(str(k), str(v)) for k, v in headers]


def _ensure_content_type(
    headers: List[Tuple[str, str]], ctype: str
) -> List[Tuple[str, str]]:
    """Append a Content-Type unless the caller already set one (case-insensitive)."""
    if any(k.lower() == "content-type" for k, _ in headers):
        return headers
    return headers + [("content-type", ctype)]


def _as_bytes(v) -> bytes:
    if isinstance(v, str):
        return v.encode("utf-8")
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    return str(v).encode("utf-8")


def _mp_quote(v) -> str:
    """Escape a value destined for a multipart Content-Disposition quoted-string
    param (name/filename). Percent-encodes the characters that would let a
    caller-supplied value break out of the quotes or inject a new MIME header
    line (CR/LF) — matching urllib3/requests (RFC 7578 §5.1). Backslash first so
    the later substitutions' '%' aren't double-encoded."""
    return (
        str(v)
        .replace("\\", "%5C")
        .replace('"', "%22")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def _no_crlf(v, what: str) -> str:
    """A value going into a raw (unquoted) MIME header line — Content-Type or a
    caller-supplied per-part header. CR/LF there is header injection, so reject
    it loudly rather than silently corrupt the framing (matches httpx)."""
    s = str(v)
    if "\r" in s or "\n" in s:
        raise ValueError(f"illegal CR/LF in multipart {what}: {s!r}")
    return s


def _encode_form(form) -> bytes:
    """application/x-www-form-urlencoded body from a mapping or (k, v) pairs.
    A list/tuple value emits repeated keys (a=1&a=2)."""
    items = form.items() if hasattr(form, "items") else form
    pairs: List[Tuple[str, str]] = []
    for k, v in items:
        if isinstance(v, (list, tuple)):
            pairs.extend((str(k), str(vv)) for vv in v)
        else:
            pairs.append((str(k), str(v)))
    return urlencode(pairs).encode("utf-8")


def _encode_multipart(fields, files) -> Tuple[bytes, str]:
    """Build a multipart/form-data body. `fields` are text parts (mapping or
    pairs); `files` map a field name to one of: bytes/str (content), or a
    (filename, content[, content_type[, headers]]) tuple. Returns (body, boundary).
    """
    boundary = "----holytls" + binascii.hexlify(os.urandom(16)).decode("ascii")
    out = bytearray()
    bb = boundary.encode("ascii")

    def part(disposition_extra: str, extra_headers, content: bytes):
        out.extend(b"--")
        out.extend(bb)
        out.extend(b"\r\n")
        out.extend(b'Content-Disposition: form-data')
        out.extend(disposition_extra.encode("utf-8"))
        out.extend(b"\r\n")
        for hk, hv in extra_headers:
            line = f"{_no_crlf(hk, 'header name')}: {_no_crlf(hv, 'header value')}"
            out.extend(line.encode("utf-8"))
            out.extend(b"\r\n")
        out.extend(b"\r\n")
        out.extend(content)
        out.extend(b"\r\n")

    field_items = fields.items() if hasattr(fields, "items") else (fields or [])
    for name, value in field_items:
        part(f'; name="{_mp_quote(name)}"', [], _as_bytes(value))

    file_items = files.items() if hasattr(files, "items") else (files or [])
    for name, spec in file_items:
        filename, content, ctype, hdrs = name, spec, None, []
        if isinstance(spec, (tuple, list)):
            filename = spec[0]
            content = spec[1]
            ctype = spec[2] if len(spec) > 2 else None
            hdrs = list(spec[3].items()) if len(spec) > 3 and spec[3] else []
        disp = f'; name="{_mp_quote(name)}"'
        if filename is not None:
            disp += f'; filename="{_mp_quote(filename)}"'
        extra = ([("Content-Type", _no_crlf(ctype, "content type"))] if ctype else []) + hdrs
        part(disp, extra, _as_bytes(content))

    out.extend(b"--")
    out.extend(bb)
    out.extend(b"--\r\n")
    return bytes(out), boundary


def _encode_body(
    data, json, form, files, headers: List[Tuple[str, str]]
) -> Tuple[Optional[bytes], List[Tuple[str, str]]]:
    """Resolve the request body from exactly one of data / json / form / files
    (files may carry text fields via form= or a dict data=) into bytes, adding
    the matching Content-Type when the caller didn't set one."""
    if files is not None:
        if json is not None:
            raise ValueError("files= cannot be combined with json=")
        if form is not None and data is not None:
            raise ValueError("with files=, pass text fields via only one of form= or data=")
        fields = form if form is not None else (data if data is not None else {})
        if isinstance(fields, (str, bytes, bytearray, memoryview)):
            raise ValueError("with files=, data=/form= must be a mapping of text fields")
        body, boundary = _encode_multipart(fields, files)
        return body, _ensure_content_type(
            headers, "multipart/form-data; boundary=" + boundary
        )
    given = sum(v is not None for v in (data, json, form))
    if given > 1:
        raise ValueError("pass only one of data=, json=, form=")
    if form is not None:
        return _encode_form(form), _ensure_content_type(
            headers, "application/x-www-form-urlencoded"
        )
    if json is not None:
        body = _json.dumps(json, separators=(",", ":")).encode("utf-8")
        return body, _ensure_content_type(headers, "application/json")
    if data is None:
        return None, headers
    if isinstance(data, str):
        return data.encode("utf-8"), headers
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data), headers
    raise TypeError("data= must be str, bytes, or None (use json=/form=/files=)")


def _fill_request(c_req, *, method, url, headers, body, fetch_mode, no_redirects,
                  keep, proxy=None):
    """Populate a `holytls_request *` cdata; append every owned buffer to `keep`
    so it outlives the C call."""
    c_req.method = int(method)
    url_c = ffi.new("char[]", url.encode("utf-8"))
    keep.append(url_c)
    c_req.url = url_c
    if body:
        buf = ffi.from_buffer(body)  # zero-copy view; cdata pins the bytes object
        keep.append(buf)
        c_req.body = ffi.cast("uint8_t *", buf)
        c_req.body_len = len(body)
    else:
        c_req.body = ffi.NULL
        c_req.body_len = 0
    if headers:
        arr = ffi.new("holytls_header[]", len(headers))
        keep.append(arr)
        for i, (name, value) in enumerate(headers):
            nb = ffi.new("char[]", str(name).encode("utf-8"))
            vb = ffi.new("char[]", str(value).encode("utf-8"))
            keep.append(nb)
            keep.append(vb)
            arr[i].name = nb
            arr[i].value = vb
        c_req.headers = arr
        c_req.header_count = len(headers)
    else:
        c_req.headers = ffi.NULL
        c_req.header_count = 0
    c_req.fetch_mode = int(fetch_mode)
    c_req.no_redirects = 0 if no_redirects is None else (0 if no_redirects else 1)
    if proxy:
        pb = ffi.new("char[]", str(proxy).encode("utf-8"))
        keep.append(pb)
        c_req.proxy = pb
    else:
        c_req.proxy = ffi.NULL


def _response_from_c(c_resp) -> Response:
    """Copy a `holytls_response *` into a Python Response, then free it."""
    try:
        ok = bool(c_resp.ok)
        status = int(c_resp.status)
        error = (
            ffi.string(c_resp.error).decode("utf-8", "replace")
            if c_resp.error != ffi.NULL
            else None
        )
        if c_resp.body != ffi.NULL and c_resp.body_len:
            content = bytes(ffi.buffer(c_resp.body, c_resp.body_len))
        else:
            content = b""
        url = ffi.string(c_resp.final_url).decode("utf-8", "replace") if c_resp.final_url != ffi.NULL else ""
        alpn = ffi.string(c_resp.alpn).decode("utf-8", "replace") if c_resp.alpn != ffi.NULL else ""
        pairs: List[Tuple[str, str]] = []
        for i in range(c_resp.header_count):
            h = c_resp.headers[i]
            name = ffi.string(h.name).decode("utf-8", "replace") if h.name != ffi.NULL else ""
            value = ffi.string(h.value).decode("utf-8", "replace") if h.value != ffi.NULL else ""
            pairs.append((name, value))
        return Response(
            ok=ok,
            status_code=status,
            error=error,
            headers=Headers(pairs),
            content=content,
            url=url,
            alpn=alpn,
            resumed=bool(c_resp.resumed),
            early_data=bool(c_resp.early_data),
            timing=Timing(
                int(c_resp.dns_ms),
                int(c_resp.tcp_ms),
                int(c_resp.tls_ms),
                int(c_resp.total_ms),
            ),
        )
    finally:
        lib.holytls_response_free(c_resp)


class Client:
    """A Chrome-fingerprinted HTTP client.

    Each Client owns its own libuv loop and transport and is NOT thread-safe —
    drive one Client from one thread at a time. For concurrency, either issue a
    batch (``get_many``/``request_many``: many requests on one loop, the native
    event-loop concurrency) or give each thread its own Client.

    Use as a context manager (``with holytls.Client() as c: ...``) or call
    ``close()`` when done to release the native loop + connections.
    """

    def __init__(
        self,
        profile: Union[Profile, str, int] = Profile.CHROME,
        *,
        dual: bool = False,
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
        ca_file: Optional[str] = None,
        key_log_file: Optional[str] = None,
    ):
        prof = Profile.coerce(profile)
        version = HttpVersion.coerce(http_version) if http_version is not None else None
        # Forcing HTTP/3 requires a dual-transport client; enable it implicitly.
        if version == HttpVersion.HTTP_3:
            dual = True

        self._c = lib.holytls_client_new(int(prof), 1 if dual else 0, 1 if verify else 0)
        if self._c == ffi.NULL:
            raise HolyTLSError("failed to create native client (out of memory)")
        self._closed = False

        if timeout_ms:
            lib.holytls_client_set_timeout_ms(self._c, int(timeout_ms))
        if max_redirects:
            lib.holytls_client_set_max_redirects(self._c, int(max_redirects))
        if version is not None:
            lib.holytls_client_set_http_version(self._c, int(version))
        if ech:
            lib.holytls_client_set_ech_enabled(self._c, 1)
        if resumption:
            lib.holytls_client_set_resumption_enabled(self._c, 1)
        if early_data:
            lib.holytls_client_set_early_data_enabled(self._c, 1)
        if max_conns_per_origin:
            lib.holytls_client_set_max_conns_per_origin(self._c, int(max_conns_per_origin))
        if dns_cache_ttl_ms is not None:
            lib.holytls_client_set_dns_cache_ttl_ms(self._c, int(dns_cache_ttl_ms))
        if override_default_headers:
            lib.holytls_client_override_default_headers(self._c, 1)
        if header_order is not None:
            self.set_header_order(header_order)
        if proxy:
            if not self.set_proxy(proxy, verify_proxy=verify_proxy):
                raise HolyTLSError(f"invalid proxy URL: {proxy!r}")
        if proxies:
            for purl in proxies:
                if not self.add_proxy(purl, verify_proxy=verify_proxy):
                    raise HolyTLSError(f"invalid proxy URL: {purl!r}")
        if local_address is not None:
            if not self.set_local_address(local_address):
                raise HolyTLSError(f"invalid local address: {local_address!r}")
        if ca_file:
            if not lib.holytls_client_add_ca_file(self._c, ca_file.encode("utf-8")):
                raise HolyTLSError(f"could not load CA file: {ca_file!r}")
        if key_log_file:
            lib.holytls_client_set_key_log_file(self._c, key_log_file.encode("utf-8"))

    # -- configuration (also settable after construction) --------------------

    def set_proxy(self, proxy_url: str, *, verify_proxy: bool = True) -> bool:
        self._check()
        return bool(
            lib.holytls_client_set_proxy(
                self._c, proxy_url.encode("utf-8"), 1 if verify_proxy else 0
            )
        )

    def add_proxy(self, proxy_url: str, *, verify_proxy: bool = True) -> bool:
        """Add a proxy to the rotation pool. Non-pooled requests round-robin the
        pool (a per-request ``proxy=`` overrides it). Returns False on a bad URL
        or a full pool."""
        self._check()
        return bool(
            lib.holytls_client_add_proxy(
                self._c, proxy_url.encode("utf-8"), 1 if verify_proxy else 0
            )
        )

    def set_local_address(self, ip: str) -> bool:
        """Bind outgoing connections to source IP ``ip`` (IPv4/IPv6 literal) for
        egress-address selection; "" clears it. Returns False on a bad literal."""
        self._check()
        return bool(lib.holytls_client_set_local_address(self._c, ip.encode("utf-8")))

    def set_header_order(self, order: Union[str, Sequence[str]]) -> bool:
        self._check()
        csv = order if isinstance(order, str) else ", ".join(order)
        return bool(lib.holytls_client_set_header_order(self._c, csv.encode("utf-8")))

    def pin_certificate(self, hostname: str, spki_sha256_b64: str, *, include_subdomains: bool = False) -> bool:
        self._check()
        return bool(
            lib.holytls_client_pin_certificate(
                self._c,
                hostname.encode("utf-8"),
                spki_sha256_b64.encode("utf-8"),
                1 if include_subdomains else 0,
            )
        )

    # -- single requests -----------------------------------------------------

    def request(
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
        on_chunk=None,
        fetch_mode: FetchMode = FetchMode.DEFAULT,
        allow_redirects: bool = True,
    ) -> Response:
        self._check()
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
        )
        if on_chunk is not None:
            # Stream the (decoded) body to on_chunk as it arrives; the returned
            # Response has empty content. cffi does NOT propagate an exception
            # raised in a callback through the C call (it would print + continue),
            # so capture it in the bridge and re-raise after the call returns.
            err: list = []

            def _bridge(user, data, n):
                if err:  # already failed — stop calling the user's callback
                    return
                try:
                    on_chunk(bytes(ffi.buffer(data, n)))
                except BaseException as e:  # noqa: BLE001 - re-raised below
                    err.append(e)

            cb = ffi.callback("void(void *, const uint8_t *, uint64_t)", _bridge)
            keep.append(cb)  # keep the callback cdata alive across the blocking call
            c_resp = lib.holytls_perform_stream(self._c, c_req, cb, ffi.NULL)
            if err:
                if c_resp != ffi.NULL:
                    lib.holytls_response_free(c_resp)
                raise err[0]
        else:
            c_resp = lib.holytls_perform(self._c, c_req)
        if c_resp == ffi.NULL:
            raise HolyTLSError("native allocation failure")
        return _response_from_c(c_resp)

    def get(self, url: str, **kwargs) -> Response:
        return self.request(Method.GET, url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request(Method.POST, url, **kwargs)

    def put(self, url: str, **kwargs) -> Response:
        return self.request(Method.PUT, url, **kwargs)

    def delete(self, url: str, **kwargs) -> Response:
        return self.request(Method.DELETE, url, **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        return self.request(Method.HEAD, url, **kwargs)

    def patch(self, url: str, **kwargs) -> Response:
        return self.request(Method.PATCH, url, **kwargs)

    def options(self, url: str, **kwargs) -> Response:
        return self.request(Method.OPTIONS, url, **kwargs)

    # -- websocket -----------------------------------------------------------

    def websocket(self, url: str, *, headers: HeaderInput = None) -> "WebSocket":
        """Open a WebSocket over this client (its TLS fingerprint). `url` is a
        ``wss://`` (or ``ws://`` / ``https://``) URL. Returns a connected
        :class:`WebSocket`; raises :class:`WebSocketError` on a failed handshake."""
        self._check()
        return WebSocket(self, url, headers)

    # -- concurrent batch (one loop, many in-flight requests) ----------------

    def request_many(self, requests: Sequence[dict]) -> List[Response]:
        """Perform many requests CONCURRENTLY on the client's single loop and
        return their responses in order. Each item is a dict with the same keys
        as ``request`` (``method``, ``url``, ``headers``, ``data``/``json``,
        ``fetch_mode``, ``allow_redirects``); ``url`` is required.

        This is the native event-loop concurrency — true network parallelism in
        one thread, with the GIL held for the whole batch (no Python runs while
        the requests are in flight). Set ``timeout_ms`` on the client so one
        stuck request can't hang the batch.
        """
        self._check()
        items = list(requests)
        n = len(items)
        if n == 0:
            return []
        keep: list = []
        c_reqs = ffi.new("holytls_request[]", n)
        keep.append(c_reqs)
        for i, item in enumerate(items):
            hdrs = _normalize_headers(item.get("headers"))
            body, hdrs = _encode_body(
                item.get("data"), item.get("json"), item.get("form"),
                item.get("files"), hdrs,
            )
            _fill_request(
                c_reqs[i],
                method=Method.coerce(item.get("method", Method.GET)),
                url=item["url"],
                headers=hdrs,
                body=body,
                fetch_mode=item.get("fetch_mode", FetchMode.DEFAULT),
                no_redirects=not item.get("allow_redirects", True),
                keep=keep,
                proxy=item.get("proxy"),
            )
        out = ffi.new("holytls_response *[]", n)
        written = lib.holytls_perform_many(self._c, c_reqs, n, out)
        if written != n:
            # A catastrophic setup failure (0): free whatever came back.
            for i in range(int(written)):
                if out[i] != ffi.NULL:
                    lib.holytls_response_free(out[i])
            raise HolyTLSError("native batch submission failed")
        # Each out[i] is an independently-owned native response. _response_from_c
        # frees the slot it processes (in its finally); if marshalling raises
        # mid-loop (e.g. MemoryError copying a huge body, or KeyboardInterrupt),
        # free the slots we never reached so their native objects don't leak.
        results: List[Response] = []
        try:
            for i in range(n):
                results.append(_response_from_c(out[i]))
        except BaseException:
            for j in range(len(results) + 1, n):  # +1: the raising slot freed itself
                if out[j] != ffi.NULL:
                    lib.holytls_response_free(out[j])
            raise
        return results

    def get_many(self, urls: Sequence[str], **kwargs) -> List[Response]:
        """Concurrent GET of many URLs (shared per-request kwargs)."""
        return self.request_many([dict(method=Method.GET, url=u, **kwargs) for u in urls])

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        if not self._closed and self._c != ffi.NULL:
            lib.holytls_client_free(self._c)
            self._closed = True
            self._c = ffi.NULL

    def _check(self) -> None:
        if self._closed or self._c == ffi.NULL:
            raise HolyTLSError("client is closed")

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class Session:
    """A cookie jar + per-hop redirect identity layered on a Client.

    The transport (and its fingerprint) is the passed-in Client; the Session
    attaches matching cookies per request, absorbs Set-Cookie, and follows
    redirects with the jar applied at each hop. One Session is one browser-like
    identity — drive it serially (its jar is not locked). For many independent
    identities, create many Sessions on a shared Client.
    """

    def __init__(self, client: Client, *, cookies: bool = True, max_redirects: int = 10):
        self._client = client
        self._s = lib.holytls_session_new(1 if cookies else 0, int(max_redirects))
        if self._s == ffi.NULL:
            raise HolyTLSError("failed to create native session")
        self._closed = False

    def request(
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
    ) -> Response:
        if self._closed:
            raise HolyTLSError("session is closed")
        self._client._check()
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
            no_redirects=None,  # the session always runs its own redirect loop
            keep=keep,
            proxy=proxy,
        )
        c_resp = lib.holytls_session_perform(self._s, self._client._c, c_req)
        if c_resp == ffi.NULL:
            raise HolyTLSError("native allocation failure")
        return _response_from_c(c_resp)

    def get(self, url: str, **kwargs) -> Response:
        return self.request(Method.GET, url, **kwargs)

    def post(self, url: str, **kwargs) -> Response:
        return self.request(Method.POST, url, **kwargs)

    def put(self, url: str, **kwargs) -> Response:
        return self.request(Method.PUT, url, **kwargs)

    def delete(self, url: str, **kwargs) -> Response:
        return self.request(Method.DELETE, url, **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        return self.request(Method.HEAD, url, **kwargs)

    def patch(self, url: str, **kwargs) -> Response:
        return self.request(Method.PATCH, url, **kwargs)

    def close(self) -> None:
        if not self._closed and self._s != ffi.NULL:
            lib.holytls_session_free(self._s)
            self._closed = True
            self._s = ffi.NULL

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class WebSocket:
    """A RFC 6455 WebSocket over a Client's fingerprinted TLS connection.

    Blocking + single-threaded, like the rest of the binding: ``recv`` runs the
    client's loop until the next message. Over an h2 server it uses RFC 8441
    Extended CONNECT; otherwise the HTTP/1.1 Upgrade (see ``transport``). Open it
    with :meth:`Client.websocket`; drive one socket from one thread and not
    concurrently with that client's other calls.

        with client.websocket("wss://echo.websocket.org") as ws:
            ws.send("hello")
            print(ws.recv())          # -> "hello"
    """

    def __init__(self, client: "Client", url: str, headers: HeaderInput = None):
        client._check()
        self._client = client
        self._closed = False
        keep: list = []
        hdrs = _normalize_headers(headers)
        c_hdrs = ffi.NULL
        if hdrs:
            arr = ffi.new("holytls_header[]", len(hdrs))
            keep.append(arr)
            for i, (name, value) in enumerate(hdrs):
                nb = ffi.new("char[]", str(name).encode("utf-8"))
                vb = ffi.new("char[]", str(value).encode("utf-8"))
                keep.append(nb)
                keep.append(vb)
                arr[i].name = nb
                arr[i].value = vb
            c_hdrs = arr
        self._ws = lib.holytls_ws_connect(
            client._c, url.encode("utf-8"), c_hdrs, len(hdrs)
        )
        if self._ws == ffi.NULL:
            raise WebSocketError("failed to create native websocket (out of memory)")
        err = lib.holytls_ws_error(self._ws)
        if err != ffi.NULL:
            msg = ffi.string(err).decode("utf-8", "replace")
            lib.holytls_ws_free(self._ws)
            self._ws = ffi.NULL
            raise WebSocketError(f"websocket connect failed: {msg}")

    @property
    def transport(self) -> str:
        """``"h1"`` (HTTP/1.1 Upgrade) or ``"h2"`` (Extended CONNECT)."""
        t = lib.holytls_ws_transport(self._ws) if self._ws != ffi.NULL else 0
        return {1: "h1", 2: "h2"}.get(t, "")

    def send(self, data: Union[str, bytes]) -> None:
        """Send one message: a ``str`` as a text frame, ``bytes`` as binary."""
        if isinstance(data, str):
            self.send_text(data)
        elif isinstance(data, (bytes, bytearray, memoryview)):
            self.send_binary(bytes(data))
        else:
            raise TypeError("WebSocket.send expects str or bytes")

    def send_text(self, text: str) -> None:
        self._check()
        raw = text.encode("utf-8")
        if not lib.holytls_ws_send_text(self._ws, raw, len(raw)):
            raise WebSocketError("websocket send failed (connection closed?)")

    def send_binary(self, data: bytes) -> None:
        self._check()
        if not lib.holytls_ws_send_binary(self._ws, data, len(data)):
            raise WebSocketError("websocket send failed (connection closed?)")

    def recv(self, timeout: Optional[float] = None) -> Union[str, bytes]:
        """Receive the next message (pings are auto-answered). Returns ``str``
        for a text frame, ``bytes`` for binary. Raises :class:`ConnectionClosed`
        when the peer closes, :class:`WebSocketError` on a transport error, and
        ``TimeoutError`` if ``timeout`` (seconds) elapses with no message (the
        connection stays usable). ``timeout=None`` blocks indefinitely."""
        self._check()
        msg = ffi.new("holytls_ws_message *")
        timeout_ms = int(timeout * 1000) if timeout and timeout > 0 else 0
        rc = lib.holytls_ws_recv(self._ws, msg, timeout_ms)
        if rc == -2:
            raise TimeoutError(f"websocket recv timed out after {timeout}s")
        if rc < 0:
            err = lib.holytls_ws_error(self._ws)
            detail = ffi.string(err).decode("utf-8", "replace") if err != ffi.NULL else "error"
            raise WebSocketError(f"websocket recv failed: {detail}")
        # Copy out before the next call invalidates msg.data.
        payload = bytes(ffi.buffer(msg.data, msg.len)) if msg.len else b""
        if rc == 0:  # the peer's Close
            reason = payload.decode("utf-8", "replace")
            raise ConnectionClosed(int(msg.close_code), reason)
        return payload.decode("utf-8", "replace") if msg.is_text else payload

    def close(self, code: int = 1000, reason: str = "") -> None:
        if not self._closed and self._ws != ffi.NULL:
            r = reason.encode("utf-8") if reason else ffi.NULL
            lib.holytls_ws_close(self._ws, int(code) & 0xFFFF, r)
            lib.holytls_ws_free(self._ws)
            self._closed = True
            self._ws = ffi.NULL

    def _check(self) -> None:
        if self._closed or self._ws == ffi.NULL:
            raise WebSocketError("websocket is closed")

    def __enter__(self) -> "WebSocket":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def version() -> str:
    """The native libholytls_capi version string."""
    return ffi.string(lib.holytls_version()).decode("utf-8")
