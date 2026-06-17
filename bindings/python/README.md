# holytls — Python bindings

A [`requests`](https://requests.readthedocs.io)-style Python API over **holytls**,
a C client that reproduces Chrome's **byte-exact TLS / HTTP-2 / HTTP-3
fingerprint** (JA4, Akamai H2, QUIC-JA4). Built with [cffi](https://cffi.readthedocs.io)
in out-of-line **API mode** — the C compiler cross-checks the binding against the
real ABI header, so it can't silently drift.

```python
import holytls

with holytls.Client(http_version="auto") as client:  # H2, then H3 via alt-svc
    r = client.get("https://tls.peet.ws/api/all")
    print(r.status_code, r.alpn)              # 200 h2
    print(r.json()["tls"]["ja4"])             # t13d1516h2_8daaf6152771_d8a2da3f94cd
```

Prefer asyncio? `AsyncClient` mirrors the same surface — every request is a
coroutine, and `asyncio.gather` runs them concurrently on the one native loop:

```python
import asyncio, holytls

async def main():
    async with holytls.AsyncClient(http_version="auto") as client:
        r = await client.get("https://example.com")
        results = await asyncio.gather(*(client.get(u) for u in urls))  # concurrent

asyncio.run(main())
```

## How it works

holytls is an **async, single-threaded** client built on a libuv event loop —
there is no blocking `client.do()`. The C ABI shim (`capi/holytls_capi.c`) bridges
that to a synchronous Python call: it submits a request, drives the loop until the
response lands, copies it out of holytls's "valid only during the callback" views
into memory Python owns, and returns it. A batch call submits *many* requests onto
the *same* loop and runs it once — the event-loop concurrency below.

## Install

The binding links a prebuilt native shared library (`libholytls_capi`), so build
that first, then install the Python package.

```sh
# 1. Build the native C ABI library (needs the holytls toolchain: cmake, a C/C++
#    compiler, Go + perl for BoringSSL — see the repo root README).
cmake -B build-capi -G Ninja -DHOLYTLS_BUILD_CAPI=ON \
    -DHOLYTLS_BUILD_TESTS=OFF -DHOLYTLS_BUILD_EXAMPLES=OFF
cmake --build build-capi --target holytls_capi

# 2. Install the Python binding (auto-discovers ./build-capi).
pip install ./bindings/python
```

If your build dir isn't `./build-capi` or `./build`, point the builder at it:

```sh
HOLYTLS_CAPI_LIBDIR=/path/to/build pip install ./bindings/python
```

The compiled extension records the library directory as an rpath, so no
`LD_LIBRARY_PATH` is needed at runtime.

## API

### `Client`

The transport. Owns a libuv loop; **not thread-safe** (one Client per thread).

```python
client = holytls.Client(
    profile="chrome",     # "chrome" | "chrome149" | "chrome148" | "firefox151"
    verify=True,          # validate server certificates
    timeout_ms=30000,     # whole-operation timeout (covers the redirect chain)
    max_redirects=0,      # follow up to N 3xx redirects (browser-faithful)
    http_version=None,    # the HTTP/3 knob: None/"h2"=H2-only (default) |
                          # "auto"=Chrome H2->H3 via alt-svc | "h3" | "h1".
                          # QUIC is built automatically for "auto"/"h3".
    proxy=None,           # "http://", "https://", "socks5://[user:pass@]host:port"
    proxy_pool=None,      # a list of proxy URLs to round-robin (rotation pool)
    ech=False,            # real Encrypted Client Hello
    resumption=False,     # TLS 1.3 session resumption (1-RTT)
    early_data=False,     # 0-RTT early data for idempotent requests
    max_conns_per_origin=0,  # >0 enables connection pooling (Chrome-like: 1)
    header_order=None,    # "accept, user-agent, ..." override (advanced)
    local_address=None,   # bind outgoing connections to this source IP (egress)
    ca_file=None,         # trust an extra PEM CA (e.g. a MITM debug proxy)
    key_log_file=None,    # NSS keylog for Wireshark
)
# also: client.add_proxy(url), client.set_local_address(ip) at runtime
```

Request methods return a `Response` and never raise on an HTTP status (call
`r.raise_for_status()` for that):

```python
client.get(url, headers=..., allow_redirects=True)
client.post(url, json={...})          # serializes + sets application/json
client.post(url, data=b"...")         # raw bytes (or str)
client.post(url, form={"a": 1, "b": [1, 2]})        # x-www-form-urlencoded
client.post(url, files={"f": ("name.txt", b"...", "text/plain")},   # multipart
            form={"field": "value"})                # text parts alongside files
client.get(url, proxy="socks5://user:pass@host:1080")  # per-request proxy
client.request("PUT", url, data=..., headers={"x-foo": "bar"})
# also: put, delete, head, patch, options
```

Body kinds (pass exactly one of `data` / `json` / `form`; `files` may carry
`form`/`data` text parts): `data=` raw bytes/str, `json=` an object (adds
`application/json`), `form=` urlencoded, `files=` multipart/form-data.

### Proxies & egress

```python
# rotation pool: each request round-robins; a per-request proxy= overrides it
client = holytls.Client(proxy_pool=["http://p1:8080", "socks5://p2:1080"])
client.add_proxy("http://p3:8080")                  # add more at runtime
client.get(url, proxy="http://specific:8080")       # override for one request

# bind outgoing connections to a source IP (egress selection, multi-homed hosts)
client = holytls.Client(local_address="203.0.113.7")
```

A `Session` resolves its proxy once (per-request `proxy=` or one pool pick) and
keeps it sticky across the whole cookie-aware redirect chain.

### Streaming large bodies

Pass `on_chunk=` to stream the **decoded** body in pieces instead of buffering it
— bounded memory for large downloads. The callback fires as data arrives; the
returned `Response` carries an empty `content`.

```python
with open("big.bin", "wb") as f:
    client.get("https://host/big.bin", on_chunk=f.write)
```

Notes: streaming is a **push** callback (not a pull `iter_content` — holytls runs
the request to completion in one blocking call). It forces a **single hop** (no
redirects) and the non-pooled path. **HTTP/2 streams for real** (bounded memory);
H1/H3 deliver the whole decoded body in one `on_chunk` call. An exception raised
in `on_chunk` is re-raised from the `get`/`post` call after the request unwinds.

### Concurrency — `get_many` / `request_many`

The native event-loop concurrency: every request runs on **one loop, one thread**,
in flight together. The whole batch is a single C call.

```python
responses = client.get_many([url1, url2, url3])          # in-order results
responses = client.request_many([
    {"method": "GET",  "url": url1},
    {"method": "POST", "url": url2, "json": {"a": 1}},
])
```

Always set `timeout_ms` so one stuck request can't hang the batch.

### `Session` — cookies + redirects

A browser-like identity (cookie jar + per-hop redirect loop) layered on a Client.
The fingerprint stays the Client's. Run one Session serially; make many for many
identities.

```python
with holytls.Client() as client:
    s = holytls.Session(client, cookies=True, max_redirects=10)
    s.get("https://example.com/login")     # absorbs Set-Cookie
    s.get("https://example.com/account")   # carries the jar
```

Seed a cookie directly into the jar for cookies obtained **out-of-band** — JS-set
or anti-bot-solver cookies (e.g. PerimeterX `_px3`/`_pxvid`) that no `Set-Cookie`
response will deliver:

```python
s.set_cookie("_px3", "<solver-value>", domain="example.com")
# options: path="/", expires=<epoch> (0=session), host_only=, secure=,
#          http_only=, same_site= (0=unset 1=Lax 2=Strict 3=None)
s.get("https://example.com/account")   # the seeded cookie rides along
```

### `Response`

| attribute | meaning |
|---|---|
| `ok` | **transport** success (TLS/HTTP framing) — *not* the HTTP status |
| `status_code` | HTTP status (e.g. `404`; `ok` is still `True`) |
| `error` | failure reason when `ok` is `False` |
| `content` / `text` | body as `bytes` / decoded `str` (charset-aware) |
| `json()` | parse the body as JSON |
| `headers` | case-insensitive, order-preserving (`get`, `get_all`, `items`) |
| `url` | final URL after redirects |
| `alpn` | negotiated protocol (`"h2"` / `"h3"`) |
| `resumed` / `early_data` | TLS 1.3 resumption / 0-RTT flags |
| `timing` | `dns_ms` / `tcp_ms` / `tls_ms` / `total_ms` |
| `raise_for_status()` | raise on transport failure or 4xx/5xx |

## Threading & the GIL

cffi calls hold the GIL, so a *single* request blocks the calling thread. For
concurrency, prefer **`get_many`/`request_many`** — many requests share one loop
in one C call, giving real network parallelism without threads (no Python runs
while they're in flight). For independent identities or CPU isolation, give each
**thread or process its own `Client`** (each is fully self-contained).

## Examples

See [`examples/`](examples/): `quickstart.py`, `concurrent.py`, `post_json.py`,
`session_cookies.py`, `fingerprint.py`.

```sh
python bindings/python/examples/quickstart.py
python bindings/python/examples/concurrent.py
```
