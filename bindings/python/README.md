# holytls — Python bindings

A [`requests`](https://requests.readthedocs.io)-style API over **holytls**, a C
client that reproduces Chrome's and Firefox's **byte-exact TLS / HTTP-2 / HTTP-3
fingerprint** (JA4, Akamai H2, QUIC-JA4). Built with [cffi](https://cffi.readthedocs.io)
in out-of-line **API mode**, so the binding is cross-checked against the real ABI
header and can't silently drift.

```python
import holytls

with holytls.Client(http_version="auto") as client:  # H2, then H3 via alt-svc
    r = client.get("https://tls.peet.ws/api/all")
    print(r.status_code, r.alpn)              # 200 h2
    print(r.json()["tls"]["ja4"])             # t13d1516h2_8daaf6152771_d8a2da3f94cd
```

Prefer asyncio? `AsyncClient` mirrors the same surface; `asyncio.gather` runs
requests concurrently on the one native loop:

```python
import asyncio, holytls

async def main():
    async with holytls.AsyncClient(http_version="auto") as client:
        results = await asyncio.gather(*(client.get(u) for u in urls))

asyncio.run(main())
```

Calls are blocking: a background libuv loop runs holytls's async I/O and returns a
copied-out `Response`. `get_many` / `request_many` drive many requests on that one
loop in a single call — real network concurrency, no threads.

## Install

Build the native library first, then install the package (it auto-discovers
`./build-capi` or `./build`; point elsewhere with `HOLYTLS_CAPI_LIBDIR`, recorded as
an rpath so no `LD_LIBRARY_PATH` at runtime).

```sh
cmake -B build-capi -G Ninja -DHOLYTLS_BUILD_CAPI=ON \
    -DHOLYTLS_BUILD_TESTS=OFF -DHOLYTLS_BUILD_EXAMPLES=OFF
cmake --build build-capi --target holytls_capi
pip install ./bindings/python
```

## API

### `Client`

The transport. Owns a libuv loop; **not thread-safe** (one Client per thread).

```python
client = holytls.Client(
    profile="chrome",     # "chrome" | "chrome149" | "chrome148" | "firefox151"
    verify=True,          # validate server certificates
    timeout_ms=30000,     # whole-operation timeout (covers the redirect chain)
    max_redirects=0,      # follow up to N 3xx redirects (browser-faithful)
    http_version=None,    # None/"h2"=H2-only (default) | "auto"=H2->H3 via alt-svc
                          #   | "h3" | "h1"; QUIC is built for "auto"/"h3"
    proxy=None,           # "http://", "https://", "socks5://[user:pass@]host:port"
    proxy_pool=None,      # a list of proxy URLs to round-robin
    ech=False,            # real Encrypted Client Hello
    resumption=False,     # TLS 1.3 session resumption (1-RTT)
    early_data=False,     # 0-RTT early data for idempotent requests
    max_conns_per_origin=0,  # >0 enables connection pooling (Chrome-like: 1)
    header_order=None,    # "accept, user-agent, ..." override (advanced)
    local_address=None,   # bind outgoing connections to this source IP
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
client.post(url, form={"a": 1})       # x-www-form-urlencoded
client.post(url, files={"f": ("name.txt", b"...", "text/plain")}, form={...})  # multipart
client.get(url, proxy="socks5://user:pass@host:1080")  # per-request proxy
client.request("PUT", url, data=..., headers={"x-foo": "bar"})
# also: put, delete, head, patch, options
```

Pass exactly one body of `data` / `json` / `form`; `files=` is multipart and may
carry `form`/`data` text parts. Stream a large body with `on_chunk=` — a push
callback over the **decoded** body (forces a single hop; H2 streams for real, with
bounded memory):

```python
with open("big.bin", "wb") as f:
    client.get("https://host/big.bin", on_chunk=f.write)
```

### Concurrency, proxies & egress

```python
client.get_many([url1, url2, url3])            # in-order results, one loop, one call
client.request_many([{"method": "POST", "url": u, "json": {...}}])
client = holytls.Client(proxy_pool=["http://p1:8080", "socks5://p2:1080"])  # round-robin
client = holytls.Client(local_address="203.0.113.7")  # bind egress source IP
```

A single request holds the GIL, so it blocks the calling thread. For concurrency
prefer `get_many` / `request_many` (one loop, one C call, no threads), and always
set `timeout_ms` so one stuck request can't hang the batch. For separate identities
give each thread or process its own `Client`.

### `Session` — cookies + redirects

A browser-like identity (cookie jar + per-hop redirect loop) over a Client; the
fingerprint stays the Client's. Run one Session serially; make many for many
identities.

```python
with holytls.Client() as client:
    s = holytls.Session(client, cookies=True, max_redirects=10)
    s.get("https://example.com/login")     # absorbs Set-Cookie
    s.get("https://example.com/account")   # carries the jar

# seed an out-of-band cookie (JS-set / anti-bot solver) no Set-Cookie will deliver:
s.set_cookie("_px3", "<solver-value>", domain="example.com")
# defaults: path="/", expires=0 (session), host_only=False, secure=True,
#           http_only=False, same_site=0  (0=unset 1=Lax 2=Strict 3=None)
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

## Examples

See [`examples/`](examples/) (quickstart, concurrent, post_json, session_cookies,
fingerprint, streaming, websocket): `python bindings/python/examples/quickstart.py`.
