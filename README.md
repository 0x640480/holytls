# holytls

**A C TLS-impersonation HTTP client that reproduces a real browser's fingerprint
across TLS, HTTP/2, and HTTP/3.**

holytls matches a real browser (Chrome or Firefox) on the wire — not just the TLS
ClientHello (JA3/JA4) like most impersonation clients, but also the HTTP/2
SETTINGS/WINDOW_UPDATE/priority shape (Akamai) and the HTTP/3 + QUIC fingerprint
(h3 settings hash, QUIC-JA4). All four are live-verified against `tls.peet.ws`,
`browserleaks.com`, and a fingerprint-preserving MITM proxy:

| Dimension | Chrome 149 fingerprint (reproduced exactly) |
|---|---|
| TLS — **JA4** | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| HTTP/2 — **Akamai** | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| HTTP/3 — **QUIC-JA4** | `q13d0311h3_55b375c5d22e_653d80c3fe9d` |
| HTTP/3 — **h3 settings hash** | `ba909fc3dc419ea5c5b26c6323ac1879` |

All four are byte-exact for **Firefox 151** too — the first non-Chrome family
(Firefox's own cipher order, FFDHE groups, fixed extension order, and even the
legacy `extended_master_secret`/`renegotiation_info` it uniquely sends in a
TLS1.3-only QUIC ClientHello). Profiles are selectable by name, and adding one is
a small data file + a registry row.

---

## What sets it apart

Most TLS-impersonation clients stop at the TLS ClientHello. holytls matches the
browser's fingerprint across **all three transports** and performs the behaviors
a real browser does:

- **Byte-exact across TLS + HTTP/2 + HTTP/3** — JA4 *and* the H2 Akamai shape
  *and* the H3/QUIC fingerprint, not just JA3/JA4.
- **Multiple browsers, registry-driven** — Chrome 148/149 and Firefox 151 ship
  today, each byte-exact across all four fingerprints; a new browser/version is a
  self-contained profile file + one registry row.
- **Chrome's HTTP/3 behavior** — H2 first, then upgrade to HTTP/3 once an origin
  advertises `alt-svc: h3` (never a cold H3 start).
- **Real ECH** — fetches the origin's `ECHConfigList` over DoH and encrypts the
  inner ClientHello (real SNI hidden), falling back to ECH-GREASE like Chrome.
- **TLS 1.3 resumption + 0-RTT early data** — on both TCP/H2 and QUIC/H3, so
  repeat visits carry the resumed-handshake fingerprint, not a fresh one.

## Quick start

Pull it into your CMake project — that's the supported integration (it builds its
own pinned BoringSSL/libuv/nghttp2/ngtcp2/nghttp3 from source):

```cmake
include(FetchContent)
FetchContent_Declare(holytls
  GIT_REPOSITORY https://github.com/0x640480/holy-tls.git
  GIT_TAG main)
FetchContent_MakeAvailable(holytls)        # builds just the library

add_executable(myapp main.c)
target_link_libraries(myapp PRIVATE holytls)
```

A minimal request (async: submit, run the loop, get the result in a callback):

```c
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

static void handle_response(void *user, const Response *resp) {
  (void)user;
  if (!resp->ok) { fprintf(stderr, "error: %s\n", resp->error); return; }
  String8 body = response_text(resp);  // valid only during this callback
  printf("HTTP %d  (%llu bytes)\n", resp->status,
         (unsigned long long)resp->body_len);
}

int main(void) {
  EventLoop loop; loop_init(&loop);
  Client c;
  // Chrome 149 over H2 (NULL h3 + HttpVersion_H2 = TCP only); verify=1.
  client_init(&c, &loop, profile_chrome149(), NULL, HttpVersion_H2, /*verify=*/1);
  client_get(&c, str8_lit("https://tls.peet.ws/api/all"), handle_response, 0);
  loop_run(&loop);                                             // drives the request
  client_cleanup(&c); loop_shutdown(&loop);
}
```

Beyond a GET: `client_post` is a one-line convenience, and `client_request`
takes a designated-initializer `RequestParams` for full control — method,
headers, and body, plus optional `.fetch_mode` (coherent Sec-Fetch-*),
`.no_redirects`, and a per-request `.deadline_ns`:

```c
client_post(&c, str8_lit("https://httpbin.org/post"), str8_lit("{\"k\":1}"),
            handle_response, 0);

Header headers[] = { header_lit("content-type", "application/json") };
RequestParams req = {
    .method       = Method_POST,
    .url          = str8_lit("https://httpbin.org/post"),
    .headers      = headers,
    .header_count = 1,
    .body         = str8_lit("{\"k\":1}"),
};
client_request(&c, &req, handle_response, 0);
```

---

## Full-configuration example

[`examples/stealth.c`](examples/stealth.c) enables the browser-faithful behaviors
— dual transport (H2→H3 upgrade), cert verification, real ECH, resumption + 0-RTT,
and a `Session` (cookie jar + redirect following) — then repeats a request so you
can watch Chrome's transport behavior unfold:

```
request 1: HTTP 200  alpn=h2   resumed=0  early_data=0   # H2, fresh handshake
request 2: HTTP 200  alpn=h3   resumed=0  early_data=0   # upgraded to HTTP/3 via alt-svc
request 3: HTTP 200  alpn=h3   resumed=1  early_data=1   # resumed + 0-RTT accepted
```

The first connection to any origin is **always** a fresh, byte-exact handshake;
only reconnects resume / send 0-RTT — exactly like a browser.

---

## Features

Browser-grade HTTP with the knobs a real browser needs. Most are opt-in — the full
surface lives in [`src/core/client.h`](src/core/client.h).

| Area | What you get | Key calls |
|------|--------------|-----------|
| **Profiles** | Chrome 148/149 + Firefox 151, byte-exact across all four fingerprints; selectable by name | `profile_chrome149`, `profile_firefox151`, `profile_by_name` |
| **Requests** | Async GET / POST, or full control via a `RequestParams` options struct (method, headers, body, Sec-Fetch, redirects, deadline), plus streaming response bodies | `client_get`, `client_post`, `client_request` (`.on_chunk`) |
| **Transports** | HTTP/1.1, HTTP/2, HTTP/3 — pin one, or run H2 with automatic H2→H3 upgrade (the `HttpVersion` passed to `client_init`) | `client_init`, `client_set_http_version` |
| **WebSocket** | RFC 6455 over the fingerprinted TLS connection — H1 Upgrade or H2 Extended CONNECT, permessage-deflate | `ws_conn_alloc`, `ws_conn_connect`, `ws_conn_send`, `ws_conn_recv` |
| **TLS behaviors** | Real ECH (encrypted SNI), TLS 1.3 resumption, 0-RTT early data, mutual TLS (client certificate) | `client_set_ech_enabled`, `client_set_resumption_enabled`, `client_set_early_data_enabled`, `client_set_client_cert` |
| **Sessions** | Lightweight per-task identity — cookie jar + redirect budget over one shared transport | `session_init`, `session_get` |
| **Proxies** | HTTP / HTTPS / SOCKS5 (incl. HTTP/3 over SOCKS5), a rotation pool, runtime switching, source-IP binding, custom CA for MITM | `client_set_proxy`, `client_add_proxy`, `client_set_local_address`, `client_add_ca_file` |
| **Headers** | Full Chrome set by default, or caller-controlled headers with explicit wire order | `client_override_default_headers`, `client_set_header_order` |
| **Pooling** | Opt-in H2 / H3 connection keep-alive | `client_set_max_conns_per_origin` |
| **Reliability** | Whole-operation timeout, browser-faithful redirects, DNS caching | `client_set_timeout_ms`, `client_set_max_redirects`, `client_set_dns_cache_ttl_ms` |
| **Inspection** | Request/response hooks, certificate pinning, TLS key log for Wireshark | `client_set_pre_hook`, `client_pin_certificate`, `client_set_key_log_file` |
| **Response bodies** | Transparent gzip / deflate / br / zstd decompression, typed accessors | `response_text`, `response_get_header`, `response_json` |

---

## Verifying the fingerprint

Route holytls through [powhttp](https://powhttp.com/) (or any MITM proxy) and inspect
the exact bytes it sends — verification stays **on**, you just trust the proxy root:

```c
client_init(&c, &loop, profile_chrome149(), NULL, HttpVersion_H2, /*verify=*/1);
client_add_ca_file(&c, "powhttp Root Certificate.pem");        // trust the MITM root
client_set_proxy(&c, str8_lit("http://127.0.0.1:8888"), 0);    // route through it
```

powhttp then shows holytls's captured ClientHello + H2 frames hashing to exactly the
Chrome 149 fingerprints above.

---

## Building & requirements

- **CMake ≥ 3.20**, a **C11** compiler, and **Go + perl** (to build the bundled
  BoringSSL fork). Deps (BoringSSL, libuv, nghttp2, ngtcp2, nghttp3, …) are fetched
  and built from source at configure time.
- Standalone: `cmake -B build && cmake --build build && ctest --test-dir build`.
  Sanitizers: `-DHOLYTLS_ASAN=ON`. As a subproject, tests/examples are off by default
  (`HOLYTLS_BUILD_TESTS` / `HOLYTLS_BUILD_EXAMPLES`).
- The TLS layer is the **lexiforest/boringssl** curl-impersonate fork, which emits
  the extensions stock BoringSSL can't (so the ClientHello is byte-exact).

### Cross-compiling for Windows (MinGW-w64)

A fully static Windows x86_64 `.exe` cross-compiles from Linux via the bundled
toolchain file (codecs built from source, libstdc++/winpthread linked statically):

```sh
cmake -B build-mingw -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake
ninja -C build-mingw
```

## Examples

- [`examples/quickstart.c`](examples/quickstart.c) — the smallest complete program: an
  async GET + response accessors.
- [`examples/fingerprint.c`](examples/fingerprint.c) — verify the byte-exact
  JA3/JA4/Akamai fingerprint the server observes, via `tls.peet.ws`.
- [`examples/post_json.c`](examples/post_json.c) — POST a JSON body with custom headers
  (the `RequestParams` options struct) and parse the JSON reply.
- [`examples/session.c`](examples/session.c) — stateful browsing: cookie jar + redirect
  following + connection pooling (and an optional proxy via `$PROXY`).
- [`examples/stealth.c`](examples/stealth.c) — full Chrome fidelity: dual H2→H3, real
  ECH, TLS 1.3 resumption + 0-RTT.

---

## Python binding

A `requests`-style Python API ([cffi](https://cffi.readthedocs.io), API mode) lives
in [`bindings/python/`](bindings/python/). It links a self-contained native shared
library (`libholytls_capi`, built from [`capi/`](capi/)) that bridges holytls's async
event loop to a blocking call — plus a batch call for true single-loop concurrency.

```python
import holytls

with holytls.Client(http_version="auto") as client:  # H2, then H3 via alt-svc
    r = client.get("https://tls.peet.ws/api/all")
    print(r.status_code, r.alpn, r.json()["tls"]["ja4"])

    # many requests in flight on one event loop:
    for resp in client.get_many(["https://example.com", "https://example.org"]):
        print(resp.status_code, resp.url)
```

…or asyncio — `AsyncClient` mirrors the same surface, and `asyncio.gather` runs
every request concurrently on the one native loop:

```python
import asyncio, holytls

async def main():
    async with holytls.AsyncClient(http_version="auto") as client:
        r = await client.get("https://example.com")
        results = await asyncio.gather(*(client.get(u) for u in urls))

asyncio.run(main())
```

```sh
cmake -B build-capi -G Ninja -DHOLYTLS_BUILD_CAPI=ON \
    -DHOLYTLS_BUILD_TESTS=OFF -DHOLYTLS_BUILD_EXAMPLES=OFF
cmake --build build-capi --target holytls_capi
pip install ./bindings/python
```

See [`bindings/python/README.md`](bindings/python/README.md) for the full API —
`Client` / `AsyncClient`, `Session`, `WebSocket`, profile selection
(`profile="firefox151"`), concurrent batches, multipart/form bodies, streaming,
proxies, mTLS, ECH/resumption, and the response model.

---

## Third-party libraries

holytls is a thin C layer over some excellent open-source work. The networking
and TLS libraries are built from source (pinned versions) at configure time; the
compression codecs are linked from the system if present; `stb_sprintf` is
vendored in-tree (`src/vendor/`). Thanks to all their authors.

| Library | Role in holytls | Source | License |
|---|---|---|---|
| **BoringSSL** (lexiforest fork) | TLS 1.2/1.3, the byte-exact impersonation ClientHello, and QUIC crypto. Default is the impersonation fork; falls back to upstream | [lexiforest/boringssl](https://github.com/lexiforest/boringssl) · [google/boringssl](https://github.com/google/boringssl) | Apache-2.0 / OpenSSL / ISC |
| **libuv** `v1.52.1` | event loop, non-blocking TCP/UDP sockets, async DNS | [libuv/libuv](https://github.com/libuv/libuv) | MIT |
| **nghttp2** `v1.69.0` | HTTP/2 framing | [nghttp2/nghttp2](https://github.com/nghttp2/nghttp2) | MIT |
| **ngtcp2** `v1.23.0` | QUIC transport | [ngtcp2/ngtcp2](https://github.com/ngtcp2/ngtcp2) | MIT |
| **nghttp3** `v1.9.0` | HTTP/3 + QPACK | [ngtcp2/nghttp3](https://github.com/ngtcp2/nghttp3) | MIT |
| **picohttpparser** | HTTP/1.x response parsing | [h2o/picohttpparser](https://github.com/h2o/picohttpparser) | MIT |
| **yyjson** `0.12.0` | JSON (session persistence, fingerprint-oracle parsing) | [ibireme/yyjson](https://github.com/ibireme/yyjson) | MIT |
| **zlib** | gzip/deflate content decoding + TLS cert compression (required) | [madler/zlib](https://github.com/madler/zlib) | zlib |
| **brotli** | `br` content + cert decompression (optional) | [google/brotli](https://github.com/google/brotli) | MIT |
| **zstd** | `zstd` content + cert decompression (optional) | [facebook/zstd](https://github.com/facebook/zstd) | BSD-3-Clause |
| **stb_sprintf** | dependency-free `snprintf` (vendored) | [nothings/stb](https://github.com/nothings/stb) | Public domain / MIT |

Licenses are summarized for convenience — see each project for authoritative terms.

## Credits

- **[curl-impersonate](https://github.com/lwthiker/curl-impersonate)** and
  **[lexiforest/curl_cffi](https://github.com/lexiforest/curl_cffi)** — the BoringSSL
  impersonation fork holytls builds on. It emits the extra TLS extensions stock
  BoringSSL can't, which is what makes a byte-exact Chrome ClientHello possible.
- **[JA4+](https://github.com/FoxIO-LLC/ja4)** (FoxIO) — the TLS / QUIC / HTTP
  fingerprint suite holytls reproduces and tests against.
- **[tls.peet.ws](https://tls.peet.ws)** and **[browserleaks.com](https://browserleaks.com)**
  — the public fingerprinting oracles used to live-verify byte-exactness.
