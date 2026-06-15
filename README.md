# holytls

**A C TLS-impersonation HTTP client that reproduces a real browser byte-for-byte —
across TLS, HTTP/2, *and* HTTP/3.**

holytls makes requests that are indistinguishable from Chrome on the wire. Not
just the TLS ClientHello (JA3/JA4) like most impersonation clients — also the
HTTP/2 SETTINGS/WINDOW_UPDATE/priority shape (Akamai), and the full HTTP/3 + QUIC
fingerprint (h3 settings hash, QUIC-JA4). All four are **live-verified byte-exact**
against `tls.peet.ws`, `browserleaks.com`, and a fingerprint-preserving MITM proxy:

| Dimension | Chrome 149 fingerprint (reproduced exactly) |
|---|---|
| TLS — **JA4** | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| HTTP/2 — **Akamai** | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| HTTP/3 — **QUIC-JA4** | `q13d0311h3_55b375c5d22e_653d80c3fe9d` |
| HTTP/3 — **h3 settings hash** | `ba909fc3dc419ea5c5b26c6323ac1879` |
---

## What sets it apart

Most TLS-impersonation clients stop at the TLS handshake. holytls goes the whole
way down the stack and across all three transports, with the behaviors a real
browser actually performs:

- **Byte-exact across TLS + HTTP/2 + HTTP/3** — not just JA3/JA4. The H2 Akamai
  fingerprint and the H3/QUIC fingerprints match Chrome exactly too.
- **First-class HTTP/3 / QUIC**, with Chrome's real transport behavior: H2 first,
  then **upgrade to HTTP/3 once an origin advertises `alt-svc: h3`** — Chrome never
  cold-starts H3, and neither do we.
- **Real ECH (Encrypted Client Hello)** — fetches the origin's `ECHConfigList` from
  its DNS HTTPS record over DoH and encrypts the inner ClientHello (real SNI
  hidden), falling back to ECH-GREASE exactly as Chrome does.
- **TLS 1.3 resumption + 0-RTT early data** — on both TCP/H2 and QUIC/H3, so repeat
  visits look like a real browser's (the resumed-handshake fingerprint, not a fresh
  one).
- **Massive concurrency, tiny footprint** — one event loop drives thousands of
  concurrent requests; no threads, no goroutines, no GC.
- **Wire-truth verifiable** — route through a MITM proxy (e.g. powhttp/mitmproxy)
  with `client_add_ca_file`, keep verification on, and inspect exactly what you
  send. holytls's fingerprint is unchanged by the proxy.
- **Generated, not hardcoded, Chrome details** — e.g. the `sec-ch-ua` GREASE brand
  list is produced by Chrome's own deterministic per-version algorithm, so a new
  Chrome version is a one-line bump, not a guess.

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
  client_init(&c, &loop, profile_chrome149(), /*verify=*/1);   // Chrome 149 over H2
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

## Maximum-fidelity example

Everything a real Chrome does, turned on at once — dual transport (H2→H3 upgrade),
cert verification, real ECH, resumption + 0-RTT, a cookie jar, browser-faithful
redirect following, and Chrome's complete navigation header set
(`user-agent`, `sec-ch-ua`, `sec-fetch-*`, `accept`, …). See
[`examples/stealth.c`](examples/stealth.c):

```c
EventLoop loop; loop_init(&loop);

// Chrome 149 over BOTH H2 and HTTP/3; verify the server cert (Chrome does).
Client client;
client_init_dual(&client, &loop, profile_chrome149(), profile_chrome149_h3(), 1);

// Behaviors a real Chrome exhibits (OFF by default so the default path is a
// byte-exact FRESH handshake; turned on here for full real-browsing fidelity).
client_set_ech_enabled(&client, 1);          // real ECH (encrypted SNI; GREASE if none)
client_set_resumption_enabled(&client, 1);   // TLS 1.3 ticket resumption
client_set_early_data_enabled(&client, 1);   // 0-RTT early data on reconnects
client_set_timeout_ms(&client, 30000);       // whole-operation deadline

// A Session adds the cookie jar + browser-faithful redirect following.
SessionConfig cfg; session_config_default(&cfg);   // cookies on, 10 redirects
Session session; session_init(&session, &cfg);

session_get(&session, &client, str8_lit("https://www.google.com/"), handle_response, 0);
loop_run(&loop);
```

Run it and watch Chrome's real transport behavior unfold across requests:

```
request 1: HTTP 200  alpn=h2   resumed=0  early_data=0   # H2, fresh handshake
request 2: HTTP 200  alpn=h3   resumed=0  early_data=0   # upgraded to HTTP/3 via alt-svc
request 3: HTTP 200  alpn=h3   resumed=1  early_data=1   # resumed + 0-RTT accepted
```

The first connection to any origin is **always** a fresh, byte-exact handshake;
only reconnects resume / send 0-RTT — exactly like a browser.

---

## Features

Browser-grade HTTP with the knobs a real Chrome needs. Most are opt-in — the full
surface lives in [`src/core/client.h`](src/core/client.h).

| Area | What you get | Key calls |
|------|--------------|-----------|
| **Requests** | Async GET / POST, or full control via a `RequestParams` options struct (method, headers, body, Sec-Fetch, redirects, deadline) | `client_get`, `client_post`, `client_request` |
| **Transports** | HTTP/1.1, HTTP/2, HTTP/3 — pin one, or run H2 with automatic H2→H3 upgrade | `client_init`, `client_init_dual`, `client_set_http_version` |
| **TLS behaviors** | Real ECH (encrypted SNI), TLS 1.3 resumption, 0-RTT early data | `client_set_ech_enabled`, `client_set_resumption_enabled`, `client_set_early_data_enabled` |
| **Sessions** | Lightweight per-task identity — cookie jar + redirect budget over one shared transport | `session_init`, `session_get` |
| **Proxies** | HTTP / HTTPS / SOCKS5 (incl. HTTP/3 over SOCKS5), runtime switching, custom CA for MITM | `client_set_proxy`, `client_add_ca_file` |
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
client_init(&c, &loop, profile_chrome149(), /*verify=*/1);
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

A fully static Windows x86_64 build cross-compiles from Linux. Install the
toolchain (`apt-get install mingw-w64 ninja-build`), then point CMake at the
bundled toolchain file:

```sh
cmake -B build-mingw -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DHOLYTLS_BUILD_TESTS=OFF -DHOLYTLS_BUILD_EXAMPLES=ON
ninja -C build-mingw          # -> build-mingw/*.exe + libholytls.a
```

zlib/brotli/zstd are built from source for the target (`HOLYTLS_FETCH_CODECS`, on
by default for Windows), and libstdc++/winpthread are linked statically — so the
`.exe`s depend only on core Windows DLLs (no MinGW/codec runtime to ship).

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

```sh
cmake -B build-capi -G Ninja -DHOLYTLS_BUILD_CAPI=ON \
    -DHOLYTLS_BUILD_TESTS=OFF -DHOLYTLS_BUILD_EXAMPLES=OFF
cmake --build build-capi --target holytls_capi
pip install ./bindings/python
```

See [`bindings/python/README.md`](bindings/python/README.md) for the full API
(Client, Session, concurrent batches, proxies, ECH/resumption, the response model).

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
