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

It's written in plain C (arena allocation, length-carrying strings, no GC, no OOP),
runs single-threaded on one libuv event loop, and embeds into any CMake project.

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
  concurrent requests; no threads, no goroutines, no GC. Per-request arenas mean
  bulk-freed memory with nothing to leak.
- **Wire-truth verifiable** — route through a MITM proxy (e.g. powhttp/mitmproxy)
  with `client_add_ca_file`, keep verification on, and inspect exactly what you
  send. holytls's fingerprint is unchanged by the proxy.
- **Generated, not hardcoded, Chrome details** — e.g. the `sec-ch-ua` GREASE brand
  list is produced by Chrome's own deterministic per-version algorithm, so a new
  Chrome version is a one-line bump, not a guess.

### vs. bogdanfinn/tls-client and friends

| | **holytls** | typical TLS-impersonation client |
|---|---|---|
| Language | **C** — embeddable static lib, no runtime | Go |
| TLS fingerprint (JA3/JA4) | byte-exact | yes |
| HTTP/2 fingerprint (Akamai) | **byte-exact, live-verified** | usually yes |
| HTTP/3 / QUIC fingerprint | **byte-exact (QUIC-JA4 + h3 hash)** + Chrome's alt-svc upgrade | partial / none |
| Real ECH (encrypted SNI) | **yes** (DNS HTTPS RR + DoH) | no |
| TLS 1.3 0-RTT early data | **yes** (H2 and H3) | no |
| Concurrency | one libuv loop, thousands of conns | goroutines |
| Proxy | HTTP / HTTPS / SOCKS5 **+ QUIC-over-SOCKS5**, runtime switching, custom CA | HTTP / SOCKS |
| Header control | full override + explicit order | order key |

holytls trades **profile breadth for fidelity depth**: it impersonates Chrome
(149/148) across every transport with verified precision, rather than offering many
shallower TLS-only profiles. New Chrome versions are data entries; other browsers
are a profile away.

---

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

static void on_response(void *user, const Response *resp) {
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
  client_get(&c, str8_lit("https://tls.peet.ws/api/all"), on_response, 0);
  loop_run(&loop);                                             // drives the request
  client_cleanup(&c); loop_shutdown(&loop);
}
```

---

## Maximum-fidelity example

Everything a real Chrome does, turned on at once — dual transport (H2→H3 upgrade),
cert verification, real ECH, resumption + 0-RTT, a cookie jar, browser-faithful
redirect following, and Chrome's complete navigation header set
(`user-agent`, `sec-ch-ua`, `sec-fetch-*`, `accept`, …). See
[`examples/google_fidelity.c`](examples/google_fidelity.c):

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

session_get(&session, &client, str8_lit("https://www.google.com/"), on_response, 0);
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

## Use cases

- **Web scraping / automation** against anti-bot stacks that fingerprint TLS, H2,
  and H3 — where a JA3/JA4-only match isn't enough.
- **High-concurrency crawling** — one loop, thousands of in-flight requests, minimal
  memory (per-request arenas), no GC pauses.
- **Embedding browser-grade HTTP** in a C/C++/native app or another language via FFI
  — a static lib, not a service.
- **Fingerprint research / QA** — verify your client (or your server's detection)
  against a byte-exact Chrome baseline; route through powhttp to read the wire.

---

## Feature tour

All of these are `Client` setters (off by default unless noted) — see
[`src/core/client.h`](src/core/client.h):

- **Transports** — `client_init` (H2/TCP) or `client_init_dual` (+ HTTP/3);
  `client_set_http_version` to pin H1/H2/H3.
- **Browser behaviors** — `client_set_ech_enabled`, `client_set_resumption_enabled`,
  `client_set_early_data_enabled`.
- **Sessions** — `session_init` gives a lightweight per-task identity (cookie jar +
  redirect budget); thousands of sessions over one shared transport `Client`.
- **Proxies** — `client_set_proxy` for `http://`, `https://`, `socks5://`
  (with `user:pass@`); SOCKS5 also carries HTTP/3 (UDP ASSOCIATE). Switch at runtime;
  the target fingerprint is unchanged. `client_add_ca_file` trusts a MITM root.
- **Headers** — full Chrome set by default; `client_override_default_headers` for
  caller-controlled headers and `client_set_header_order` /
  `client_set_header_order_str` for explicit wire order (the
  `req.Header` + `HeaderOrderKey` equivalent). `header_lit("name","value")` helper.
- **Pooling** — `client_set_max_conns_per_origin` (opt-in H2 + H3 keep-alive).
- **Reliability** — `client_set_timeout_ms` (whole-operation deadline),
  `client_set_max_redirects` (browser-faithful method transitions),
  `client_set_dns_cache_ttl_ms`.
- **Inspection / security** — request/response hooks (`client_set_pre_hook` /
  `client_set_post_hook`), `client_pin_certificate`, `client_set_key_log_file`
  (`SSLKEYLOGFILE` for Wireshark).
- **Bodies** — transparent decompression (gzip / deflate / br / zstd);
  `response_text` / `response_get_header` / `response_json` accessors.

---

## Verifying the fingerprint

Route holytls through [powhttp](https://github.com/) (or any MITM proxy) and inspect
the exact bytes it sends — verification stays **on**, you just trust the proxy root:

```c
client_init(&c, &loop, profile_chrome149(), /*verify=*/1);
client_add_ca_file(&c, "powhttp Root Certificate.pem");        // trust the MITM root
client_set_proxy(&c, str8_lit("http://127.0.0.1:8888"), 0);    // route through it
```

powhttp then shows holytls's captured ClientHello + H2 frames hashing to exactly the
Chrome 149 fingerprints above. See [`examples/powhttp_proxy.c`](examples/powhttp_proxy.c).

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

## Examples

- [`examples/google_fidelity.c`](examples/google_fidelity.c) — maximum-fidelity Chrome
  (dual transport, ECH, resumption, 0-RTT, cookies).
- [`examples/peet_compare.c`](examples/peet_compare.c) — caller-controlled headers +
  explicit order (the bogdanfinn `req.Header` + `HeaderOrderKey` equivalent).
- [`examples/powhttp_proxy.c`](examples/powhttp_proxy.c) — route through a MITM proxy
  for wire-truth inspection.

## Code style

holytls is plain C — arena allocation, length-carrying `String8`, plain structs +
free functions, and a callback-driven libuv event loop. When extending it, match the
structure, naming, and comment density of the surrounding subsystem.
