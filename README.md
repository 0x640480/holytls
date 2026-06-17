# holytls

**A C TLS-impersonation HTTP client that reproduces a real browser's fingerprint
across TLS, HTTP/2, and HTTP/3.**

Most impersonation clients stop at the TLS ClientHello (JA3/JA4). holytls matches a
real browser on the wire across **all three transports** — the JA4 ClientHello, the
HTTP/2 SETTINGS/WINDOW_UPDATE/priority shape (Akamai), and the HTTP/3 + QUIC
fingerprint (h3 settings hash, QUIC-JA4). All four are live-verified against
`tls.peet.ws`, `browserleaks.com`, and a fingerprint-preserving MITM proxy:

| Dimension | Chrome 149 (reproduced exactly) |
|---|---|
| TLS — **JA4** | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |
| HTTP/2 — **Akamai** | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| HTTP/3 — **QUIC-JA4** | `q13d0311h3_55b375c5d22e_653d80c3fe9d` |
| HTTP/3 — **h3 settings hash** | `ba909fc3dc419ea5c5b26c6323ac1879` |

Byte-exact for **Firefox 151** too — the first non-Chrome family. Profiles are
selectable by name; adding one is a data file + a registry row.

## Features

- **Byte-exact across TLS + HTTP/2 + HTTP/3** — JA4, the H2 Akamai shape, *and* the
  H3/QUIC fingerprint, not just JA3/JA4.
- **Multiple browsers, registry-driven** — Chrome 148/149 and Firefox 151 today.
- **Chrome's HTTP/3 behavior** — H2 first, then upgrade to H3 on `alt-svc: h3`.
- **Real ECH** — fetches the origin's `ECHConfigList` over DoH and encrypts the inner
  ClientHello (real SNI hidden), with ECH-GREASE fallback.
- **TLS 1.3 resumption + 0-RTT early data** — on both TCP/H2 and QUIC/H3.
- **WebSocket** — RFC 6455 over the fingerprinted connection (H1 Upgrade or H2
  Extended CONNECT), permessage-deflate.
- **Proxies & egress** — HTTP / HTTPS / SOCKS5 (incl. H3 over SOCKS5), a rotation
  pool, runtime switching, and source-IP binding.
- **Sessions** — cookie jar + browser-faithful redirects over one shared transport.
- **Streaming bodies** + transparent gzip / deflate / br / zstd decompression.
- **mTLS** — client-certificate authentication.

Full knob list in [`src/core/client.h`](src/core/client.h).

## Quick start

Pull it into your CMake project — the supported integration (it builds its own
pinned BoringSSL / libuv / nghttp2 / ngtcp2 / nghttp3 from source):

```cmake
include(FetchContent)
FetchContent_Declare(holytls
  GIT_REPOSITORY https://github.com/0x640480/holytls.git
  GIT_TAG main)
FetchContent_MakeAvailable(holytls)

add_executable(myapp main.c)
target_link_libraries(myapp PRIVATE holytls)
```

A request — async, the result arrives in a callback once you run the loop:

```c
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

static void handle_response(void *user, const Response *resp) {
  (void)user;
  if (!resp->ok) { fprintf(stderr, "error: %s\n", resp->error); return; }
  printf("HTTP %d  (%llu bytes)\n", resp->status,
         (unsigned long long)resp->body_len);
}

int main(void) {
  EventLoop loop; loop_init(&loop);
  Client c;
  // Chrome 149 over H2 (NULL h3 + HttpVersion_H2 = TCP only); verify=1.
  client_init(&c, &loop, profile_chrome149(), NULL, HttpVersion_H2, /*verify=*/1);
  client_get(&c, str8_lit("https://tls.peet.ws/api/all"), handle_response, 0);
  loop_run(&loop);
  client_cleanup(&c); loop_shutdown(&loop);
}
```

…or blocking — the `*_sync` variants run the loop for you and return a `Response`
owned by an arena (valid until you release it):

```c
Arena *arena = arena_alloc();
Response *r = client_get_sync(&c, str8_lit("https://tls.peet.ws/api/all"), arena);
if (r->ok) printf("HTTP %d\n", r->status);
arena_release(arena);
```

## Verifying the fingerprint

Route holytls through [powhttp](https://powhttp.com/) (or any MITM proxy) and read
the exact bytes it sends — verification stays **on**, you just trust the proxy root:

```c
client_add_ca_file(&c, "powhttp Root Certificate.pem");     // trust the MITM root
client_set_proxy(&c, str8_lit("http://127.0.0.1:8888"), 0); // route through it
```

The captured ClientHello + H2 frames hash to exactly the Chrome 149 fingerprints
above.

## Building

CMake ≥ 3.20, a C11 compiler, and Go + perl (to build the bundled
lexiforest/boringssl curl-impersonate fork). All deps are fetched and built from
source at configure time.

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

Sanitizers: `-DHOLYTLS_ASAN=ON`. As a subproject, tests/examples are off by default
(`HOLYTLS_BUILD_TESTS` / `HOLYTLS_BUILD_EXAMPLES`). A static Windows x86_64 build
cross-compiles from Linux with `-DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake`.

## Examples

[`examples/`](examples/): `quickstart.c`, `fingerprint.c`, `post_json.c`,
`session.c` (cookies + redirects + pooling), and `stealth.c` (full Chrome fidelity
— H2→H3, ECH, resumption + 0-RTT).

## Python binding

A `requests`-style API ([cffi](https://cffi.readthedocs.io), API mode) over a
self-contained native library lives in [`bindings/python/`](bindings/python/):

```python
import holytls

with holytls.Client(http_version="auto") as client:  # H2, then H3 via alt-svc
    r = client.get("https://tls.peet.ws/api/all")
    print(r.status_code, r.alpn, r.json()["tls"]["ja4"])
```

Full API (`Client` / `AsyncClient`, `Session`, `WebSocket`, concurrent batches,
multipart, streaming, proxies, mTLS, ECH): [`bindings/python/README.md`](bindings/python/README.md).

## Credits

Built on the **lexiforest/boringssl** curl-impersonate fork (the extra TLS
extensions that make a byte-exact ClientHello possible), FoxIO's
**[JA4+](https://github.com/FoxIO-LLC/ja4)** fingerprint suite, and live-verified
against **[tls.peet.ws](https://tls.peet.ws)** / **[browserleaks.com](https://browserleaks.com)**.

Full dependency + license list: [THIRD_PARTY.md](THIRD_PARTY.md).
