# Third-party libraries

holytls is a thin C layer over some excellent open-source work. The networking and
TLS libraries are built from source (pinned versions) at configure time; the
compression codecs are linked from the system if present; `stb_sprintf` is vendored
in-tree (`src/vendor/`). Thanks to all their authors.

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
