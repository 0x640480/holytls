// Connection — an async TCP+TLS connection on the libuv loop. It resolves a
// host, connects, drives the BoringSSL handshake through the memory-BIO SslPump,
// and reports the negotiated ALPN. The established plaintext stream
// (conn_read_plaintext / conn_send_plaintext) is the seam the HTTP/2 layer hooks
// onto.
//
// The caller owns the Connection storage (typically arena- or stack-allocated);
// conn_init / conn_close bracket its lifetime. Async results arrive through the
// callback pairs (function pointer + void* user), the C form of the old
// std::function seams.
#ifndef HOLYTLS_CONNECTION_H
#define HOLYTLS_CONNECTION_H

#include <uv.h>

#include "base/base.h"
#include "base/ring_alloc.h"
#include "base/string8.h"
#include "net/loop.h"
#include "net/proxy.h"
#include "profile/profile.h"
#include "tls/ssl_conn.h"

typedef struct DnsCache DnsCache;  // net/dns_cache.h (borrowed pointer below)

// ok=false carries a human-readable reason in `err`.
typedef void (*ConnReadyFn)(void *user, B32 ok, const char *err);
// Decrypted application bytes are available (post-handshake): drain with
// conn_read_plaintext.
typedef void (*ConnReadableFn)(void *user);
// The connection closed or errored after being established.
typedef void (*ConnClosedFn)(void *user, const char *err);
// The underlying handle is fully closed — the safe point to free the owner.
typedef void (*ConnFullyClosedFn)(void *user);
// The 0-RTT window is open (ClientHello sent, handshake not yet complete): the
// caller may submit + send its request now, which goes out as early data. Fires
// at most once, before on_ready, and only on a connection with early data enabled.
typedef void (*ConnEarlyReadyFn)(void *user);

typedef enum ConnState {
  ConnState_Idle,
  ConnState_Resolving,
  ConnState_Connecting,
  ConnState_ProxyTls,        // outer TLS handshake to an HTTPS proxy
  ConnState_ProxyNegotiate,  // CONNECT / SOCKS5 tunnel negotiation
  ConnState_Handshaking,
  ConnState_EarlyData,  // 0-RTT window: early-data writes permitted
  ConnState_Established,
  ConnState_Closing,
  ConnState_Failed,
} ConnState;

typedef struct Connection Connection;
struct Connection {
  EventLoop *loop;
  SSL_CTX *ctx;
  const TlsProfile *profile;
  SslPump pump;

  char host[256];  // stripped (no brackets), NUL-terminated; SNI + resolve node
  U16 port;
  ConnState state;

  uv_getaddrinfo_t resolver;
  uv_tcp_t tcp;
  uv_connect_t connect_req;
  B32 tcp_inited;
  B32 ready_fired;

  const U8 *ech_config;  // serialized ECHConfigList (0 => ECH-GREASE), borrowed
  U64 ech_config_len;

  SSL_SESSION *resume_session;  // cached ticket to offer (0 => fresh handshake)
  void *resume_ctx;             // per-conn ctx for the new-session callback

  B32 want_early_data;  // attempt 0-RTT (only if the offered session is capable)
  B32 early_fired;      // on_early_ready has fired (fires once)
  B32 early_rejected;   // the server rejected our early data (retry fresh)

  // Timing (uv_hrtime ns), stamped once across the connect lifecycle; read via
  // conn_timing_ms. Phases: dns = resolved-start, tcp = connected-resolved,
  // tls = established-connected.
  U64 t_connect_start_ns, t_resolved_ns, t_connected_ns, t_established_ns;

  DnsCache *dns_cache;  // borrowed per-Client DNS cache (0 = none); set pre-connect
  B32 dns_was_cached;   // this connect used a cached address (evict it on failure)

  // Proxy tunnel (proxy.type == ProxyType_None => direct). When set, conn_connect
  // resolves+connects the PROXY; after the negotiation the inner (target) TLS
  // handshake runs over the tunnel — the target ClientHello is byte-for-byte
  // unchanged. The outer pump wraps the target stream only for an HTTPS proxy.
  ProxyConfig proxy;
  SSL_CTX *proxy_ctx;               // outer-TLS context (HTTPS proxy; borrowed)
  const TlsProfile *proxy_profile;  // outer-TLS profile (http/1.1 ALPN; borrowed)
  SslPump outer;                    // outer TLS to the proxy (HTTPS proxy)
  B32 outer_active;                 // wrap inner I/O through the outer pump
  char resolve_host[256];           // host actually resolved+connected (proxy or target)
  int proxy_phase;                  // ProxyPhase (connection.c): negotiation step
  U8 nbuf[2048];                    // negotiation-reply accumulator
  U64 nlen;

  // Plaintext that SSL_write could not take (the 0-RTT early-data limit was hit):
  // queued here and flushed as 1-RTT once the handshake completes. malloc'd.
  U8 *pending;
  U64 pending_len, pending_cap;

  // Egress write ring (base/ring_alloc.h): in-flight socket writes (the WriteReq
  // + its payload) are ring blocks instead of per-write mallocs, and the TLS
  // flush path BIO-reads ciphertext straight into the in-flight buffer. Sound
  // because libuv completes a stream's writes strictly in submission order ==
  // the ring's FIFO-release contract (producer and consumer are both the loop
  // thread). One aligned_alloc holds the control block + buffer; conn_cleanup
  // frees it. 0 (alloc failure) => per-write malloc fallback, same behavior.
  ra_ring *egress;

  ConnReadyFn on_ready;
  void *ready_user;
  ConnEarlyReadyFn on_early_ready;
  void *early_ready_user;
  ConnReadableFn on_readable;
  void *readable_user;
  ConnClosedFn on_closed;
  void *closed_user;
  ConnFullyClosedFn on_fully_closed;
  void *fully_closed_user;
};

// Offer real ECH on this connection with `config` (a serialized ECHConfigList,
// borrowed — must outlive conn_connect). Set before conn_connect; 0 => GREASE.
internal inline void conn_set_ech(Connection *c, const U8 *config, U64 len) {
  c->ech_config = config;
  c->ech_config_len = len;
}

// Borrow a DNS cache for this connection (set before conn_connect; 0 = none). On
// connect, a live cache hit skips uv_getaddrinfo; a miss caches the resolution.
internal inline void conn_set_dns_cache(Connection *c, DnsCache *dc) {
  c->dns_cache = dc;
}

// Offer 1-RTT TLS resumption on this connection. `session` (may be 0) is a cached
// SSL_SESSION the caller retains ownership of; `resume_ctx` (may be 0) is an
// opaque per-connection pointer handed to the new-session callback so a freshly
// issued ticket can be cached against this origin. Set before conn_connect.
internal inline void conn_set_resume(Connection *c, SSL_SESSION *session,
                                     void *resume_ctx) {
  // Own a ref: the cache entry this borrows from can be replaced/evicted (LRU)
  // before the handshake calls SSL_set_session. conn_cleanup drops it.
  c->resume_session = session;
  if (session) SSL_SESSION_up_ref(session);
  c->resume_ctx = resume_ctx;
}

// Attempt TLS 1.3 0-RTT on this connection (set before conn_connect). Only takes
// effect when a resume session is also offered and it is 0-RTT-capable; then the
// on_early_ready callback fires so the caller writes its request as early data.
internal inline void conn_set_early_data(Connection *c, B32 on) {
  c->want_early_data = on;
}

// Route this connection through a forward proxy (set before conn_connect; a
// ProxyType_None config is a no-op). `proxy_ctx`/`proxy_profile` are only used by
// an HTTPS (TLS-to-proxy) proxy for the outer handshake — pass 0 otherwise. The
// target's TLS handshake (SNI, profile, fingerprint) is unaffected.
internal inline void conn_set_proxy(Connection *c, const ProxyConfig *p,
                                    SSL_CTX *proxy_ctx,
                                    const TlsProfile *proxy_profile) {
  c->proxy = *p;
  // Own a ref on the HTTPS-proxy SSL_CTX so the Client can free/rebuild it (a
  // runtime proxy switch) while this connection is still using it; conn_cleanup
  // drops the ref. (proxy_profile points at the Client's proxy_tls, which is
  // proxy-independent, so it needs no such protection.)
  c->proxy_ctx = proxy_ctx;
  if (proxy_ctx) SSL_CTX_up_ref(proxy_ctx);
  c->proxy_profile = proxy_profile;
}

void conn_init(Connection *c, EventLoop *loop, SSL_CTX *ctx,
               const TlsProfile *profile);
// Free the embedded SSL/BIO state. Call after the handle is fully closed (i.e.
// after the loop has drained the close); does not touch the SSL_CTX (caller's).
void conn_cleanup(Connection *c);
void conn_connect(Connection *c, const char *host, U16 port,
                  ConnReadyFn on_ready, void *user);

internal inline void conn_on_readable(Connection *c, ConnReadableFn fn,
                                      void *user) {
  c->on_readable = fn;
  c->readable_user = user;
}
internal inline void conn_on_closed(Connection *c, ConnClosedFn fn, void *user) {
  c->on_closed = fn;
  c->closed_user = user;
}
internal inline void conn_on_fully_closed(Connection *c, ConnFullyClosedFn fn,
                                          void *user) {
  c->on_fully_closed = fn;
  c->fully_closed_user = user;
}
internal inline void conn_on_early_ready(Connection *c, ConnEarlyReadyFn fn,
                                         void *user) {
  c->on_early_ready = fn;
  c->early_ready_user = user;
}

// Queue plaintext for encryption + send. Returns false on hard failure.
B32 conn_send_plaintext(Connection *c, const U8 *data, U64 len);
// Drain decrypted application data into buf; same convention as
// ssl_pump_read_plaintext (>=0 bytes, -1 want-io, -2 closed/error).
internal inline int conn_read_plaintext(Connection *c, U8 *buf, U64 cap) {
  return ssl_pump_read_plaintext(&c->pump, buf, cap);
}
// The negotiated ALPN as a view into the live SSL (valid while established).
String8 conn_alpn(Connection *c);
// True if this connection's handshake resumed a cached TLS session.
internal inline B32 conn_resumed(Connection *c) {
  return ssl_pump_resumed(&c->pump);
}
// True if the completed handshake confirmed the server accepted 0-RTT early data.
internal inline B32 conn_early_data_accepted(Connection *c) {
  return ssl_pump_early_accepted(&c->pump);
}
// True if the server rejected our 0-RTT early data (the request must be retried
// on a fresh, non-0-RTT connection).
internal inline B32 conn_early_rejected(Connection *c) {
  return c->early_rejected;
}

// Connection-setup phase durations in ms, as seen by a request that started at
// `req_start_ns`. Writes dns/tcp/tls. Returns all-zero when the connection was
// established before the request started (pooled reuse) or never established.
void conn_timing_ms(const Connection *c, U64 req_start_ns, U64 *dns_ms,
                    U64 *tcp_ms, U64 *tls_ms);

void conn_close(Connection *c);

#endif  // HOLYTLS_CONNECTION_H
