// QuicConnection — an async QUIC client connection on the libuv loop (UDP +
// ngtcp2 + the BoringSSL QUIC TLS via ngtcp2_crypto_boringssl). Mirrors
// Connection's callback surface so the HTTP/3 layer reuses the same patterns.
// The HTTP/3 framing/QPACK lives one layer up (H3Session); this owns the
// transport: handshake, packets, timers, streams.
//
// The caller owns the QuicConnection storage; quic_conn_init /
// quic_conn_cleanup bracket it. `ctx` must already be QUIC-configured
// (build_ctx + ngtcp2_crypto_boringssl_configure_client_context, done in
// quic_conn_init).
#ifndef HOLYTLS_QUIC_CONNECTION_H
#define HOLYTLS_QUIC_CONNECTION_H

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/ssl.h>
#include <uv.h>

#include "base/base.h"
#include "base/string8.h"
#include "h3/h3_control.h"  // U8Buf (per-stream send buffers)
#include "net/loop.h"
#include "net/proxy.h"
#include "profile/profile.h"

typedef struct DnsCache DnsCache;  // net/dns_cache.h (borrowed pointer below)

typedef void (*QuicReadyFn)(void *user, B32 ok, const char *err);
typedef void (*QuicStreamDataFn)(void *user, S64 stream_id, const U8 *data,
                                 U64 len, B32 fin);
typedef void (*QuicStreamCloseFn)(void *user, S64 stream_id);
typedef void (*QuicClosedFn)(void *user, const char *err);
typedef void (*QuicFullyClosedFn)(void *user);
// Fired after a received packet has been fully processed (read_pkt + egress
// flush). The safe point to submit new streams from a response callback without
// re-entering ngtcp2 (see `in_recv`). The pool uses it to flush deferred
// submits.
typedef void (*QuicRecvDoneFn)(void *user);
// The 0-RTT window is open (ngtcp2 conn created with restored transport
// params): the caller may open early streams + submit its request as 0-RTT
// data. Fires once, before on_ready, only when early data is armed.
typedef void (*QuicEarlyReadyFn)(void *user);

typedef enum QuicState {
  QuicState_Idle,
  QuicState_Resolving,
  QuicState_Handshaking,
  QuicState_EarlyData,  // 0-RTT window: early streams may be opened/sent
  QuicState_Established,
  QuicState_Closing,
  QuicState_Failed,
} QuicState;

// HTTP/3 opens only a handful of streams per connection (request bidi +
// control/QPACK uni), so an inline array with a linear scan beats a node map —
// especially since the egress loop scans it once per QUIC packet built.
typedef struct QuicSendBuf QuicSendBuf;
struct QuicSendBuf {
  S64 id;
  U8Buf data;
  U64 off;
  B32 fin;
  B32 fin_sent;
  B32 blocked;  // flow-control-blocked this egress pass; retried on the next
                // flush
};

typedef struct QuicConnection QuicConnection;
struct QuicConnection {
  EventLoop *loop;
  SSL_CTX *ctx;
  const TlsProfile *tls;
  const Http3Profile *h3;
  Arena *arena;  // owns the per-stream send buffers
  ngtcp2_crypto_conn_ref conn_ref;

  char host[256];  // stripped (no brackets), NUL-terminated; SNI + resolve node
  U16 port;
  QuicState state;

  uv_getaddrinfo_t resolver;
  uv_udp_t udp;
  uv_timer_t timer;
  struct sockaddr_storage bind_addr;  // source address to bind before connect
  B32 has_bind_addr;                  // (egress IP selection); 0 = OS default
  B32 udp_inited;
  B32 timer_inited;
  B32 ready_fired;
  B32 in_recv;  // inside ngtcp2_conn_read_pkt: defer stream submits (no
                // re-entry)
  int handles_closing;

  SSL *ssl;
  ngtcp2_conn *conn;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  struct sockaddr_storage remote_addr;
  socklen_t remote_addrlen;

  QuicSendBuf send_bufs[32];  // 3 persistent uni + concurrent request streams
  int send_count;

  QuicReadyFn on_ready;
  void *ready_user;
  QuicStreamDataFn on_stream_data;
  void *stream_data_user;
  QuicStreamCloseFn on_stream_close;
  void *stream_close_user;
  QuicClosedFn on_closed;
  void *closed_user;
  QuicFullyClosedFn on_fully_closed;
  void *fully_closed_user;
  QuicRecvDoneFn on_recv_done;
  void *recv_done_user;

  const U8 *ech_config;  // serialized ECHConfigList (0 => ECH-GREASE), borrowed
  U64 ech_config_len;

  SSL_SESSION *resume_session;  // cached ticket to offer (0 => fresh handshake)
  void *resume_ctx;             // per-conn ctx for the new-session callback

  B32 want_early_data;  // attempt 0-RTT (armed only if session-capable + TP
                        // set)
  B32 early_fired;      // on_early_ready has fired (fires once)
  B32 early_rejected;   // the server rejected our 0-RTT (retry on a fresh conn)
  U8 early_tp[256];     // cached ngtcp2 0-RTT transport params to restore
  U64 early_tp_len;
  QuicEarlyReadyFn on_early_ready;
  void *early_ready_user;

  // Timing (uv_hrtime ns); read via quic_conn_timing_ms. QUIC has no separate
  // TCP phase: tls spans resolved->established (UDP setup + the QUIC
  // handshake).
  U64 t_connect_start_ns, t_resolved_ns, t_established_ns;

  DnsCache
      *dns_cache;  // borrowed per-Client DNS cache (0 = none); set pre-connect
  B32 dns_was_cached;  // this connect used a cached address

  // SOCKS5 UDP-ASSOCIATE proxy (proxy.type == ProxyType_None => direct). The
  // TCP `ctrl` channel negotiates the association and stays open for its
  // lifetime; UDP datagrams go to `relay_addr` (also c->remote_addr / the
  // ngtcp2 path) wrapped in `udp_hdr` (a SOCKS5 UDP header for `target_addr`).
  // The QUIC Initial is unchanged, so QUIC-JA4 is byte-identical.
  ProxyConfig proxy;
  B32 proxied;
  uv_tcp_t ctrl;  // SOCKS5 control channel
  uv_connect_t ctrl_conn;
  B32 ctrl_inited;
  int proxy_phase;  // ProxyPhase (quic_connection.c): negotiation step
  U8 nbuf[512];     // negotiation-reply accumulator
  U64 nlen;
  struct sockaddr_storage
      proxy_addr;  // resolved proxy (relay base when BND=0.0.0.0)
  socklen_t proxy_addrlen;
  struct sockaddr_storage
      relay_addr;  // UDP relay endpoint from the ASSOCIATE reply
  socklen_t relay_addrlen;
  U8 udp_hdr[262];  // prebuilt SOCKS5 UDP request header (target addr/port)
  U64 udp_hdr_len;
};

// Bind this QUIC connection's UDP socket to source IP `ip` (IPv4/IPv6 literal)
// before connecting — egress-address selection. Returns 1 if parsed, 0 on a bad
// literal. Set before quic_conn_connect. (Not inline: shares the IP parser with
// connection.c, defined later in the unity TU.)
B32 quic_set_local_address(QuicConnection *c, String8 ip);

// Route this QUIC connection through a SOCKS5 UDP-ASSOCIATE proxy (set before
// quic_conn_connect; a ProxyType_None / non-Socks5 config is a no-op). The
// target's QUIC handshake/fingerprint is unaffected.
internal inline void quic_set_proxy(QuicConnection *c, const ProxyConfig *p) {
  if (p && p->type == ProxyType_Socks5) {
    c->proxy = *p;
    c->proxied = 1;
  }
}

// Offer real ECH on this QUIC connection (set before quic_conn_connect; 0 =>
// GREASE).
internal inline void quic_set_ech(QuicConnection *c, const U8 *config,
                                  U64 len) {
  c->ech_config = config;
  c->ech_config_len = len;
}

// Borrow a DNS cache for this connection (set before quic_conn_connect; 0 =
// none).
internal inline void quic_set_dns_cache(QuicConnection *c, DnsCache *dc) {
  c->dns_cache = dc;
}

// Offer 1-RTT TLS resumption on this QUIC connection (set before
// quic_conn_connect). `session` (may be 0) is a cached SSL_SESSION the caller
// retains ownership of; `resume_ctx` (may be 0) routes a freshly issued ticket
// to its origin via the new-session callback. See conn_set_resume.
internal inline void quic_set_resume(QuicConnection *c, SSL_SESSION *session,
                                     void *resume_ctx) {
  // Own a ref: the cache entry this borrows from can be replaced/evicted (LRU)
  // before the handshake calls SSL_set_session. quic_conn_cleanup drops it.
  c->resume_session = session;
  if (session) SSL_SESSION_up_ref(session);
  c->resume_ctx = resume_ctx;
}

// Attempt QUIC 0-RTT on this connection (set before quic_conn_connect). `tp` is
// the prior connection's encoded 0-RTT transport params (paired with the resume
// session); copied. Only takes effect when a resume session is offered and it
// is 0-RTT-capable. Then on_early_ready fires so the caller opens early
// streams.
internal inline void quic_set_early_data(QuicConnection *c, const U8 *tp,
                                         U64 tp_len) {
  c->want_early_data = 1;
  U64 n = tp_len < sizeof c->early_tp ? tp_len : sizeof c->early_tp;
  if (n) MemoryCopy(c->early_tp, tp, n);
  c->early_tp_len = n;
}
internal inline void quic_on_early_ready(QuicConnection *c, QuicEarlyReadyFn fn,
                                         void *user) {
  c->on_early_ready = fn;
  c->early_ready_user = user;
}

// True if this QUIC connection's TLS handshake resumed a cached session.
internal inline B32 quic_conn_resumed(QuicConnection *c) {
  return c->ssl ? (B32)SSL_session_reused(c->ssl) : 0;
}
// True if the completed handshake confirmed the server accepted 0-RTT.
internal inline B32 quic_conn_early_accepted(QuicConnection *c) {
  return c->ssl ? (B32)SSL_early_data_accepted(c->ssl) : 0;
}
// True if the server rejected our 0-RTT (retry on a fresh, non-0-RTT
// connection).
internal inline B32 quic_conn_early_rejected(QuicConnection *c) {
  return c->early_rejected;
}

// Connection-setup phase durations in ms, as seen by a request that started at
// `req_start_ns`. tcp_ms is always 0 (QUIC has no separate TCP); tls_ms covers
// the combined UDP-setup + QUIC handshake. All-zero on reuse / not established.
void quic_conn_timing_ms(const QuicConnection *c, U64 req_start_ns, U64 *dns_ms,
                         U64 *tcp_ms, U64 *tls_ms);
// Encode this connection's 0-RTT transport params (for caching) into `dst`;
// returns bytes written (0 on failure / no conn). Valid after the handshake.
U64 quic_conn_encode_0rtt_tp(QuicConnection *c, U8 *dst, U64 cap);

void quic_conn_init(QuicConnection *c, EventLoop *loop, SSL_CTX *ctx,
                    const TlsProfile *tls, const Http3Profile *h3);
void quic_conn_cleanup(QuicConnection *c);  // frees ssl + ngtcp2_conn + arena
void quic_conn_connect(QuicConnection *c, const char *host, U16 port,
                       QuicReadyFn on_ready, void *user);

internal inline void quic_on_stream_data(QuicConnection *c, QuicStreamDataFn fn,
                                         void *user) {
  c->on_stream_data = fn;
  c->stream_data_user = user;
}
internal inline void quic_on_stream_close(QuicConnection *c,
                                          QuicStreamCloseFn fn, void *user) {
  c->on_stream_close = fn;
  c->stream_close_user = user;
}
internal inline void quic_on_closed(QuicConnection *c, QuicClosedFn fn,
                                    void *user) {
  c->on_closed = fn;
  c->closed_user = user;
}
internal inline void quic_on_fully_closed(QuicConnection *c,
                                          QuicFullyClosedFn fn, void *user) {
  c->on_fully_closed = fn;
  c->fully_closed_user = user;
}
internal inline void quic_on_recv_done(QuicConnection *c, QuicRecvDoneFn fn,
                                       void *user) {
  c->on_recv_done = fn;
  c->recv_done_user = user;
}

// Stream API for the HTTP/3 layer.
int quic_open_uni_stream(QuicConnection *c, S64 *out_id);
int quic_open_bidi_stream(QuicConnection *c, S64 *out_id);
void quic_stream_send(QuicConnection *c, S64 stream_id, const U8 *data, U64 len,
                      B32 fin);
// Abort a request stream (shut down both directions with H3_REQUEST_CANCELLED).
// Used to cancel one multiplexed request (e.g. a timeout) without closing the
// conn.
void quic_reset_stream(QuicConnection *c, S64 stream_id);

String8 quic_conn_alpn(QuicConnection *c);  // view into the live SSL
void quic_conn_close(QuicConnection *c);

#endif  // HOLYTLS_QUIC_CONNECTION_H
