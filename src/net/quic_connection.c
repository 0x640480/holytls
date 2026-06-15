#include "net/quic_connection.h"

#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/rand.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/platform_net.h"  // htons, sockaddr_in/in6 (winsock on Windows)
#include "net/dns_cache.h"
#include "net/proxy.h"
#include "tls/ssl_ctx.h"

internal void quic_log(void *user, const char *fmt, ...) {
  (void)user;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
}

internal U64 quic_now_ns(void) { return uv_hrtime(); }

internal void quic_fail(QuicConnection *c, const char *reason);
internal void quic_deliver_ready(QuicConnection *c, B32 ok, const char *err);
internal void quic_flush_egress(QuicConnection *c);
internal void quic_arm_timer(QuicConnection *c);
internal B32 quic_init_ngtcp2(QuicConnection *c);
internal void quic_begin_udp(QuicConnection *c);
internal void quic_on_resolved(uv_getaddrinfo_t *req, int status,
                               struct addrinfo *res);
internal void quic_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                           const struct sockaddr *addr, unsigned flags);
internal void quic_timer_cb(uv_timer_t *t);

// SOCKS5 UDP-ASSOCIATE control-channel negotiation (proxied path).
internal void quic_proxy_connect_ctrl(QuicConnection *c);
internal void quic_on_proxy_resolved(uv_getaddrinfo_t *req, int status,
                                     struct addrinfo *res);
internal void quic_on_ctrl_connected(uv_connect_t *req, int status);
internal void quic_ctrl_read_cb(uv_stream_t *s, ssize_t nread,
                                const uv_buf_t *buf);
internal void quic_proxy_advance(QuicConnection *c);
internal void quic_proxy_resolve_target(QuicConnection *c);
internal void quic_on_target_resolved(uv_getaddrinfo_t *req, int status,
                                      struct addrinfo *res);
internal void quic_proxy_finish(QuicConnection *c);

// Negotiation step on the SOCKS5 control channel (QuicConnection.proxy_phase).
enum { QPhase_Greeting, QPhase_Auth, QPhase_Associate, QPhase_Done };

internal ngtcp2_conn *quic_get_conn(ngtcp2_crypto_conn_ref *ref) {
  return ((QuicConnection *)ref->user_data)->conn;
}

//- init / lifetime

void quic_conn_init(QuicConnection *c, EventLoop *loop, SSL_CTX *ctx,
                    const TlsProfile *tls, const Http3Profile *h3) {
  MemoryZeroStruct(c);
  c->loop = loop;
  c->ctx = ctx;
  c->tls = tls;
  c->h3 = h3;
  c->arena = arena_alloc();
  c->conn_ref.get_conn = quic_get_conn;
  c->conn_ref.user_data = c;
}

void quic_conn_cleanup(QuicConnection *c) {
  if (c->resume_session) {  // drop the ref taken in quic_set_resume
    SSL_SESSION_free(c->resume_session);
    c->resume_session = 0;
  }
  if (c->conn) {
    ngtcp2_conn_del(c->conn);
    c->conn = 0;
  }
  if (c->ssl) {
    SSL_free(c->ssl);
    c->ssl = 0;
  }
  if (c->arena) {
    arena_release(c->arena);
    c->arena = 0;
  }
}

B32 quic_set_local_address(QuicConnection *c, String8 ip) {
  if (!ip_literal_to_sockaddr(ip, &c->bind_addr)) return 0;  // shared parser
  c->has_bind_addr = 1;
  return 1;
}

void quic_conn_connect(QuicConnection *c, const char *host, U16 port,
                       QuicReadyFn on_ready, void *user) {
  c->on_ready = on_ready;
  c->ready_user = user;
  c->port = port;
  strip_host(c->host, sizeof c->host, host);  // shared with connection.c
  c->t_connect_start_ns = uv_hrtime();        // connect start (DNS begins next)

  // SOCKS5 UDP-ASSOCIATE proxy: negotiate the tunnel over a TCP control channel
  // first; the QUIC handshake (target SNI = c->host) then runs over the relay.
  if (c->proxied) {
    quic_proxy_connect_ctrl(c);
    return;
  }

  // DNS cache hit -> skip uv_getaddrinfo, go straight to UDP setup.
  if (c->dns_cache) {
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    if (dns_cache_get(c->dns_cache, c->host, uv_now(loop_uv(c->loop)), &ss,
                      &sl) &&
        // Skip a cached address that can't match a bound source IP (see
        // connection.c) — re-resolve with the family hint below instead.
        (!c->has_bind_addr || ss.ss_family == c->bind_addr.ss_family)) {
      dns_sockaddr_set_port(&ss, c->port);
      MemoryCopy(&c->remote_addr, &ss, sl);
      c->remote_addrlen = sl;
      c->t_resolved_ns = uv_hrtime();  // ~0ms DNS on a cache hit
      c->dns_was_cached = 1;
      quic_begin_udp(c);
      return;
    }
  }

  c->state = QuicState_Resolving;
  c->resolver.data = c;
  struct addrinfo hints;
  MemoryZeroStruct(&hints);
  // Constrain resolution to the bound source family (connect-compatible).
  hints.ai_family = c->has_bind_addr ? c->bind_addr.ss_family : AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  char portstr[8];
  snprintf(portstr, sizeof portstr, "%u", port);
  int rc = uv_getaddrinfo(loop_uv(c->loop), &c->resolver, quic_on_resolved,
                          c->host, portstr, &hints);
  if (rc) quic_fail(c, uv_strerror(rc));
}

// Set up the UDP socket + ngtcp2 against c->remote_addr (already populated,
// from a fresh resolution or the DNS cache), then open the handshake / 0-RTT
// window.
internal void quic_begin_udp(QuicConnection *c) {
  uv_udp_init(loop_uv(c->loop), &c->udp);
  c->udp_inited = 1;
  c->udp.data = c;
  if (c->has_bind_addr &&  // bind the chosen source address (egress IP)
      uv_udp_bind(&c->udp, (const struct sockaddr *)&c->bind_addr, 0) != 0) {
    quic_fail(c, "uv_udp_bind failed");
    return;
  }
  if (uv_udp_connect(&c->udp, (struct sockaddr *)&c->remote_addr) != 0) {
    quic_fail(c, "uv_udp_connect failed");
    return;
  }
  int namelen = sizeof c->local_addr;
  uv_udp_getsockname(&c->udp, (struct sockaddr *)&c->local_addr, &namelen);
  c->local_addrlen = (socklen_t)namelen;

  if (!quic_init_ngtcp2(c)) return;

  uv_timer_init(loop_uv(c->loop), &c->timer);
  c->timer_inited = 1;
  c->timer.data = c;
  uv_udp_recv_start(&c->udp, net_alloc_cb, quic_recv_cb);
  // If 0-RTT is armed (quic_init_ngtcp2 enabled early data + restored the TP),
  // open the early window and let the caller submit its request as 0-RTT before
  // the Initial is flushed; the request bytes coalesce into the first flight.
  if (c->want_early_data && c->on_early_ready) {
    c->state = QuicState_EarlyData;
    c->early_fired = 1;
    c->on_early_ready(c->early_ready_user);
  } else {
    c->state = QuicState_Handshaking;
  }
  quic_flush_egress(c);  // send the Initial (ClientHello) + any 0-RTT data
}

internal void quic_on_resolved(uv_getaddrinfo_t *req, int status,
                               struct addrinfo *res) {
  QuicConnection *c = (QuicConnection *)req->data;
  if (status < 0) {
    quic_fail(c, uv_strerror(status));
    if (res) uv_freeaddrinfo(res);
    return;
  }
  c->t_resolved_ns = uv_hrtime();  // DNS done
  MemoryCopy(&c->remote_addr, res->ai_addr, res->ai_addrlen);
  c->remote_addrlen = res->ai_addrlen;
  if (c->dns_cache)  // remember this resolution for the next connection to the
                     // host
    dns_cache_put(c->dns_cache, c->host, res->ai_addr, res->ai_addrlen,
                  uv_now(loop_uv(c->loop)));
  uv_freeaddrinfo(res);
  quic_begin_udp(c);
}

//- SOCKS5 UDP-ASSOCIATE control channel
//
// A TCP channel negotiates the association (greeting -> [user/pass] -> UDP
// ASSOCIATE) and stays open for its lifetime. The reply's BND endpoint is the
// UDP relay; QUIC datagrams ride to it wrapped in a SOCKS5 UDP header (built
// from the target's resolved address). The QUIC Initial is unmodified ->
// QUIC-JA4 intact.

typedef struct QWrite QWrite;
struct QWrite {
  uv_write_t req;  // first member: (QWrite*)req in the cb
  uv_buf_t buf;    // payload inline after
};
internal void quic_ctrl_on_write(uv_write_t *r, int st) {
  (void)st;
  free(r);
}
internal void quic_ctrl_write(QuicConnection *c, const U8 *d, U64 n) {
  if (n == 0 || !c->ctrl_inited || uv_is_closing((uv_handle_t *)&c->ctrl))
    return;
  QWrite *w = (QWrite *)malloc(sizeof(QWrite) + n);
  U8 *p = (U8 *)(w + 1);
  MemoryCopy(p, d, n);
  w->buf = uv_buf_init((char *)p, (unsigned)n);
  w->req.data = w;
  if (uv_write(&w->req, (uv_stream_t *)&c->ctrl, &w->buf, 1,
               quic_ctrl_on_write) != 0) {
    free(w);
    quic_fail(c, "proxy control write failed");
  }
}

// Build the per-datagram SOCKS5 UDP header from the target's resolved address.
internal B32 quic_build_udp_hdr(QuicConnection *c, const struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
    c->udp_hdr_len = proxy_socks5_udp_request_header(
        c->udp_hdr, sizeof c->udp_hdr, 0x01, (const U8 *)&s->sin_addr, 4,
        ntohs(s->sin_port));
  } else if (sa->sa_family == AF_INET6) {
    const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
    c->udp_hdr_len = proxy_socks5_udp_request_header(
        c->udp_hdr, sizeof c->udp_hdr, 0x04, (const U8 *)&s->sin6_addr, 16,
        ntohs(s->sin6_port));
  } else {
    return 0;
  }
  return c->udp_hdr_len > 0;
}

// Derive the UDP relay endpoint from the ASSOCIATE reply's BND.ADDR:BND.PORT.
// Per RFC 1928, BND.ADDR 0.0.0.0 means "same host as the TCP control channel".
internal void quic_proxy_set_relay(QuicConnection *c, U8 atyp, const U8 *addr,
                                   U16 port) {
  U64 alen = atyp == 0x01 ? 4 : atyp == 0x04 ? 16 : 0;
  B32 addr_zero = 1;
  for (U64 i = 0; i < alen; ++i)
    if (addr[i]) {
      addr_zero = 0;
      break;
    }
  if (alen == 0 || addr_zero) {  // use the proxy's address with the bound port
    MemoryCopy(&c->relay_addr, &c->proxy_addr, c->proxy_addrlen);
    c->relay_addrlen = c->proxy_addrlen;
    dns_sockaddr_set_port(&c->relay_addr, port);
  } else if (atyp == 0x01) {
    struct sockaddr_in *sin = (struct sockaddr_in *)&c->relay_addr;
    MemoryZeroStruct(sin);
    sin->sin_family = AF_INET;
    MemoryCopy(&sin->sin_addr, addr, 4);
    sin->sin_port = htons(port);
    c->relay_addrlen = sizeof *sin;
  } else {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&c->relay_addr;
    MemoryZeroStruct(sin6);
    sin6->sin6_family = AF_INET6;
    MemoryCopy(&sin6->sin6_addr, addr, 16);
    sin6->sin6_port = htons(port);
    c->relay_addrlen = sizeof *sin6;
  }
}

// Relay known + target resolved (udp_hdr built): set the ngtcp2 path to the
// relay and run the normal UDP/ngtcp2 setup + handshake.
internal void quic_proxy_finish(QuicConnection *c) {
  MemoryCopy(&c->remote_addr, &c->relay_addr, c->relay_addrlen);
  c->remote_addrlen = c->relay_addrlen;
  quic_begin_udp(c);
}

internal void quic_on_target_resolved(uv_getaddrinfo_t *req, int status,
                                      struct addrinfo *res) {
  QuicConnection *c = (QuicConnection *)req->data;
  if (status < 0) {
    quic_fail(c, uv_strerror(status));
    if (res) uv_freeaddrinfo(res);
    return;
  }
  c->t_resolved_ns = uv_hrtime();
  B32 ok = quic_build_udp_hdr(c, res->ai_addr);
  if (c->dns_cache)
    dns_cache_put(c->dns_cache, c->host, res->ai_addr, res->ai_addrlen,
                  uv_now(loop_uv(c->loop)));
  uv_freeaddrinfo(res);
  if (!ok) {
    quic_fail(c, "unsupported target address family");
    return;
  }
  quic_proxy_finish(c);
}

// Resolve the TARGET (for the SOCKS5 UDP DST header); the relay is already
// known.
internal void quic_proxy_resolve_target(QuicConnection *c) {
  if (c->dns_cache) {
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    if (dns_cache_get(c->dns_cache, c->host, uv_now(loop_uv(c->loop)), &ss,
                      &sl)) {
      dns_sockaddr_set_port(&ss, c->port);
      if (!quic_build_udp_hdr(c, (struct sockaddr *)&ss)) {
        quic_fail(c, "unsupported target address family");
        return;
      }
      c->t_resolved_ns = uv_hrtime();
      quic_proxy_finish(c);
      return;
    }
  }
  c->resolver.data = c;
  struct addrinfo hints;
  MemoryZeroStruct(&hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  char portstr[8];
  snprintf(portstr, sizeof portstr, "%u", c->port);
  int rc = uv_getaddrinfo(loop_uv(c->loop), &c->resolver,
                          quic_on_target_resolved, c->host, portstr, &hints);
  if (rc) quic_fail(c, uv_strerror(rc));
}

internal void quic_proxy_send_associate(QuicConnection *c) {
  U8 buf[10];
  U64 m = proxy_socks5_udp_associate_request(buf, sizeof buf);
  c->nlen = 0;
  c->proxy_phase = QPhase_Associate;
  quic_ctrl_write(c, buf, m);
}
internal void quic_proxy_send_userpass(QuicConnection *c) {
  U8 buf[520];
  U64 m = proxy_socks5_userpass(&c->proxy, buf, sizeof buf);
  if (m == 0) {
    quic_fail(c, "SOCKS5 credentials too long");
    return;
  }
  c->nlen = 0;
  c->proxy_phase = QPhase_Auth;
  quic_ctrl_write(c, buf, m);
}

internal void quic_proxy_advance(QuicConnection *c) {
  switch (c->proxy_phase) {
    case QPhase_Greeting: {
      U8 method = 0;
      if (!proxy_socks5_parse_method(c->nbuf, c->nlen, &method)) return;
      if (method == 0x00)
        quic_proxy_send_associate(c);
      else if (method == 0x02)
        quic_proxy_send_userpass(c);
      else
        quic_fail(c, "SOCKS5 no acceptable auth method");
      return;
    }
    case QPhase_Auth: {
      B32 ok = 0;
      if (!proxy_socks5_parse_userpass_reply(c->nbuf, c->nlen, &ok)) return;
      if (ok)
        quic_proxy_send_associate(c);
      else
        quic_fail(c, "SOCKS5 authentication failed");
      return;
    }
    case QPhase_Associate: {
      B32 complete = 0, ok = 0;
      U8 atyp = 0;
      const U8 *addr = 0;
      U16 port = 0;
      proxy_socks5_parse_reply(c->nbuf, c->nlen, &complete, &ok, &atyp, &addr,
                               &port);
      if (!complete) return;
      if (!ok) {
        quic_fail(c, "SOCKS5 UDP ASSOCIATE failed");
        return;
      }
      quic_proxy_set_relay(c, atyp, addr, port);
      c->proxy_phase = QPhase_Done;
      quic_proxy_resolve_target(
          c);  // -> build udp_hdr -> begin_udp -> handshake
      return;
    }
    default:
      return;
  }
}

internal void quic_ctrl_read_cb(uv_stream_t *s, ssize_t nread,
                                const uv_buf_t *buf) {
  QuicConnection *c = (QuicConnection *)s->data;
  if (nread < 0) {  // the association requires the control channel to stay open
    quic_fail(c, nread == UV_EOF ? "proxy control channel closed"
                                 : uv_strerror((int)nread));
    return;
  }
  if (nread == 0) return;
  if (c->proxy_phase == QPhase_Done)
    return;  // association up; ignore ctrl chatter
  if (c->nlen + (U64)nread > sizeof c->nbuf) {
    quic_fail(c, "proxy negotiation overflow");
    return;
  }
  MemoryCopy(c->nbuf + c->nlen, buf->base, (U64)nread);
  c->nlen += (U64)nread;
  quic_proxy_advance(c);
}

internal void quic_on_ctrl_connected(uv_connect_t *req, int status) {
  QuicConnection *c = (QuicConnection *)req->data;
  if (status < 0) {
    quic_fail(c, uv_strerror(status));
    return;
  }
  uv_read_start((uv_stream_t *)&c->ctrl, net_alloc_cb, quic_ctrl_read_cb);
  U8 buf[8];
  U64 m = proxy_socks5_greeting(&c->proxy, buf, sizeof buf);
  c->nlen = 0;
  c->proxy_phase = QPhase_Greeting;
  quic_ctrl_write(c, buf, m);
}

internal void quic_on_proxy_resolved(uv_getaddrinfo_t *req, int status,
                                     struct addrinfo *res) {
  QuicConnection *c = (QuicConnection *)req->data;
  if (status < 0) {
    quic_fail(c, uv_strerror(status));
    if (res) uv_freeaddrinfo(res);
    return;
  }
  MemoryCopy(&c->proxy_addr, res->ai_addr, res->ai_addrlen);
  c->proxy_addrlen = res->ai_addrlen;
  uv_freeaddrinfo(res);
  uv_tcp_init(loop_uv(c->loop), &c->ctrl);
  c->ctrl_inited = 1;
  c->ctrl.data = c;
  uv_tcp_nodelay(&c->ctrl, 1);
  c->ctrl_conn.data = c;
  if (uv_tcp_connect(&c->ctrl_conn, &c->ctrl, (struct sockaddr *)&c->proxy_addr,
                     quic_on_ctrl_connected) != 0)
    quic_fail(c, "proxy connect failed");
}

internal void quic_proxy_connect_ctrl(QuicConnection *c) {
  c->state = QuicState_Resolving;
  c->resolver.data = c;
  struct addrinfo hints;
  MemoryZeroStruct(&hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  char portstr[8];
  snprintf(portstr, sizeof portstr, "%u", c->proxy.port);
  int rc =
      uv_getaddrinfo(loop_uv(c->loop), &c->resolver, quic_on_proxy_resolved,
                     c->proxy.host, portstr, &hints);
  if (rc) quic_fail(c, uv_strerror(rc));
}

//- ngtcp2 callbacks

internal void quic_rand_cb(U8 *dest, size_t destlen, const ngtcp2_rand_ctx *r) {
  (void)r;
  RAND_bytes(dest, (int)destlen);
}

internal int quic_get_new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                 ngtcp2_stateless_reset_token *token,
                                 size_t cidlen, void *user) {
  (void)conn;
  (void)user;
  if (RAND_bytes(cid->data, (int)cidlen) != 1)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = cidlen;
  if (RAND_bytes(token->data, sizeof token->data) != 1)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  return 0;
}

internal int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user) {
  (void)conn;
  QuicConnection *c = (QuicConnection *)user;
  c->state = QuicState_Established;
  if (!c->t_established_ns)
    c->t_established_ns = uv_hrtime();  // QUIC handshake done
  // If we attempted 0-RTT but the server did not accept it, ngtcp2's BoringSSL
  // crypto helper has already discarded the early streams; flag it so the owner
  // retries the request on a fresh, non-0-RTT connection.
  if (c->want_early_data && c->ssl && !SSL_early_data_accepted(c->ssl))
    c->early_rejected = 1;
  quic_deliver_ready(c, 1, 0);
  return 0;
}

void quic_conn_timing_ms(const QuicConnection *c, U64 req_start_ns, U64 *dns_ms,
                         U64 *tcp_ms, U64 *tls_ms) {
  *dns_ms = *tcp_ms = *tls_ms = 0;  // QUIC has no separate TCP phase
  if (!c->t_established_ns || c->t_established_ns <= req_start_ns) return;
  if (c->t_resolved_ns > c->t_connect_start_ns)
    *dns_ms = (c->t_resolved_ns - c->t_connect_start_ns) / 1000000;
  if (c->t_established_ns > c->t_resolved_ns)
    *tls_ms = (c->t_established_ns - c->t_resolved_ns) / 1000000;
}

internal int quic_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                                      int64_t stream_id, uint64_t offset,
                                      const uint8_t *data, size_t datalen,
                                      void *user, void *sdata) {
  (void)offset;
  (void)sdata;
  QuicConnection *c = (QuicConnection *)user;
  B32 fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
  if (c->on_stream_data)
    c->on_stream_data(c->stream_data_user, stream_id, data, datalen, fin);
  ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
  ngtcp2_conn_extend_max_offset(conn, datalen);
  return 0;
}

internal int quic_stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
                                  int64_t stream_id, uint64_t app_error,
                                  void *user, void *sdata) {
  (void)conn;
  (void)flags;
  (void)app_error;
  (void)sdata;
  QuicConnection *c = (QuicConnection *)user;
  if (c->on_stream_close) c->on_stream_close(c->stream_close_user, stream_id);
  // Recycle the closed stream's send_buf slot (swap-with-last) so a pooled
  // connection can keep opening new request streams indefinitely. The egress
  // loop re-scans send_count each packet, so removing here (inside read_pkt,
  // before the post-recv flush) is safe.
  for (int i = 0; i < c->send_count; ++i)
    if (c->send_bufs[i].id == stream_id) {
      c->send_bufs[i] = c->send_bufs[--c->send_count];
      break;
    }
  return 0;
}

internal B32 quic_init_ngtcp2(QuicConnection *c) {
  if (ngtcp2_crypto_boringssl_configure_client_context(c->ctx) != 0) {
    quic_fail(c, "ngtcp2_crypto_boringssl_configure_client_context failed");
    return 0;
  }
  c->ssl = SSL_new(c->ctx);
  if (!c->ssl) {
    quic_fail(c, "SSL_new failed");
    return 0;
  }
  SSL_set_app_data(c->ssl, &c->conn_ref);
  SSL_set_connect_state(c->ssl);
  if (!configure_ssl(c->ssl, c->tls, c->host, c->ech_config, c->ech_config_len,
                     c->resume_session, c->resume_ctx)) {
    quic_fail(c, "configure_ssl failed");
    return 0;
  }
  // 0-RTT: enable early data only if the offered session is 0-RTT-capable.
  if (c->want_early_data &&
      !(c->resume_session && SSL_SESSION_early_data_capable(c->resume_session)))
    c->want_early_data = 0;
  if (c->want_early_data) SSL_set_early_data_enabled(c->ssl, 1);

  ngtcp2_cid dcid, scid;
  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  scid.datalen = 8;
  if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1 ||
      RAND_bytes(scid.data, (int)scid.datalen) != 1) {
    quic_fail(c, "RAND_bytes failed");
    return 0;
  }

  ngtcp2_path path = {
      {(struct sockaddr *)&c->local_addr, c->local_addrlen},
      {(struct sockaddr *)&c->remote_addr, c->remote_addrlen},
      0,
  };

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.initial_ts = quic_now_ns();
  if (getenv("HOLYTLS_QUIC_DEBUG")) settings.log_printf = quic_log;

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_data = c->h3->initial_max_data;
  params.initial_max_stream_data_bidi_local =
      c->h3->initial_max_stream_data_bidi_local;
  params.initial_max_stream_data_bidi_remote =
      c->h3->initial_max_stream_data_bidi_remote;
  params.initial_max_stream_data_uni = c->h3->initial_max_stream_data_uni;
  params.initial_max_streams_bidi = c->h3->initial_max_streams_bidi;
  params.initial_max_streams_uni = c->h3->initial_max_streams_uni;
  params.max_idle_timeout = c->h3->max_idle_timeout_ms * NGTCP2_MILLISECONDS;
  // Only override ngtcp2's (valid) default when the profile specifies it: a
  // profile that omits max_udp_payload_size (e.g. Firefox, which sends none)
  // must not force it to 0, which is below the QUIC minimum (1200) and makes the
  // server reject the transport params (CONNECTION_CLOSE -> draining).
  if (c->h3->max_udp_payload_size)
    params.max_udp_payload_size = c->h3->max_udp_payload_size;
  // Required when we advertise SETTINGS_H3_DATAGRAM=1 (Chrome does); without it
  // a strict server (e.g. cloudflare) closes with H3_SETTINGS_ERROR.
  params.max_datagram_frame_size = c->h3->max_datagram_frame_size;

  ngtcp2_callbacks callbacks;
  MemoryZeroStruct(&callbacks);
  callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks.update_key = ngtcp2_crypto_update_key_cb;
  callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks.delete_crypto_cipher_ctx =
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks.get_path_challenge_data2 =
      ngtcp2_crypto_get_path_challenge_data2_cb;
  callbacks.rand = quic_rand_cb;
  callbacks.get_new_connection_id2 = quic_get_new_cid_cb;
  callbacks.handshake_completed = quic_handshake_completed_cb;
  callbacks.recv_stream_data = quic_recv_stream_data_cb;
  callbacks.stream_close = quic_stream_close_cb;

  int rv =
      ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                             &callbacks, &settings, &params, 0, c);
  if (rv != 0) {
    quic_fail(c, ngtcp2_strerror(rv));
    return 0;
  }
  ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

  // Restore the prior connection's 0-RTT transport params so early streams can
  // be opened. ngtcp2 requires this AFTER set_tls_native_handle and BEFORE
  // opening any 0-RTT stream. On failure, fall back cleanly to a 1-RTT
  // handshake.
  if (c->want_early_data && c->early_tp_len) {
    if (ngtcp2_conn_decode_and_set_0rtt_transport_params(
            c->conn, c->early_tp, (size_t)c->early_tp_len) != 0)
      c->want_early_data = 0;
  } else {
    c->want_early_data = 0;  // no TP -> cannot 0-RTT
  }
  return 1;
}

U64 quic_conn_encode_0rtt_tp(QuicConnection *c, U8 *dst, U64 cap) {
  if (!c->conn) return 0;
  ngtcp2_ssize n =
      ngtcp2_conn_encode_0rtt_transport_params2(c->conn, dst, (size_t)cap);
  return n > 0 ? (U64)n : 0;
}

//- io

internal void quic_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                           const struct sockaddr *addr, unsigned flags) {
  (void)flags;
  QuicConnection *c = (QuicConnection *)handle->data;
  if (nread == 0 || addr == 0) return;  // nothing to read this event
  if (nread < 0) {
    quic_fail(c, uv_strerror((int)nread));
    return;
  }
  const U8 *data = (const U8 *)buf->base;
  U64 dlen = (U64)nread;
  const struct sockaddr *src = addr;
  if (c->proxied) {
    // Strip the relay's SOCKS5 UDP header; the inner payload is the QUIC
    // packet. ngtcp2's path remote stays the relay (== remote_addr), as on
    // egress.
    U64 hl = proxy_socks5_udp_header_len(data, dlen);
    if (hl == 0 || hl >= dlen) return;  // malformed / empty -> drop
    data += hl;
    dlen -= hl;
    src = (const struct sockaddr *)&c->remote_addr;
  }
  ngtcp2_path path = {
      {(struct sockaddr *)&c->local_addr, c->local_addrlen},
      {(struct sockaddr *)src, c->remote_addrlen},
      0,
  };
  ngtcp2_pkt_info pi;
  MemoryZeroStruct(&pi);
  c->in_recv =
      1;  // stream callbacks fire here: submits must defer their egress
  int rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, data, (size_t)dlen,
                                quic_now_ns());
  c->in_recv = 0;
  if (rv != 0) {
    quic_fail(c, ngtcp2_strerror(rv));
    return;
  }
  quic_flush_egress(c);
  // Safe point (outside read_pkt) to submit streams queued by response
  // callbacks.
  if (c->on_recv_done) c->on_recv_done(c->recv_done_user);
}

internal QuicSendBuf *quic_pick_pending(QuicConnection *c, S64 *stream_id) {
  for (int i = 0; i < c->send_count; ++i) {
    QuicSendBuf *sb = &c->send_bufs[i];
    if (sb->blocked) continue;  // flow-control-blocked this pass
    if (sb->off < sb->data.len || (sb->fin && !sb->fin_sent)) {
      *stream_id = sb->id;
      return sb;
    }
  }
  *stream_id = -1;
  return 0;
}

internal QuicSendBuf *quic_find_or_add_send_buf(QuicConnection *c, S64 id) {
  for (int i = 0; i < c->send_count; ++i)
    if (c->send_bufs[i].id == id) return &c->send_bufs[i];
  if (c->send_count >= (int)ArrayCount(c->send_bufs)) return 0;
  QuicSendBuf *sb = &c->send_bufs[c->send_count++];
  sb->id = id;
  u8buf_init(&sb->data, c->arena, 0);
  sb->off = 0;
  sb->fin = 0;
  sb->fin_sent = 0;
  return sb;
}

internal void quic_flush_egress(QuicConnection *c) {
  if (!c->conn || c->state == QuicState_Closing || c->state == QuicState_Failed)
    return;
  U8 buf[1452];
  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;
  MemoryZeroStruct(&pi);
  U64 ts = quic_now_ns();
  // Fresh pass: re-attempt every stream (a stream blocked last time may have
  // had its flow-control window lifted by a MAX_STREAM_DATA/MAX_DATA frame
  // since).
  for (int i = 0; i < c->send_count; ++i) c->send_bufs[i].blocked = 0;

  for (;;) {
    S64 stream_id = -1;
    QuicSendBuf *sb = quic_pick_pending(c, &stream_id);
    ngtcp2_vec datav;
    MemoryZeroStruct(&datav);
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (sb) {
      datav.base = sb->data.v + sb->off;
      datav.len = sb->data.len - sb->off;
      if (sb->fin && !sb->fin_sent) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }
    ngtcp2_ssize wdatalen = 0;
    ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
        c->conn, &ps.path, &pi, buf, sizeof buf, &wdatalen, flags,
        (int64_t)stream_id, sb ? &datav : 0, sb ? 1 : 0, ts);
    if (nwrite < 0) {
      if (nwrite == NGTCP2_ERR_WRITE_MORE) {
        if (sb && wdatalen > 0) {
          sb->off += (U64)wdatalen;
          if (sb->off >= sb->data.len && sb->fin) sb->fin_sent = 1;
        }
        continue;
      }
      // Per-stream, non-fatal (ngtcp2 contract under WRITE_STREAM_FLAG_MORE):
      // the stream can't make progress now (e.g. its 0-RTT flow-control window
      // from the remembered transport params is exhausted). Skip it this pass
      // and keep building the packet; its buffered bytes drain on a later flush
      // once the server raises flow control. Do NOT tear the connection down.
      if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
          nwrite == NGTCP2_ERR_STREAM_SHUT_WR ||
          nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) {
        if (sb) sb->blocked = 1;
        continue;
      }
      quic_fail(c, ngtcp2_strerror((int)nwrite));
      return;
    }
    if (sb && wdatalen > 0) {
      sb->off += (U64)wdatalen;
      if (sb->off >= sb->data.len && sb->fin) sb->fin_sent = 1;
    }
    if (nwrite == 0) break;  // nothing left to send
    if (c->proxied) {
      // Prepend the SOCKS5 UDP header; the 2 bufs gather into one datagram to
      // the relay (no copy — the header lives in the struct). The relay strips
      // it.
      uv_buf_t out2[2] = {
          uv_buf_init((char *)c->udp_hdr, (unsigned)c->udp_hdr_len),
          uv_buf_init((char *)buf, (unsigned)nwrite),
      };
      uv_udp_try_send(&c->udp, out2, 2, 0);
    } else {
      uv_buf_t out = uv_buf_init((char *)buf, (unsigned)nwrite);
      uv_udp_try_send(&c->udp, &out, 1,
                      0);  // UDP: drop on EAGAIN, QUIC retransmits
    }
  }
  quic_arm_timer(c);
}

internal void quic_arm_timer(QuicConnection *c) {
  if (!c->conn || !c->timer_inited) return;
  ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(c->conn);
  if (expiry == UINT64_MAX) return;
  U64 now = quic_now_ns();
  U64 ms = expiry <= now ? 1 : (expiry - now) / NGTCP2_MILLISECONDS + 1;
  uv_timer_start(&c->timer, quic_timer_cb, ms, 0);
}

internal void quic_timer_cb(uv_timer_t *t) {
  QuicConnection *c = (QuicConnection *)t->data;
  if (!c->conn) return;
  int rv = ngtcp2_conn_handle_expiry(c->conn, quic_now_ns());
  if (rv != 0) {
    quic_fail(c, ngtcp2_strerror(rv));
    return;
  }
  quic_flush_egress(c);
}

//- stream API

int quic_open_uni_stream(QuicConnection *c, S64 *out_id) {
  int64_t id = 0;
  int rv = ngtcp2_conn_open_uni_stream(c->conn, &id, 0);
  if (rv == 0) {
    *out_id = id;
    quic_find_or_add_send_buf(c, id);  // create empty buffer
  }
  return rv;
}

int quic_open_bidi_stream(QuicConnection *c, S64 *out_id) {
  int64_t id = 0;
  int rv = ngtcp2_conn_open_bidi_stream(c->conn, &id, 0);
  if (rv == 0) {
    *out_id = id;
    quic_find_or_add_send_buf(c, id);
  }
  return rv;
}

void quic_stream_send(QuicConnection *c, S64 stream_id, const U8 *data, U64 len,
                      B32 fin) {
  QuicSendBuf *sb = quic_find_or_add_send_buf(c, stream_id);
  if (!sb) return;
  u8buf_append(&sb->data, data, len);
  if (fin) sb->fin = 1;
  quic_flush_egress(c);
}

void quic_reset_stream(QuicConnection *c, S64 stream_id) {
  if (!c->conn) return;
  // Drop any buffered egress for this stream, then shut both directions with an
  // H3 "request cancelled" (0x010c) app error; the flush emits
  // RESET_STREAM/STOP_SENDING.
  for (int i = 0; i < c->send_count; ++i)
    if (c->send_bufs[i].id == stream_id) {
      c->send_bufs[i] = c->send_bufs[--c->send_count];
      break;
    }
  ngtcp2_conn_shutdown_stream(c->conn, 0, stream_id, 0x010cull);
  quic_flush_egress(c);
}

//- misc

String8 quic_conn_alpn(QuicConnection *c) {
  const U8 *p = 0;
  unsigned n = 0;
  if (c->ssl) SSL_get0_alpn_selected(c->ssl, &p, &n);
  String8 r;
  r.str = (U8 *)p;
  r.size = (p && n) ? n : 0;
  return r;
}

internal void quic_deliver_ready(QuicConnection *c, B32 ok, const char *err) {
  if (c->ready_fired) return;
  c->ready_fired = 1;
  if (c->on_ready) c->on_ready(c->ready_user, ok, err);
}

internal void quic_fail(QuicConnection *c, const char *reason) {
  // A connection the owner already chose to close (e.g. the 0-RTT-reject retry)
  // must not surface a late on_closed from a trailing/coalesced frame error.
  if (c->state == QuicState_Failed || c->state == QuicState_Closing) return;
  c->state = QuicState_Failed;
  if (!c->ready_fired) {
    quic_deliver_ready(c, 0, reason);
  } else if (c->on_closed) {
    c->on_closed(c->closed_user, reason);
  }
}

internal void quic_on_handle_closed(uv_handle_t *h) {
  QuicConnection *c = (QuicConnection *)h->data;
  if (!c) return;
  if (--c->handles_closing <= 0 && c->on_fully_closed)
    c->on_fully_closed(c->fully_closed_user);
}

void quic_conn_close(QuicConnection *c) {
  if (c->state == QuicState_Closing) return;
  c->state = QuicState_Closing;
  c->handles_closing = 0;
  if (c->timer_inited && !uv_is_closing((uv_handle_t *)&c->timer)) {
    ++c->handles_closing;
    uv_close((uv_handle_t *)&c->timer, quic_on_handle_closed);
    c->timer_inited = 0;
  }
  if (c->udp_inited && !uv_is_closing((uv_handle_t *)&c->udp)) {
    ++c->handles_closing;
    uv_udp_recv_stop(&c->udp);
    uv_close((uv_handle_t *)&c->udp, quic_on_handle_closed);
    c->udp_inited = 0;
  }
  if (c->ctrl_inited && !uv_is_closing((uv_handle_t *)&c->ctrl)) {
    ++c->handles_closing;  // the SOCKS5 control channel (proxied path)
    uv_read_stop((uv_stream_t *)&c->ctrl);
    uv_close((uv_handle_t *)&c->ctrl, quic_on_handle_closed);
    c->ctrl_inited = 0;
  }
  if (c->handles_closing == 0 && c->on_fully_closed)
    c->on_fully_closed(c->fully_closed_user);
}
