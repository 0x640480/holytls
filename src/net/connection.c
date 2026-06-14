#include "net/connection.h"

#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/platform_net.h"  // inet_pton, sockaddr_in/in6 (winsock on Windows)
#include "net/dns_cache.h"

// libuv writes need the buffer to outlive the call (freed in the write
// callback): the request header + the payload inline behind it. Fast path: the
// whole block lives in the connection's egress ring and is FIFO-released in
// conn_write_cb — zero malloc/free per write. `ring` distinguishes the malloc
// fallback used when the ring is momentarily full (kernel send backpressure)
// or absent.
typedef struct WriteReq WriteReq;
struct WriteReq {
  uv_write_t req;
  uv_buf_t buf;
  B32 ring;
  // payload bytes follow inline
};

// Egress ring capacity (power of two). Holds a few max-size TLS records of
// in-flight writes; under backpressure the ring fills and writes degrade to
// the malloc path, so correctness never depends on this size.
#define CONN_EGRESS_CAP 65536
_Static_assert((sizeof(ra_ring) % RA_CACHELINE) == 0,
               "control block + buffer share one aligned_alloc");

internal void conn_egress_init(Connection *c) {
  void *mem = ra_aligned_alloc(RA_CACHELINE, sizeof(ra_ring) + CONN_EGRESS_CAP);
  if (!mem) return;  // egress stays 0 -> per-write malloc fallback
  c->egress = (ra_ring *)mem;
  if (ra_init(c->egress, (U8 *)mem + sizeof(ra_ring), CONN_EGRESS_CAP) != 0) {
    ra_aligned_free(mem);
    c->egress = 0;
  }
}

// Copy `host` into `dst` (NUL-terminated), stripping the brackets of an IPv6
// literal ("[::1]" -> "::1"). Truncates silently at cap-1 (invalid hostnames).
internal void strip_host(char *dst, U64 cap, const char *host) {
  U64 n = strlen(host);
  const char *p = host;
  if (n >= 2 && host[0] == '[' && host[n - 1] == ']') {
    p = host + 1;
    n -= 2;
  }
  if (n > cap - 1) n = cap - 1;
  MemoryCopy(dst, p, n);
  dst[n] = 0;
}

internal void conn_fail(Connection *c, const char *reason);
internal void conn_deliver_ready(Connection *c, B32 ok, const char *err);
internal void conn_drive_handshake(Connection *c);
internal void conn_flush_output(Connection *c);
internal void conn_pending_append(Connection *c, const U8 *data, U64 len);
internal B32 conn_flush_pending(Connection *c);
internal void conn_on_connected(uv_connect_t *req, int status);
// Generic libuv read-buffer provider, shared with the QUIC path
// (quic_connection.c, later in the unity TU) — see the definition below.
internal void net_alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *buf);
internal void conn_read_cb(uv_stream_t *stream, ssize_t nread,
                           const uv_buf_t *buf);
internal void conn_write_cb(uv_write_t *req, int status);
internal void conn_raw_write(Connection *c, const U8 *data, U64 len);
internal void conn_transport_feed(Connection *c, const U8 *data, U64 len);
internal void conn_proxy_begin(Connection *c);
internal void conn_proxy_outer_drive(Connection *c);
internal void conn_proxy_on_data(Connection *c, const U8 *data, U64 len);
internal void conn_proxy_advance(Connection *c);

// Negotiation step for a proxied connection (Connection.proxy_phase).
typedef enum ProxyPhase {
  ProxyPhase_None,
  ProxyPhase_HttpConnect,     // CONNECT sent, awaiting the HTTP response
  ProxyPhase_Socks5Greeting,  // greeting sent, awaiting method selection
  ProxyPhase_Socks5Auth,      // user/pass sent, awaiting auth status
  ProxyPhase_Socks5Connect,   // CONNECT request sent, awaiting the reply
} ProxyPhase;

// Parse an IPv4/IPv6 literal into a source sockaddr (port 0 = ephemeral). A ':'
// marks IPv6. Returns 1 on success.
internal B32 ip_literal_to_sockaddr(String8 ip, struct sockaddr_storage *out) {
  char buf[64];
  if (ip.size == 0 || ip.size >= sizeof buf) return 0;
  MemoryCopy(buf, ip.str, ip.size);
  buf[ip.size] = 0;
  MemoryZeroStruct(out);
  U64 idx;
  if (str8_index_of(ip, ':', &idx)) {
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)out;
    if (inet_pton(AF_INET6, buf, &a6->sin6_addr) != 1) return 0;
    a6->sin6_family = AF_INET6;
  } else {
    struct sockaddr_in *a4 = (struct sockaddr_in *)out;
    if (inet_pton(AF_INET, buf, &a4->sin_addr) != 1) return 0;
    a4->sin_family = AF_INET;
  }
  return 1;
}

B32 conn_set_local_address(Connection *c, String8 ip) {
  if (!ip_literal_to_sockaddr(ip, &c->bind_addr)) return 0;
  c->has_bind_addr = 1;
  return 1;
}

// Connect the (already-created) TCP handle to `addr` — from a fresh resolution
// or the DNS cache. On failure, fails the connection.
internal void conn_begin_tcp_connect(Connection *c,
                                     const struct sockaddr *addr) {
  if (c->has_bind_addr) {  // bind the chosen source address (egress IP)
    int brc = uv_tcp_bind(&c->tcp, (const struct sockaddr *)&c->bind_addr, 0);
    if (brc) {
      conn_fail(c, uv_strerror(brc));
      return;
    }
  }
  c->connect_req.data = c;
  int rc = uv_tcp_connect(&c->connect_req, &c->tcp, addr, conn_on_connected);
  if (rc) {
    conn_fail(c, uv_strerror(rc));
    return;
  }
  c->state = ConnState_Connecting;
}

//- libuv trampolines

internal void conn_on_resolved(uv_getaddrinfo_t *req, int status,
                               struct addrinfo *res) {
  Connection *c = (Connection *)req->data;
  if (status < 0) {
    conn_fail(c, uv_strerror(status));
    if (res) uv_freeaddrinfo(res);
    return;
  }
  c->t_resolved_ns = uv_hrtime();  // DNS done
  if (c->dns_cache)  // remember this resolution (of the proxy, when proxied)
    dns_cache_put(c->dns_cache, c->resolve_host, res->ai_addr, res->ai_addrlen,
                  uv_now(loop_uv(c->loop)));
  conn_begin_tcp_connect(c, res->ai_addr);
  uv_freeaddrinfo(res);  // uv_tcp_connect copied the address
}

internal void conn_on_connected(uv_connect_t *req, int status) {
  Connection *c = (Connection *)req->data;
  if (status < 0) {
    // A cached address that no longer connects: drop it so a retry resolves
    // fresh.
    if (c->dns_was_cached && c->dns_cache)
      dns_cache_evict(c->dns_cache, c->resolve_host);
    conn_fail(c, uv_strerror(status));
    return;
  }
  c->t_connected_ns =
      uv_hrtime();  // TCP connect done (to the proxy when proxied)
  uv_read_start((uv_stream_t *)&c->tcp, net_alloc_cb, conn_read_cb);
  if (c->proxy.type == ProxyType_None) {
    c->state = ConnState_Handshaking;
    conn_drive_handshake(c);
  } else {
    conn_proxy_begin(
        c);  // negotiate the tunnel; the target TLS then runs over it
  }
}

// Reused per-thread read buffer for every libuv stream/datagram read in the
// loop (TCP ciphertext here, UDP datagrams and the proxy control stream in
// quic_connection.c). The read callbacks consume the bytes synchronously before
// the next read event — single loop thread, one read in flight — so a single
// shared buffer needs no per-read malloc/free and never aliases a live read.
internal void net_alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *buf) {
  (void)h;
  (void)suggested;
  static thread_local U8 storage[65536];
  buf->base = (char *)storage;
  buf->len = sizeof storage;
}

internal void conn_read_cb(uv_stream_t *stream, ssize_t nread,
                           const uv_buf_t *buf) {
  Connection *c = (Connection *)stream->data;
  if (nread < 0) {
    if (c->state == ConnState_Established) {
      c->state = ConnState_Closing;
      if (c->on_closed)
        c->on_closed(c->closed_user,
                     nread == UV_EOF ? 0 : uv_strerror((int)nread));
    } else {
      conn_fail(c, nread == UV_EOF ? "connection closed during handshake"
                                   : uv_strerror((int)nread));
    }
    return;
  }
  if (nread == 0) return;  // EAGAIN
  const U8 *data = (const U8 *)buf->base;
  U64 n = (U64)nread;

  // Proxy negotiation phases consume bytes before the target TLS begins.
  if (c->state ==
      ConnState_ProxyTls) {  // outer TLS handshake to an HTTPS proxy
    ssl_pump_feed_ciphertext(&c->outer, data, n);
    conn_proxy_outer_drive(c);
    return;
  }
  if (c->state == ConnState_ProxyNegotiate) {  // CONNECT / SOCKS5 exchange
    conn_proxy_on_data(c, data, n);
    return;
  }

  // Target TLS / established: feed via the transport (raw, or unwrapped from
  // the outer proxy TLS for an HTTPS proxy).
  conn_transport_feed(c, data, n);
  if (!c->pump.established) {
    conn_drive_handshake(c);
  } else {
    conn_flush_output(c);  // e.g. session tickets / key updates
    if (c->on_readable) c->on_readable(c->readable_user);
  }
}

internal void conn_write_cb(uv_write_t *req, int status) {
  WriteReq *wr = (WriteReq *)req->data;
  if (wr->ring) {
    // Ring writes complete in submission order (libuv finishes a stream's
    // writes FIFO, including UV_ECANCELED on close), so wr is the oldest live
    // block; ra_free asserts exactly that in debug builds. The Connection is
    // alive here: uv runs every pending write callback before the close
    // callback that lets the owner free it.
    Connection *c = (Connection *)req->handle->data;
    ra_free(c->egress, wr);
  } else {
    free(wr);
  }
  (void)status;  // a dead connection surfaces on the next read error
}

internal void conn_on_handle_closed(uv_handle_t *h) {
  Connection *c = (Connection *)h->data;
  if (!c) return;
  c->tcp_inited = 0;
  // May free the owner (and thus this connection) — touch nothing afterward.
  if (c->on_fully_closed) c->on_fully_closed(c->fully_closed_user);
}

//- driving

internal void conn_drive_handshake(Connection *c) {
  HsStatus st = ssl_pump_do_handshake(&c->pump);
  conn_flush_output(c);  // always flush — this is what sends the ClientHello
  if (st == HsStatus_Done) {
    c->state = ConnState_Established;
    if (!c->t_established_ns) c->t_established_ns = uv_hrtime();  // TLS done
    // Send any 0-RTT early-data overflow as 1-RTT. If it can't all be written,
    // fail rather than report a truncated request as ready.
    if (!conn_flush_pending(c)) {
      conn_fail(c, "early-data flush failed");
      return;
    }
    conn_deliver_ready(c, 1, 0);
  } else if (st == HsStatus_EarlyData) {
    // 0-RTT window open: permit early-data writes and let the caller submit its
    // request once (it goes out as early data). The handshake continues; the
    // server's response drives it to HsStatus_Done (accepted) or
    // HsStatus_EarlyRejected. Stay in EarlyData until then
    // (pump.established==0, so conn_read_cb keeps re-driving the handshake).
    c->state = ConnState_EarlyData;
    if (!c->early_fired) {
      c->early_fired = 1;
      if (c->on_early_ready) c->on_early_ready(c->early_ready_user);
      // Push the early-data records the callback wrote (unless it tore the
      // connection down, e.g. a session-alloc failure).
      if (c->state == ConnState_EarlyData) conn_flush_output(c);
    }
  } else if (st == HsStatus_EarlyRejected) {
    // The server declined 0-RTT. The early-data bytes are discarded; signal the
    // owner (via on_ready, which has not fired yet) so it retries fresh.
    c->early_rejected = 1;
    conn_fail(c, "early data rejected");
  } else if (st == HsStatus_Error) {
    unsigned long e = c->pump.last_err;
    if (e) {
      char buf[256];
      ERR_error_string_n(e, buf, sizeof buf);
      conn_fail(c, buf);
    } else {
      conn_fail(c, "TLS handshake failed");
    }
  }
  // WantIo: wait for more ciphertext via conn_read_cb.
}

// Submit one in-flight write whose payload sits inline after `wr` (which must
// stay valid until conn_write_cb). Returns 0 or a libuv error code.
internal int conn_submit_write(Connection *c, WriteReq *wr, U64 len, B32 ring) {
  wr->ring = ring;
  wr->buf = uv_buf_init((char *)(wr + 1), (unsigned)len);
  wr->req.data = wr;
  return uv_write(&wr->req, (uv_stream_t *)&c->tcp, &wr->buf, 1, conn_write_cb);
}

// Write raw bytes straight to the TCP socket. Fast path: the WriteReq + payload
// are one egress-ring block, released in conn_write_cb. Fallback (ring full or
// absent): one malloc, freed there instead. The base for both plaintext proxy
// negotiation and ciphertext the ring couldn't take in conn_pump_to_socket.
internal void conn_raw_write(Connection *c, const U8 *data, U64 len) {
  if (len == 0 || !c->tcp_inited || uv_is_closing((uv_handle_t *)&c->tcp))
    return;
  if (c->egress) {
    WriteReq *wr = (WriteReq *)ra_reserve(c->egress, sizeof(WriteReq) + len, 0);
    if (wr) {
      MemoryCopy(wr + 1, data, len);
      int rc = conn_submit_write(c, wr, len, 1);
      if (rc) {  // abort (commit would orphan the block) before failing
        ra_abort(c->egress);
        conn_fail(c, uv_strerror(rc));
      } else {
        ra_commit(c->egress, sizeof(WriteReq) + len, 0);
      }
      return;
    }
  }
  WriteReq *wr = (WriteReq *)malloc(sizeof(WriteReq) + len);
  if (!wr) {
    conn_fail(c, "out of memory");
    return;
  }
  MemoryCopy(wr + 1, data, len);
  int rc = conn_submit_write(c, wr, len, 0);
  if (rc) {
    free(wr);
    conn_fail(c, uv_strerror(rc));
  }
}

// Drain `pump`'s write BIO (ciphertext) to the socket. Fast path: reserve a
// ring block and BIO-read straight into the in-flight write buffer — no malloc
// and no intermediate copy (the reserve -> fill -> commit pattern the ring was
// built for). Falls back to a stack hop + conn_raw_write when the ring is
// momentarily full or absent.
internal void conn_pump_to_socket(Connection *c, SslPump *pump) {
  for (;;) {
    if (!c->tcp_inited || uv_is_closing((uv_handle_t *)&c->tcp)) return;
    if (c->egress) {
      U64 max = 0;
      WriteReq *wr =
          (WriteReq *)ra_reserve(c->egress, sizeof(WriteReq) + 1024, &max);
      if (wr) {
        int n =
            ssl_pump_read_output(pump, (U8 *)(wr + 1), max - sizeof(WriteReq));
        if (n <= 0) {
          ra_abort(c->egress);
          return;
        }
        int rc = conn_submit_write(c, wr, (U64)n, 1);
        if (rc) {  // clear the reservation before conn_fail can re-enter us
          ra_abort(c->egress);
          conn_fail(c, uv_strerror(rc));
          return;
        }
        ra_commit(c->egress, sizeof(WriteReq) + (U64)n, 0);
        continue;
      }
    }
    U8 tmp[16384];
    int n = ssl_pump_read_output(pump, tmp, sizeof tmp);
    if (n <= 0) return;
    conn_raw_write(c, tmp, (U64)n);
  }
}

// Drain the outer (proxy) TLS write BIO to the socket.
internal void conn_proxy_outer_flush(Connection *c) {
  conn_pump_to_socket(c, &c->outer);
}

internal void conn_flush_output(Connection *c) {
  // Skip when there is no handle, or it is already closing (a re-entrant
  // failure path may reach here after conn_close has scheduled uv_close).
  if (!c->tcp_inited || uv_is_closing((uv_handle_t *)&c->tcp)) return;
  if (!c->outer_active) {
    // Inner ciphertext straight to the socket, BIO-read into the egress ring.
    conn_pump_to_socket(c, &c->pump);
    return;
  }
  // HTTPS proxy: wrap the inner (target) ciphertext inside the outer proxy
  // TLS. The stack hop is inherent here (SSL_write re-encrypts the bytes, so
  // there is no in-place destination); the outer pump's ciphertext then goes
  // out through the ring. Post-handshake the outer mem-wbio is unbounded, so
  // SSL_write takes it all; loop defensively regardless.
  U8 tmp[16384];
  int n;
  while ((n = ssl_pump_read_output(&c->pump, tmp, sizeof tmp)) > 0) {
    U64 off = 0;
    while (off < (U64)n) {
      int w = ssl_pump_write_plaintext(&c->outer, tmp + off, (U64)n - off);
      if (w > 0)
        off += (U64)w;
      else
        break;
    }
  }
  conn_proxy_outer_flush(c);  // drain outer wbio -> socket
}

internal void conn_deliver_ready(Connection *c, B32 ok, const char *err) {
  if (c->ready_fired) return;
  c->ready_fired = 1;
  if (c->on_ready) c->on_ready(c->ready_user, ok, err);
}

// Queue plaintext that SSL_write could not accept (the 0-RTT early-data limit).
internal void conn_pending_append(Connection *c, const U8 *data, U64 len) {
  if (!len) return;
  if (c->pending_len + len > c->pending_cap) {
    U64 ncap = c->pending_cap ? c->pending_cap : 4096;
    while (ncap < c->pending_len + len) ncap *= 2;
    U8 *np = (U8 *)realloc(c->pending, ncap);
    if (!np) {
      conn_fail(c, "out of memory");
      return;
    }
    c->pending = np;
    c->pending_cap = ncap;
  }
  MemoryCopy(c->pending + c->pending_len, data, len);
  c->pending_len += len;
}

// After the handshake completes, flush any early-data overflow as 1-RTT. The
// early-data and 1-RTT application byte streams are contiguous, so splitting
// the request across the boundary is transparent to the server. Returns false
// if the whole tail could not be written (a hard SSL_write error) — the caller
// must then fail the connection rather than report a half-sent request as
// ready.
internal B32 conn_flush_pending(Connection *c) {
  if (!c->pending_len) return 1;
  U64 off = 0;
  while (off < c->pending_len) {
    int n = ssl_pump_write_plaintext(&c->pump, c->pending + off,
                                     c->pending_len - off);
    if (n > 0)
      off += (U64)n;
    else
      break;  // post-handshake the unbounded wbio always consumes everything
  }
  B32 ok = (off == c->pending_len);  // anything short here is a real failure
  free(c->pending);
  c->pending = 0;
  c->pending_len = 0;
  c->pending_cap = 0;
  conn_flush_output(c);
  return ok;
}

internal void conn_fail(Connection *c, const char *reason) {
  c->state = ConnState_Failed;
  conn_deliver_ready(c, 0, reason);
}

//- proxy tunnel negotiation
//
// When proxied, conn_connect connected the PROXY (not the target). We negotiate
// a tunnel here, then hand off to conn_drive_handshake to run the target's TLS
// over it. For an HTTPS proxy the `outer` pump carries everything to the proxy
// (its own TLS), and the inner/target pump's records ride inside that — see
// conn_transport_feed / conn_flush_output.

// Feed received socket bytes toward the target (inner) pump. With an HTTPS
// proxy the bytes are outer-TLS ciphertext: decrypt them through the outer pump
// first; the recovered plaintext is the inner (target) TLS ciphertext.
internal void conn_transport_feed(Connection *c, const U8 *data, U64 len) {
  if (!c->outer_active) {
    ssl_pump_feed_ciphertext(&c->pump, data, len);
    return;
  }
  ssl_pump_feed_ciphertext(&c->outer, data, len);
  U8 tmp[16384];
  int m;
  while ((m = ssl_pump_read_plaintext(&c->outer, tmp, sizeof tmp)) > 0)
    ssl_pump_feed_ciphertext(&c->pump, tmp, (U64)m);
}

// The tunnel to the target is open (any proxy type). Start the target TLS over
// it — its ClientHello is byte-identical to a direct connection.
internal void conn_proxy_tunnel_ready(Connection *c) {
  c->nlen = 0;
  c->proxy_phase = ProxyPhase_None;
  c->state = ConnState_Handshaking;
  conn_drive_handshake(c);
}

internal void conn_socks5_send_connect(Connection *c) {
  U8 buf[300];  // 7 fixed + domain (<=255) + 2 port
  U64 m = proxy_socks5_connect_request(str8_cstring(c->host), c->port, buf,
                                       sizeof buf);
  if (m == 0) {
    conn_fail(c, "SOCKS5 target host too long");
    return;
  }
  c->nlen = 0;
  c->proxy_phase = ProxyPhase_Socks5Connect;
  conn_raw_write(c, buf, m);
}

internal void conn_socks5_send_userpass(Connection *c) {
  U8 buf[520];  // 3 fixed + user (<=255) + pass (<=255)
  U64 m = proxy_socks5_userpass(&c->proxy, buf, sizeof buf);
  if (m == 0) {
    conn_fail(c, "SOCKS5 credentials too long");
    return;
  }
  c->nlen = 0;
  c->proxy_phase = ProxyPhase_Socks5Auth;
  conn_raw_write(c, buf, m);
}

// Run the parser for the current negotiation step against the accumulated
// reply.
internal void conn_proxy_advance(Connection *c) {
  switch (c->proxy_phase) {
    case ProxyPhase_HttpConnect: {
      B32 complete = 0;
      int status = 0;
      proxy_http_response_status(c->nbuf, c->nlen, &complete, &status);
      if (!complete) {
        if (c->nlen >= sizeof c->nbuf)
          conn_fail(c, "proxy CONNECT response too large");
        return;
      }
      if (status != 200)
        conn_fail(c, "proxy CONNECT refused");
      else
        conn_proxy_tunnel_ready(c);
      return;
    }
    case ProxyPhase_Socks5Greeting: {
      U8 method = 0;
      if (!proxy_socks5_parse_method(c->nbuf, c->nlen, &method)) return;
      if (method == 0x00)
        conn_socks5_send_connect(c);
      else if (method == 0x02)
        conn_socks5_send_userpass(c);
      else
        conn_fail(c, "SOCKS5 no acceptable auth method");
      return;
    }
    case ProxyPhase_Socks5Auth: {
      B32 ok = 0;
      if (!proxy_socks5_parse_userpass_reply(c->nbuf, c->nlen, &ok)) return;
      if (ok)
        conn_socks5_send_connect(c);
      else
        conn_fail(c, "SOCKS5 authentication failed");
      return;
    }
    case ProxyPhase_Socks5Connect: {
      B32 complete = 0, ok = 0;
      proxy_socks5_parse_reply(c->nbuf, c->nlen, &complete, &ok, 0, 0, 0);
      if (!complete) return;
      if (ok)
        conn_proxy_tunnel_ready(c);
      else
        conn_fail(c, "SOCKS5 CONNECT failed");
      return;
    }
    default:
      return;
  }
}

// Append negotiation bytes and re-run the phase parser. Overflow (a reply
// larger than nbuf) is only reachable with a hostile/broken proxy -> fail.
internal void conn_proxy_consume(Connection *c, const U8 *data, U64 len) {
  if (c->nlen + len > sizeof c->nbuf) {
    conn_fail(c, "proxy negotiation overflow");
    return;
  }
  MemoryCopy(c->nbuf + c->nlen, data, len);
  c->nlen += len;
  conn_proxy_advance(c);
}

internal void conn_proxy_on_data(Connection *c, const U8 *data, U64 len) {
  // For an HTTPS proxy the CONNECT exchange is plaintext inside the outer TLS.
  if (!c->outer_active) {
    conn_proxy_consume(c, data, len);
    return;
  }
  ssl_pump_feed_ciphertext(&c->outer, data, len);
  U8 tmp[2048];
  int m;
  while ((m = ssl_pump_read_plaintext(&c->outer, tmp, sizeof tmp)) > 0)
    conn_proxy_consume(c, tmp, (U64)m);
}

// Outer TLS to the proxy is up: send the CONNECT as plaintext through it.
internal void conn_proxy_send_connect_https(Connection *c) {
  Temp scr = scratch_begin(0, 0);
  String8 req = proxy_http_connect_request(scr.arena, &c->proxy,
                                           str8_cstring(c->host), c->port);
  U64 off = 0;
  while (off < req.size) {
    int w = ssl_pump_write_plaintext(&c->outer, req.str + off, req.size - off);
    if (w > 0)
      off += (U64)w;
    else
      break;
  }
  scratch_end(scr);
  conn_proxy_outer_flush(c);
  c->nlen = 0;
  c->proxy_phase = ProxyPhase_HttpConnect;
  c->state = ConnState_ProxyNegotiate;
}

internal void conn_proxy_outer_drive(Connection *c) {
  HsStatus st = ssl_pump_do_handshake(&c->outer);
  conn_proxy_outer_flush(c);  // push the proxy ClientHello / handshake records
  if (st == HsStatus_Done)
    conn_proxy_send_connect_https(c);
  else if (st == HsStatus_Error)
    conn_fail(c, "proxy TLS handshake failed");
  // WantIo: await more outer ciphertext via conn_read_cb.
}

// Kick off the tunnel negotiation right after the TCP connect to the proxy.
internal void conn_proxy_begin(Connection *c) {
  c->nlen = 0;
  if (c->proxy.type == ProxyType_Socks5) {
    U8 buf[8];
    U64 m = proxy_socks5_greeting(&c->proxy, buf, sizeof buf);
    c->proxy_phase = ProxyPhase_Socks5Greeting;
    c->state = ConnState_ProxyNegotiate;
    conn_raw_write(c, buf, m);
    return;
  }
  if (c->proxy.type == ProxyType_Https) {
    if (!c->proxy_ctx || !c->proxy_profile) {
      conn_fail(c, "HTTPS proxy has no TLS context");
      return;
    }
    ssl_pump_init(&c->outer, c->proxy_ctx);
    if (!ssl_pump_valid(&c->outer)) {
      conn_fail(c, "proxy SSL_new failed");
      return;
    }
    if (!ssl_pump_configure(&c->outer, c->proxy_profile, c->proxy.host, 0, 0, 0,
                            0)) {
      conn_fail(c, "proxy configure_ssl failed");
      return;
    }
    c->outer_active = 1;
    c->state = ConnState_ProxyTls;
    conn_proxy_outer_drive(c);  // sends the ClientHello to the proxy
    return;
  }
  // ProxyType_Http: plaintext CONNECT.
  Temp scr = scratch_begin(0, 0);
  String8 req = proxy_http_connect_request(scr.arena, &c->proxy,
                                           str8_cstring(c->host), c->port);
  c->proxy_phase = ProxyPhase_HttpConnect;
  c->state = ConnState_ProxyNegotiate;
  conn_raw_write(c, req.str, req.size);
  scratch_end(scr);
}

//- public API

void conn_init(Connection *c, EventLoop *loop, SSL_CTX *ctx,
               const TlsProfile *profile) {
  MemoryZeroStruct(c);
  c->loop = loop;
  c->ctx = ctx;
  c->profile = profile;
  ssl_pump_init(&c->pump, ctx);
  conn_egress_init(c);
}

void conn_cleanup(Connection *c) {
  if (c->resume_session) {  // drop the ref taken in conn_set_resume
    SSL_SESSION_free(c->resume_session);
    c->resume_session = 0;
  }
  if (c->egress) {
    // All write callbacks have run by now (uv completes them before the close
    // callback that leads here), so no block is still in flight.
    ra_aligned_free(c->egress);
    c->egress = 0;
  }
  if (c->pending) {
    free(c->pending);
    c->pending = 0;
  }
  if (ssl_pump_valid(&c->outer)) ssl_pump_cleanup(&c->outer);  // HTTPS proxy
  if (c->proxy_ctx) {  // drop the ref taken in conn_set_proxy
    SSL_CTX_free(c->proxy_ctx);
    c->proxy_ctx = 0;
  }
  ssl_pump_cleanup(&c->pump);
}

void conn_connect(Connection *c, const char *host, U16 port,
                  ConnReadyFn on_ready, void *user) {
  c->on_ready = on_ready;
  c->ready_user = user;
  c->port = port;
  strip_host(c->host, sizeof c->host, host);
  // When proxied, the socket goes to the PROXY; the target host stays in
  // c->host for SNI + the CONNECT/SOCKS request. resolve_host is what we DNS +
  // connect.
  B32 proxying = c->proxy.type != ProxyType_None;
  strip_host(c->resolve_host, sizeof c->resolve_host,
             proxying ? c->proxy.host : host);
  U16 rport = proxying ? c->proxy.port : port;

  // Create the TCP handle up front so EVERY failure path (TLS config, DNS,
  // connect) has a handle to close — conn_close then always reaches
  // on_fully_closed, so the owner's arena is freed exactly once (no leak on a
  // failed resolve / connect).
  uv_tcp_init(loop_uv(c->loop), &c->tcp);
  c->tcp_inited = 1;
  c->tcp.data = c;
  uv_tcp_nodelay(&c->tcp, 1);

  if (!ssl_pump_valid(&c->pump)) {
    conn_deliver_ready(c, 0, "SSL_new failed");
    return;
  }
  if (!ssl_pump_configure(&c->pump, c->profile, c->host, c->ech_config,
                          c->ech_config_len, c->resume_session,
                          c->resume_ctx)) {
    conn_deliver_ready(c, 0, "configure_ssl failed");
    return;
  }
  // 0-RTT: enable early data only if the offered session is 0-RTT-capable. If
  // it is not, want_early_data has no effect and the handshake is a plain
  // (1-RTT or fresh) one — no early-data records, byte-identical to the
  // non-0-RTT path.
  if (c->want_early_data)
    c->want_early_data =
        ssl_pump_enable_early_data(&c->pump, c->resume_session);

  c->t_connect_start_ns =
      uv_hrtime();  // request/connect start (DNS begins next)

  // DNS cache hit -> skip uv_getaddrinfo, connect straight to the cached
  // address.
  if (c->dns_cache) {
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    if (dns_cache_get(c->dns_cache, c->resolve_host, uv_now(loop_uv(c->loop)),
                      &ss, &sl) &&
        // Skip a cached address whose family can't match a bound source IP
        // (binding v4 then connecting v6 fails) — re-resolve with the family
        // hint below instead.
        (!c->has_bind_addr || ss.ss_family == c->bind_addr.ss_family)) {
      dns_sockaddr_set_port(&ss, rport);
      c->t_resolved_ns = uv_hrtime();  // ~0ms DNS on a cache hit
      c->dns_was_cached = 1;
      conn_begin_tcp_connect(c, (struct sockaddr *)&ss);
      return;
    }
  }

  c->state = ConnState_Resolving;
  c->resolver.data = c;
  struct addrinfo hints;
  MemoryZeroStruct(&hints);
  // Constrain resolution to the bound source family so the (first, only-used)
  // address is connect-compatible; AF_UNSPEC otherwise.
  hints.ai_family = c->has_bind_addr ? c->bind_addr.ss_family : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  char portstr[8];
  snprintf(portstr, sizeof portstr, "%u", rport);
  int rc = uv_getaddrinfo(loop_uv(c->loop), &c->resolver, conn_on_resolved,
                          c->resolve_host, portstr, &hints);
  if (rc) conn_fail(c, uv_strerror(rc));
}

void conn_timing_ms(const Connection *c, U64 req_start_ns, U64 *dns_ms,
                    U64 *tcp_ms, U64 *tls_ms) {
  *dns_ms = *tcp_ms = *tls_ms = 0;
  // Not established, or established before this request started (pooled reuse):
  // this request did no connection setup.
  if (!c->t_established_ns || c->t_established_ns <= req_start_ns) return;
  if (c->t_resolved_ns > c->t_connect_start_ns)
    *dns_ms = (c->t_resolved_ns - c->t_connect_start_ns) / 1000000;
  if (c->t_connected_ns > c->t_resolved_ns)
    *tcp_ms = (c->t_connected_ns - c->t_resolved_ns) / 1000000;
  if (c->t_established_ns > c->t_connected_ns)
    *tls_ms = (c->t_established_ns - c->t_connected_ns) / 1000000;
}

B32 conn_send_plaintext(Connection *c, const U8 *data, U64 len) {
  // Allow writes once established, and during the 0-RTT window where SSL_write
  // emits the data as early data (the handshake has not yet completed).
  if (c->state != ConnState_Established && c->state != ConnState_EarlyData)
    return 0;
  // If earlier bytes already overflowed into the pending queue, keep ordering:
  // everything after them also queues, to be flushed as 1-RTT after the
  // handshake.
  if (c->pending_len) {
    conn_pending_append(c, data, len);
    return 1;
  }
  U64 off = 0;
  while (off < len) {
    int n = ssl_pump_write_plaintext(&c->pump, data + off, len - off);
    if (n > 0) {
      off += (U64)n;
    } else if (n == -1) {
      // Would-block: in the 0-RTT window this is the server's early-data limit.
      // Queue the remainder; conn_flush_pending sends it as 1-RTT once
      // established. (On an established conn the mem wbio never blocks.)
      conn_pending_append(c, data + off, len - off);
      break;
    } else {
      return 0;
    }
  }
  conn_flush_output(c);
  return 1;
}

String8 conn_alpn(Connection *c) {
  const U8 *p = 0;
  unsigned n = 0;
  ssl_pump_alpn(&c->pump, &p, &n);
  String8 r;
  r.str = (U8 *)p;
  r.size = (p && n) ? n : 0;
  return r;
}

void conn_close(Connection *c) {
  if (c->tcp_inited && !uv_is_closing((uv_handle_t *)&c->tcp)) {
    uv_read_stop((uv_stream_t *)&c->tcp);
    uv_close((uv_handle_t *)&c->tcp, conn_on_handle_closed);
  }
  c->state = ConnState_Closing;
}
