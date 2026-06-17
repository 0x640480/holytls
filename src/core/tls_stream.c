#include "core/tls_stream.h"

#include <uv.h>

#include "base/arena.h"
#include "net/connection.h"
#include "net/loop.h"

// A raw TLS byte stream: an embedded Connection driven blocking-style, mirroring
// WsConn (ws/ws.c) minus the RFC 6455 codec. Each public call runs the loop
// until its event; callbacks set a flag + loop_stop (tls_wake) to unblock.
struct TlsStream {
  Arena *arena;     // owns this stream's allocations
  Client *client;   // borrowed: loop / profile / SSL_CTX
  EventLoop *loop;  // borrowed (== client->loop)
  Connection conn;  // embedded TCP+TLS connection
  TlsProfile tls;   // client's profile->tls with ALPN + ALPS cleared (no ALPN)
  B32 conn_inited;
  B32 established;
  B32 closed;
  B32 fail;
  B32 fully_closed;
  B32 timed_out;
  const char *err;
};

internal void tls_wake(TlsStream *s) { loop_stop(s->loop); }

// Fires when decrypted plaintext is available — just wake; tls_stream_read drains
// it via conn_read_plaintext (no separate buffer needed).
internal void tls_on_readable(void *user) { tls_wake((TlsStream *)user); }

internal void tls_on_ready(void *user, B32 ok, const char *err) {
  TlsStream *s = (TlsStream *)user;
  if (!ok) {
    s->fail = 1;
    if (!s->err) s->err = err ? err : "connect failed";
  } else {
    conn_on_readable(&s->conn, tls_on_readable, s);
    s->established = 1;
  }
  tls_wake(s);
}

internal void tls_on_closed(void *user, const char *err) {
  TlsStream *s = (TlsStream *)user;
  if (!s->err && err) s->err = err;  // err == 0 is a clean EOF
  s->closed = 1;
  tls_wake(s);
}

internal void tls_on_fully_closed(void *user) {
  TlsStream *s = (TlsStream *)user;
  s->fully_closed = 1;
  tls_wake(s);
}

internal void tls_on_connect_timeout(void *user) {
  TlsStream *s = (TlsStream *)user;
  if (!s->established) {
    s->fail = 1;
    s->err = "timeout";
    tls_wake(s);
  }
}

internal void tls_on_recv_timeout(void *user) {
  TlsStream *s = (TlsStream *)user;
  s->timed_out = 1;
  tls_wake(s);
}

TlsStream *tls_stream_connect(Client *client, String8 host, U16 port,
                              U64 timeout_ms) {
  Arena *a = arena_alloc();
  TlsStream *s = push_struct(a, TlsStream);
  s->arena = a;
  s->client = client;
  s->loop = client->loop;
  // Raw byte stream: keep the client's TLS knobs (ciphers/curves/extensions =
  // the fingerprint) but advertise NO ALPN and drop ALPS (an h2-only extension)
  // — what a mail client sends. ALPN is applied per-SSL, so this is just a value
  // copy over the shared SSL_CTX.
  s->tls = client->profile->tls;
  s->tls.alpn_wire = 0;
  s->tls.alpn_wire_len = 0;
  s->tls.alps_count = 0;
  conn_init(&s->conn, client->loop, client->ctx.ctx, &s->tls);
  s->conn_inited = 1;
  conn_on_closed(&s->conn, tls_on_closed, s);
  conn_on_fully_closed(&s->conn, tls_on_fully_closed, s);
  conn_set_dns_cache(&s->conn, &client->dns_cache);

  U64 t = timeout_ms ? timeout_ms : client_get_timeout_ms(client);
  ReqTimer *timer = req_timer_arm(
      s->loop, t ? uv_hrtime() + t * 1000000ull : 0, tls_on_connect_timeout, s);
  conn_connect(&s->conn, push_str8_cstr(a, host), port, tls_on_ready, s);
  while (!s->established && !s->fail && !s->closed) loop_run(s->loop);
  req_timer_disarm(timer);
  if (!s->established && !s->err) s->err = "tls connect failed";
  return s;
}

B32 tls_stream_write(TlsStream *s, const U8 *data, U64 len) {
  if (s->fail || s->closed || !s->established) return 0;
  return conn_send_plaintext(&s->conn, data, len);
}

int tls_stream_read(TlsStream *s, U8 *buf, U64 cap, U64 timeout_ms) {
  if (!s->established && !s->closed && !s->fail) return -1;
  if (cap == 0) return 0;
  s->timed_out = 0;
  ReqTimer *t = timeout_ms ? req_timer_arm(s->loop,
                                           uv_hrtime() + timeout_ms * 1000000ull,
                                           tls_on_recv_timeout, s)
                           : 0;
  int rc;
  for (;;) {
    // Drain any already-decrypted plaintext first (a prior record SSL still
    // holds), then block. conn_read_plaintext: >0 bytes, -1 want-IO, -2 closed.
    int n = conn_read_plaintext(&s->conn, buf, cap);
    if (n > 0) {
      rc = n;
      break;
    }
    if (n == -2 || s->closed || s->fail) {
      rc = s->err ? -1 : 0;  // error vs clean close (peer EOF / close_notify)
      break;
    }
    if (s->timed_out) {
      rc = -2;  // deadline elapsed; the stream is still usable
      break;
    }
    loop_run(s->loop);  // block until data / close / the deadline wakes us
  }
  req_timer_disarm(t);
  return rc;
}

void tls_stream_free(TlsStream *s) {
  if (!s) return;
  if (s->conn_inited) {
    conn_close(&s->conn);
    // Drain the close so on_fully_closed fires before we free the SSL/BIOs.
    s->fully_closed = 0;
    while (!s->fully_closed && uv_loop_alive(loop_uv(s->loop)))
      loop_run(s->loop);
    conn_cleanup(&s->conn);
  }
  arena_release(s->arena);
}

const char *tls_stream_error(TlsStream *s) { return s ? s->err : "null stream"; }
