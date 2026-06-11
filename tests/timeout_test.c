// Offline request-timeout tests. An in-process HTTP/2 loopback origin that, by
// request path, either answers 200 immediately ("/fast"), redirects 302 to /slow
// ("/redir"), or NEVER answers ("/slow"). With a short client timeout we assert:
//   - a hung non-pooled request fails once with "timeout", within ~the budget;
//   - a fast request with a generous timeout succeeds (no spurious timeout);
//   - a pooled request that times out is cancelled per-stream — its connection
//     survives and a later request reuses it (conns_created stays 1);
//   - the timeout spans a redirect chain (a redirect to /slow still times out).
#include <nghttp2/nghttp2.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

global SSL_CTX *g_ctx;
global U16 g_port;
global char g_slow_url[64];  // https://127.0.0.1:<port>/slow (for redirect Location)
global EventLoop *g_loop;

// --- HTTP/2 loopback origin (slow / fast / redirect by path) ----------------
typedef struct WR {
  uv_write_t req;
  uv_buf_t buf;
} WR;
internal void on_wr(uv_write_t *r, int st) {
  (void)st;
  free(r);
}
internal void raw_write(uv_tcp_t *t, const U8 *d, U64 n) {
  if (n == 0 || uv_is_closing((uv_handle_t *)t)) return;
  WR *w = (WR *)malloc(sizeof(WR) + n);
  U8 *p = (U8 *)(w + 1);
  MemoryCopy(p, d, n);
  w->buf = uv_buf_init((char *)p, (unsigned)n);
  uv_write(&w->req, (uv_stream_t *)t, &w->buf, 1, on_wr);
}
internal void alloc_cb(uv_handle_t *h, size_t s, uv_buf_t *b) {
  (void)h;
  (void)s;
  static thread_local U8 storage[65536];
  b->base = (char *)storage;
  b->len = sizeof storage;
}
internal int alpn_cb(SSL *ssl, const U8 **out, U8 *outlen, const U8 *in,
                     unsigned inlen, void *arg) {
  (void)ssl;
  (void)in;
  (void)inlen;
  (void)arg;
  static const U8 h2[] = {'h', '2'};
  *out = h2;
  *outlen = 2;
  return SSL_TLSEXT_ERR_OK;
}

enum { PATH_FAST, PATH_SLOW, PATH_REDIR };  // stored AS the stream user_data ptr

typedef struct SC SC;
struct SC {
  uv_tcp_t tcp;
  SSL *ssl;
  BIO *rb, *wb;
  nghttp2_session *h2;
  B32 inited, closing;
  SC *next;
};
global SC *g_conns;

internal void sc_on_closed(uv_handle_t *h) {
  SC *c = (SC *)h->data;
  if (c->h2) nghttp2_session_del(c->h2);
  SSL_free(c->ssl);
  free(c);
}
internal void sc_close(SC *c) {
  if (c->closing) return;
  c->closing = 1;
  for (SC **pp = &g_conns; *pp; pp = &(*pp)->next)
    if (*pp == c) {
      *pp = c->next;
      break;
    }
  uv_close((uv_handle_t *)&c->tcp, sc_on_closed);
}
internal void sc_flush(SC *c) {
  U8 b[16384];
  int n;
  while ((n = BIO_read(c->wb, b, (int)sizeof b)) > 0) raw_write(&c->tcp, b, (U64)n);
}
internal nghttp2_ssize sc_send(nghttp2_session *s, const U8 *data, size_t len,
                               int flags, void *user) {
  (void)s;
  (void)flags;
  SC *c = (SC *)user;
  SSL_write(c->ssl, data, len);
  return (nghttp2_ssize)len;
}
internal int sc_on_header(nghttp2_session *s, const nghttp2_frame *frame,
                          const U8 *name, size_t namelen, const U8 *value,
                          size_t valuelen, U8 flags, void *user) {
  (void)flags;
  (void)user;
  if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
    String8 path = str8((U8 *)value, valuelen);
    int kind = str8_contains(path, str8_lit("slow"))    ? PATH_SLOW
               : str8_contains(path, str8_lit("redir")) ? PATH_REDIR
                                                        : PATH_FAST;
    nghttp2_session_set_stream_user_data(s, frame->hd.stream_id,
                                         (void *)(uintptr_t)kind);
  }
  return 0;
}
internal int sc_on_frame_recv(nghttp2_session *s, const nghttp2_frame *frame,
                              void *user) {
  (void)user;
  if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) ||
      frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    return 0;
  int kind = (int)(uintptr_t)nghttp2_session_get_stream_user_data(
      s, frame->hd.stream_id);
  if (kind == PATH_SLOW) return 0;  // withhold the response forever
  if (kind == PATH_REDIR) {
    nghttp2_nv nv[] = {
        {(U8 *)":status", (U8 *)"302", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(U8 *)"location", (U8 *)g_slow_url, 8, strlen(g_slow_url),
         NGHTTP2_NV_FLAG_NONE},
    };
    nghttp2_submit_response2(s, frame->hd.stream_id, nv, 2, 0);
  } else {
    nghttp2_nv ok = {(U8 *)":status", (U8 *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE};
    nghttp2_submit_response2(s, frame->hd.stream_id, &ok, 1, 0);
  }
  return 0;
}
internal void sc_h2_init(SC *c) {
  nghttp2_session_callbacks *cbs = 0;
  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_send_callback2(cbs, sc_send);
  nghttp2_session_callbacks_set_on_header_callback(cbs, sc_on_header);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, sc_on_frame_recv);
  nghttp2_session_server_new(&c->h2, cbs, c);
  nghttp2_session_callbacks_del(cbs);
  nghttp2_settings_entry iv[] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  nghttp2_submit_settings(c->h2, NGHTTP2_FLAG_NONE, iv, 1);
  c->inited = 1;
}
internal void sc_drive(SC *c) {
  if (c->closing) return;
  if (!SSL_is_init_finished(c->ssl)) {
    int r = SSL_do_handshake(c->ssl);
    sc_flush(c);
    if (r != 1) {
      int e = SSL_get_error(c->ssl, r);
      if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) sc_close(c);
      return;
    }
  }
  if (!c->inited) sc_h2_init(c);
  U8 b[16384];
  int n;
  while ((n = SSL_read(c->ssl, b, (int)sizeof b)) > 0)
    if (nghttp2_session_mem_recv2(c->h2, b, (size_t)n) < 0) {
      sc_close(c);
      return;
    }
  nghttp2_session_send(c->h2);
  sc_flush(c);
}
internal void sc_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
  SC *c = (SC *)s->data;
  if (c->closing) return;
  if (nread < 0) {
    sc_close(c);
    return;
  }
  if (nread > 0) BIO_write(c->rb, buf->base, (int)nread);
  sc_drive(c);
}
internal void on_conn(uv_stream_t *srv, int status) {
  if (status < 0) return;
  SC *c = (SC *)calloc(1, sizeof(SC));
  uv_tcp_init(srv->loop, &c->tcp);
  c->tcp.data = c;
  if (uv_accept(srv, (uv_stream_t *)&c->tcp) != 0) {
    sc_close(c);
    return;
  }
  c->ssl = SSL_new(g_ctx);
  c->rb = BIO_new(BIO_s_mem());
  c->wb = BIO_new(BIO_s_mem());
  SSL_set_bio(c->ssl, c->rb, c->wb);
  SSL_set_accept_state(c->ssl);
  c->next = g_conns;
  g_conns = c;
  uv_read_start((uv_stream_t *)&c->tcp, alloc_cb, sc_read);
}
internal SSL_CTX *make_ctx(void) {
  EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0);
  EVP_PKEY *pk = 0;
  if (!pc || EVP_PKEY_keygen_init(pc) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pc, NID_X9_62_prime256v1) <= 0 ||
      EVP_PKEY_keygen(pc, &pk) <= 0) {
    if (pc) EVP_PKEY_CTX_free(pc);
    return 0;
  }
  EVP_PKEY_CTX_free(pc);
  X509 *x = X509_new();
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), 0);
  X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
  X509_set_pubkey(x, pk);
  X509_NAME *nm = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                             (const unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(x, nm);
  X509_sign(x, pk, EVP_sha256());
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_use_certificate(ctx, x);
  SSL_CTX_use_PrivateKey(ctx, pk);
  SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, 0);
  X509_free(x);
  EVP_PKEY_free(pk);
  return ctx;
}

// --- driver -----------------------------------------------------------------
typedef struct RC {
  int calls;
  B32 ok;
  int status;
  char err[64];
  U64 t0, elapsed_ms;
} RC;
internal void on_resp(void *user, const Response *r) {
  RC *rc = (RC *)user;
  rc->calls++;
  rc->ok = r->ok;
  rc->status = r->status;
  rc->elapsed_ms = (uv_hrtime() - rc->t0) / 1000000;
  rc->err[0] = 0;
  if (r->error) snprintf(rc->err, sizeof rc->err, "%s", r->error);
  uv_stop(loop_uv(g_loop));
}
internal void wd_cb(uv_timer_t *t) {
  (void)t;
  fprintf(stderr, "  [watchdog] timed out\n");
  uv_stop(loop_uv(g_loop));
}
internal RC do_get(EventLoop *loop, uv_timer_t *wd, Client *c, const char *url) {
  RC rc;
  MemoryZeroStruct(&rc);
  rc.t0 = uv_hrtime();
  uv_timer_start(wd, wd_cb, 8000, 0);  // safety net well above any test budget
  client_get(c, str8_cstring(url), on_resp, &rc);
  loop_run(loop);
  uv_timer_stop(wd);
  return rc;
}

internal uv_timer_t g_wd;
internal void setup(EventLoop *loop, uv_tcp_t *srv) {
  uv_tcp_init(loop_uv(loop), srv);
  struct sockaddr_in a;
  uv_ip4_addr("127.0.0.1", 0, &a);
  uv_tcp_bind(srv, (const struct sockaddr *)&a, 0);
  uv_listen((uv_stream_t *)srv, 16, on_conn);
  struct sockaddr_storage ss;
  int sl = sizeof ss;
  uv_tcp_getsockname(srv, (struct sockaddr *)&ss, &sl);
  g_port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
  snprintf(g_slow_url, sizeof g_slow_url, "https://127.0.0.1:%u/slow", g_port);
}

int main(void) {
  g_ctx = make_ctx();
  if (!g_ctx) {
    fprintf(stderr, "ctx failed\n");
    return 1;
  }
  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  uv_tcp_t srv;
  setup(&loop, &srv);
  uv_timer_init(loop_uv(&loop), &g_wd);
  uv_unref((uv_handle_t *)&g_wd);

  char fast[64], redir[64];
  snprintf(fast, sizeof fast, "https://127.0.0.1:%u/fast", g_port);
  snprintf(redir, sizeof redir, "https://127.0.0.1:%u/redir", g_port);

  // 1) Non-pooled hung request -> times out once, ~within the budget.
  {
    Client c;
    client_init(&c, &loop, profile_chrome148(), 0);
    client_set_http_version(&c, HttpVersion_H2);
    client_set_timeout_ms(&c, 400);
    RC rc = do_get(&loop, &g_wd, &c, g_slow_url);
    fprintf(stderr, "  [non-pooled slow] calls=%d ok=%d err=%s elapsed=%llums\n",
            rc.calls, rc.ok, rc.err, (unsigned long long)rc.elapsed_ms);
    CHECK(rc.calls == 1 && !rc.ok && strcmp(rc.err, "timeout") == 0);
    CHECK(rc.elapsed_ms >= 350 && rc.elapsed_ms < 2000);  // ~the budget, not 8s
    client_cleanup(&c);
  }

  // 2) Fast request with a generous timeout -> success, no spurious timeout.
  {
    Client c;
    client_init(&c, &loop, profile_chrome148(), 0);
    client_set_http_version(&c, HttpVersion_H2);
    client_set_timeout_ms(&c, 3000);
    RC rc = do_get(&loop, &g_wd, &c, fast);
    fprintf(stderr, "  [fast] calls=%d ok=%d status=%d elapsed=%llums\n",
            rc.calls, rc.ok, rc.status, (unsigned long long)rc.elapsed_ms);
    CHECK(rc.calls == 1 && rc.ok && rc.status == 200 && rc.elapsed_ms < 1500);
    client_cleanup(&c);
  }

  // 3) Pooled: a timed-out request is cancelled per-stream; the connection
  //    survives, so a later request reuses it (only one conn ever created).
  {
    Client c;
    client_init(&c, &loop, profile_chrome148(), 0);
    client_set_http_version(&c, HttpVersion_H2);
    client_set_max_conns_per_origin(&c, 1);
    client_set_timeout_ms(&c, 400);
    RC slow = do_get(&loop, &g_wd, &c, g_slow_url);
    CHECK(slow.calls == 1 && !slow.ok && strcmp(slow.err, "timeout") == 0);
    RC ok = do_get(&loop, &g_wd, &c, fast);  // reuse the same pooled conn
    PoolStats ps = client_pool_stats(&c);
    fprintf(stderr,
            "  [pooled] slow_err=%s fast_ok=%d conns_created=%llu reuses=%llu\n",
            slow.err, ok.ok, (unsigned long long)ps.conns_created,
            (unsigned long long)ps.reuses);
    CHECK(ok.calls == 1 && ok.ok && ok.status == 200);
    CHECK(ps.conns_created == 1);  // the cancel did NOT kill the connection
    client_cleanup(&c);
  }

  // 4) The timeout spans a redirect: /redir -> 302 -> /slow still times out.
  {
    Client c;
    client_init(&c, &loop, profile_chrome148(), 0);
    client_set_http_version(&c, HttpVersion_H2);
    client_set_max_redirects(&c, 5);
    client_set_timeout_ms(&c, 500);
    RC rc = do_get(&loop, &g_wd, &c, redir);
    fprintf(stderr, "  [redirect->slow] calls=%d ok=%d err=%s elapsed=%llums\n",
            rc.calls, rc.ok, rc.err, (unsigned long long)rc.elapsed_ms);
    CHECK(rc.calls == 1 && !rc.ok && strcmp(rc.err, "timeout") == 0);
    CHECK(rc.elapsed_ms < 2500);  // bounded by the deadline despite the hop
    client_cleanup(&c);
  }

  // teardown
  uv_close((uv_handle_t *)&g_wd, 0);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  while (g_conns) sc_close(g_conns);
  uv_close((uv_handle_t *)&srv, 0);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);
  SSL_CTX_free(g_ctx);
  fprintf(stderr, "[timeout_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
