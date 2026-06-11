// Offline runtime proxy-switching test. One loop hosts a persistent HTTP/2
// loopback origin + TWO counting HTTP-CONNECT proxies; on a single Client we
// rotate direct -> proxyA -> proxyB -> direct and assert each request routed
// through the CURRENT proxy. Run with pooling on AND off — the pooling-on pass is
// the regression guard for pool_evict_all: a switch must NOT reuse a connection
// established through the old proxy. H2 is required because H1 is never pooled.
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <nghttp2/nghttp2.h>
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

global SSL_CTX *g_origin_ctx;
global U16 g_origin_port;
global EventLoop *g_loop;
global B32 g_resp_ok;
global int g_resp_status;
global U64 g_origin_reqs;    // total request streams the origin served
global U64 g_tunnels[2];     // CONNECT tunnels established through proxy A / B

// --- shared helpers ---------------------------------------------------------
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
internal SSL_CTX *make_server_ctx(void) {
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0);
  EVP_PKEY *pkey = 0;
  if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
      EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return 0;
  }
  EVP_PKEY_CTX_free(pctx);
  X509 *x = X509_new();
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), 0);
  X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
  X509_set_pubkey(x, pkey);
  X509_NAME *nm = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                             (const unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(x, nm);
  X509_sign(x, pkey, EVP_sha256());
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_use_certificate(ctx, x);
  SSL_CTX_use_PrivateKey(ctx, pkey);
  X509_free(x);
  EVP_PKEY_free(pkey);
  return ctx;
}
internal U16 listen_ephemeral(EventLoop *loop, uv_tcp_t *srv, uv_connection_cb cb,
                              void *data) {
  uv_tcp_init(loop_uv(loop), srv);
  srv->data = data;
  struct sockaddr_in a;
  uv_ip4_addr("127.0.0.1", 0, &a);
  uv_tcp_bind(srv, (const struct sockaddr *)&a, 0);
  uv_listen((uv_stream_t *)srv, 64, cb);
  struct sockaddr_storage ss;
  int sl = sizeof ss;
  uv_tcp_getsockname(srv, (struct sockaddr *)&ss, &sl);
  return ntohs(((struct sockaddr_in *)&ss)->sin_port);
}

// --- HTTP/2 loopback origin (nghttp2 server, persistent, bodyless 200) -------
internal int srv_alpn_cb(SSL *ssl, const U8 **out, U8 *outlen, const U8 *in,
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
typedef struct OC OC;
struct OC {
  uv_tcp_t tcp;
  SSL *ssl;
  BIO *rb, *wb;
  nghttp2_session *h2;
  B32 inited, closing;
  OC *next;
};
global OC *g_origins;
internal void oc_on_closed(uv_handle_t *h) {
  OC *o = (OC *)h->data;
  if (o->h2) nghttp2_session_del(o->h2);
  SSL_free(o->ssl);
  free(o);
}
internal void oc_close(OC *o) {
  if (o->closing) return;
  o->closing = 1;
  for (OC **pp = &g_origins; *pp; pp = &(*pp)->next)
    if (*pp == o) {
      *pp = o->next;
      break;
    }
  uv_close((uv_handle_t *)&o->tcp, oc_on_closed);
}
internal void oc_flush_tls(OC *o) {
  U8 b[16384];
  int n;
  while ((n = BIO_read(o->wb, b, (int)sizeof b)) > 0) raw_write(&o->tcp, b, (U64)n);
}
internal nghttp2_ssize oc_send_cb(nghttp2_session *s, const U8 *data, size_t len,
                                  int flags, void *user) {
  (void)s;
  (void)flags;
  OC *o = (OC *)user;
  SSL_write(o->ssl, data, len);
  return (nghttp2_ssize)len;
}
internal int oc_on_frame_recv(nghttp2_session *s, const nghttp2_frame *frame,
                              void *user) {
  (void)user;
  if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) &&
      frame->hd.type == NGHTTP2_HEADERS &&
      frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    g_origin_reqs++;
    nghttp2_nv st = {(U8 *)":status", (U8 *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE};
    nghttp2_submit_response2(s, frame->hd.stream_id, &st, 1, 0);
  }
  return 0;
}
internal void oc_h2_init(OC *o) {
  nghttp2_session_callbacks *cbs = 0;
  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_send_callback2(cbs, oc_send_cb);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, oc_on_frame_recv);
  nghttp2_session_server_new(&o->h2, cbs, o);
  nghttp2_session_callbacks_del(cbs);
  nghttp2_settings_entry iv[] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1000}};
  nghttp2_submit_settings(o->h2, NGHTTP2_FLAG_NONE, iv, 1);
  o->inited = 1;
}
internal void oc_drive(OC *o) {
  if (o->closing) return;
  if (!SSL_is_init_finished(o->ssl)) {
    int r = SSL_do_handshake(o->ssl);
    oc_flush_tls(o);
    if (r != 1) {
      int e = SSL_get_error(o->ssl, r);
      if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) oc_close(o);
      return;
    }
  }
  if (!o->inited) oc_h2_init(o);
  U8 b[16384];
  int n;
  while ((n = SSL_read(o->ssl, b, (int)sizeof b)) > 0)
    if (nghttp2_session_mem_recv2(o->h2, b, (size_t)n) < 0) {
      oc_close(o);
      return;
    }
  nghttp2_session_send(o->h2);
  oc_flush_tls(o);
}
internal void oc_read_cb(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
  OC *o = (OC *)s->data;
  if (o->closing) return;
  if (nread < 0) {
    oc_close(o);
    return;
  }
  if (nread > 0) BIO_write(o->rb, buf->base, (int)nread);
  oc_drive(o);
}
internal void origin_on_conn(uv_stream_t *srv, int status) {
  if (status < 0) return;
  OC *o = (OC *)calloc(1, sizeof(OC));
  uv_tcp_init(srv->loop, &o->tcp);
  o->tcp.data = o;
  if (uv_accept(srv, (uv_stream_t *)&o->tcp) != 0) {
    oc_close(o);
    return;
  }
  o->ssl = SSL_new(g_origin_ctx);
  o->rb = BIO_new(BIO_s_mem());
  o->wb = BIO_new(BIO_s_mem());
  SSL_set_bio(o->ssl, o->rb, o->wb);
  SSL_set_accept_state(o->ssl);
  o->next = g_origins;
  g_origins = o;
  uv_read_start((uv_stream_t *)&o->tcp, alloc_cb, oc_read_cb);
}

// --- counting HTTP-CONNECT proxy (raw relay to the origin) -------------------
typedef struct PX PX;
struct PX {
  uv_tcp_t client;
  uv_tcp_t origin;
  uv_connect_t oconn;
  U8 nbuf[1024];
  U64 nlen;
  U64 *counter;  // which proxy's tunnel count to bump
  B32 origin_inited, tunneled, closing;
  int closes;
  PX *next;
};
global PX *g_proxies;
internal void px_freed(uv_handle_t *h) {
  PX *pc = (PX *)h->data;
  if (++pc->closes == (pc->origin_inited ? 2 : 1)) free(pc);
}
internal void px_close(PX *pc) {
  if (pc->closing) return;
  pc->closing = 1;
  for (PX **pp = &g_proxies; *pp; pp = &(*pp)->next)
    if (*pp == pc) {
      *pp = pc->next;
      break;
    }
  uv_close((uv_handle_t *)&pc->client, px_freed);
  if (pc->origin_inited) uv_close((uv_handle_t *)&pc->origin, px_freed);
}
internal void px_client_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf);
internal void px_origin_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
  PX *pc = (PX *)s->data;
  if (pc->closing) return;
  if (nread < 0) {
    px_close(pc);
    return;
  }
  if (nread > 0) raw_write(&pc->client, (const U8 *)buf->base, (U64)nread);
}
internal void px_on_origin_connected(uv_connect_t *req, int status) {
  PX *pc = (PX *)req->data;
  if (pc->closing) return;
  if (status < 0) {
    px_close(pc);
    return;
  }
  static const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
  raw_write(&pc->client, (const U8 *)ok, strlen(ok));
  pc->tunneled = 1;
  pc->nlen = 0;
  uv_read_start((uv_stream_t *)&pc->origin, alloc_cb, px_origin_read);
}
internal void px_client_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
  PX *pc = (PX *)s->data;
  if (pc->closing) return;
  if (nread < 0) {
    px_close(pc);
    return;
  }
  if (nread == 0) return;
  if (pc->tunneled) {  // relay client -> origin verbatim
    raw_write(&pc->origin, (const U8 *)buf->base, (U64)nread);
    return;
  }
  if (pc->nlen + (U64)nread > sizeof pc->nbuf) {
    px_close(pc);
    return;
  }
  MemoryCopy(pc->nbuf + pc->nlen, buf->base, (U64)nread);
  pc->nlen += (U64)nread;
  for (U64 i = 0; i + 4 <= pc->nlen; ++i)
    if (memcmp(pc->nbuf + i, "\r\n\r\n", 4) == 0) {  // got the CONNECT request
      (*pc->counter)++;
      uv_tcp_init(s->loop, &pc->origin);
      pc->origin.data = pc;
      pc->origin_inited = 1;
      pc->oconn.data = pc;
      struct sockaddr_in a;
      uv_ip4_addr("127.0.0.1", g_origin_port, &a);
      if (uv_tcp_connect(&pc->oconn, &pc->origin, (const struct sockaddr *)&a,
                         px_on_origin_connected) != 0)
        px_close(pc);
      return;
    }
}
internal void proxy_on_conn(uv_stream_t *srv, int status) {
  if (status < 0) return;
  PX *pc = (PX *)calloc(1, sizeof(PX));
  pc->counter = (U64 *)srv->data;
  uv_tcp_init(srv->loop, &pc->client);
  pc->client.data = pc;
  if (uv_accept(srv, (uv_stream_t *)&pc->client) != 0) {
    px_close(pc);
    return;
  }
  pc->next = g_proxies;
  g_proxies = pc;
  uv_read_start((uv_stream_t *)&pc->client, alloc_cb, px_client_read);
}

// --- driver -----------------------------------------------------------------
internal void on_resp(void *user, const Response *r) {
  (void)user;
  g_resp_ok = r->ok;
  g_resp_status = r->status;
  uv_stop(loop_uv(g_loop));
}
internal void wd_cb(uv_timer_t *t) {
  (void)t;
  fprintf(stderr, "  [watchdog] timed out\n");
  uv_stop(loop_uv(g_loop));
}
internal B32 do_request(EventLoop *loop, uv_timer_t *wd, Client *c) {
  g_resp_ok = 0;
  g_resp_status = 0;
  char url[64];
  snprintf(url, sizeof url, "https://127.0.0.1:%u/", g_origin_port);
  uv_timer_start(wd, wd_cb, 5000, 0);
  client_get(c, str8_cstring(url), on_resp, 0);
  loop_run(loop);
  uv_timer_stop(wd);
  return g_resp_ok && g_resp_status == 200;
}

internal void run_rotation(B32 pooling) {
  g_origin_reqs = 0;
  g_tunnels[0] = g_tunnels[1] = 0;

  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  uv_tcp_t origin, pa, pb;
  g_origin_port = listen_ephemeral(&loop, &origin, origin_on_conn, 0);
  U16 pa_port = listen_ephemeral(&loop, &pa, proxy_on_conn, &g_tunnels[0]);
  U16 pb_port = listen_ephemeral(&loop, &pb, proxy_on_conn, &g_tunnels[1]);

  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/0);
  client_set_http_version(&c, HttpVersion_H2);  // H2 so the pool is in play
  if (pooling) client_set_max_conns_per_origin(&c, 1);

  uv_timer_t wd;
  uv_timer_init(loop_uv(&loop), &wd);
  uv_unref((uv_handle_t *)&wd);  // never keeps the loop alive

  char a[64], b[64];
  snprintf(a, sizeof a, "http://127.0.0.1:%u", pa_port);
  snprintf(b, sizeof b, "http://127.0.0.1:%u", pb_port);

  // direct -> A -> B -> direct, one request each.
  CHECK(do_request(&loop, &wd, &c));  // direct
  CHECK(client_set_proxy(&c, str8_cstring(a), 0));
  CHECK(do_request(&loop, &wd, &c));  // via A
  CHECK(client_set_proxy(&c, str8_cstring(b), 0));
  CHECK(do_request(&loop, &wd, &c));  // via B
  CHECK(client_set_proxy(&c, str8_lit(""), 0));  // back to direct
  CHECK(do_request(&loop, &wd, &c));  // direct

  // Routing: every request reached the origin; exactly one tunnel through each
  // proxy (the pooling-on case proves the old-proxy conn was NOT reused).
  CHECK(g_origin_reqs == 4);
  CHECK(g_tunnels[0] == 1);
  CHECK(g_tunnels[1] == 1);
  fprintf(stderr, "  [pooling=%d] origin_reqs=%llu tunnels A=%llu B=%llu\n",
          pooling, (unsigned long long)g_origin_reqs,
          (unsigned long long)g_tunnels[0], (unsigned long long)g_tunnels[1]);

  uv_close((uv_handle_t *)&wd, 0);
  client_cleanup(&c);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  while (g_proxies) px_close(g_proxies);
  while (g_origins) oc_close(g_origins);
  uv_close((uv_handle_t *)&origin, 0);
  uv_close((uv_handle_t *)&pa, 0);
  uv_close((uv_handle_t *)&pb, 0);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);
}

int main(void) {
  g_origin_ctx = make_server_ctx();
  if (!g_origin_ctx) {
    fprintf(stderr, "ctx setup failed\n");
    return 1;
  }
  SSL_CTX_set_alpn_select_cb(g_origin_ctx, srv_alpn_cb, 0);

  run_rotation(/*pooling=*/0);
  run_rotation(/*pooling=*/1);

  SSL_CTX_free(g_origin_ctx);
  fprintf(stderr, "[proxy_switch_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
