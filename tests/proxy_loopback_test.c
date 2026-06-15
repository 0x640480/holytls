// Offline end-to-end proxy test. One libuv loop hosts a loopback TLS origin
// (HTTP/1.1) AND an in-process proxy server; a real holytls Client, configured
// with a proxy, fetches the origin through the tunnel. Proves the full path —
// HTTP CONNECT, SOCKS5, and an HTTPS (nested-TLS) proxy, each with and without
// auth — delivers a working request (200) with the target TLS running over the
// tunnel (so the origin's handshake, hence its fingerprint, is unaffected).
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "net/proxy.h"
#include "profile/profile.h"
#include "support/loopback_server.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

global SSL_CTX *g_proxy_ctx;  // outer TLS for the HTTPS proxy
global ProxyType g_proxy_type;
global B32 g_require_auth;
global U16 g_origin_port;
global EventLoop *g_loop;
global B32 g_resp_ok;
global int g_resp_status;

// The shared loopback origin just answers 200 "ok" (HTTP/1.1).
static void ok_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)req;
  (void)user;
  resp->status = 200;
  resp->body = (const U8 *)"ok";
  resp->body_len = 2;
}

// --- in-process proxy server (HTTP CONNECT / SOCKS5 / HTTPS) -----------------
enum {
  PXP_TLS,           // HTTPS proxy: outer TLS handshake (server side)
  PXP_HTTP_CONNECT,  // awaiting "CONNECT host:port"
  PXP_S5_GREET,      // awaiting SOCKS5 greeting
  PXP_S5_AUTH,       // awaiting SOCKS5 user/pass
  PXP_S5_CONNECT,    // awaiting SOCKS5 CONNECT request
  PXP_RELAY,         // tunnel open: pipe client<->origin
};

typedef struct PC PC;
struct PC {
  uv_tcp_t client;
  SSL *ssl;  // outer TLS (HTTPS proxy)
  BIO *rb, *wb;
  B32 tls;
  int phase;
  U8 nbuf[4096];
  U64 nlen;
  uv_tcp_t origin;
  uv_connect_t oconn;
  B32 origin_inited, closing;
  PC *next;
};
global PC *g_proxies;

internal void pc_on_closed(uv_handle_t *h) {
  PC *pc = (PC *)h->data;
  // Both handles share one PC; free only after the second closes.
  if (pc->client.data == (void *)1 && pc->origin.data == (void *)1) {
    if (pc->ssl) SSL_free(pc->ssl);
    free(pc);
  } else {
    h->data = (void *)2;  // mark this handle closed
    if (pc->client.data == (void *)2 && pc->origin.data == (void *)2) {
      if (pc->ssl) SSL_free(pc->ssl);
      free(pc);
    }
  }
}
internal void pc_close(PC *pc) {
  if (pc->closing) return;
  pc->closing = 1;
  for (PC **pp = &g_proxies; *pp; pp = &(*pp)->next)
    if (*pp == pc) {
      *pp = pc->next;
      break;
    }
  if (!uv_is_closing((uv_handle_t *)&pc->client))
    uv_close((uv_handle_t *)&pc->client, pc_on_closed);
  else
    pc->client.data = (void *)2;
  if (pc->origin_inited && !uv_is_closing((uv_handle_t *)&pc->origin))
    uv_close((uv_handle_t *)&pc->origin, pc_on_closed);
  else
    pc->origin.data = (void *)2;
  // If neither handle will deliver a close cb, free now.
  if (pc->client.data == (void *)2 && pc->origin.data == (void *)2) {
    if (pc->ssl) SSL_free(pc->ssl);
    free(pc);
  }
}

// Write to the holytls client (encrypting via the outer TLS for an HTTPS
// proxy).
internal void pc_to_client(PC *pc, const U8 *d, U64 n) {
  if (pc->tls) {
    SSL_write(pc->ssl, d, (int)n);
    U8 b[16384];
    int m;
    while ((m = BIO_read(pc->wb, b, (int)sizeof b)) > 0)
      lb_raw_write(&pc->client, b, (U64)m);
  } else {
    lb_raw_write(&pc->client, d, n);
  }
}

internal void pc_origin_read_cb(uv_stream_t *s, ssize_t nread,
                                const uv_buf_t *buf) {
  PC *pc = (PC *)s->data;
  if (pc->closing) return;
  if (nread < 0) {
    pc_close(pc);
    return;
  }
  if (nread > 0)
    pc_to_client(pc, (const U8 *)buf->base, (U64)nread);  // origin -> client
}

internal B32 pc_creds_ok(String8 user, String8 pass) {
  return str8_match(user, str8_lit("user")) &&
         str8_match(pass, str8_lit("pass"));
}

internal void pc_start_relay(PC *pc) {
  pc->phase = PXP_RELAY;
  uv_read_start((uv_stream_t *)&pc->origin, lb_alloc_cb, pc_origin_read_cb);
}

internal void pc_on_origin_connected(uv_connect_t *req, int status) {
  PC *pc = (PC *)req->data;
  if (pc->closing) return;
  if (status < 0) {
    pc_close(pc);
    return;
  }
  if (g_proxy_type == ProxyType_Socks5) {
    U8 ok[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    pc_to_client(pc, ok, sizeof ok);
  } else {  // HTTP / HTTPS CONNECT
    static const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
    pc_to_client(pc, (const U8 *)ok, strlen(ok));
  }
  pc->nlen = 0;
  pc_start_relay(pc);
}

internal void pc_connect_origin(PC *pc) {
  uv_tcp_init(g_loop ? loop_uv(g_loop) : pc->client.loop, &pc->origin);
  pc->origin.data = pc;
  pc->origin_inited = 1;
  pc->oconn.data = pc;
  struct sockaddr_in a;
  uv_ip4_addr("127.0.0.1", g_origin_port, &a);
  if (uv_tcp_connect(&pc->oconn, &pc->origin, (const struct sockaddr *)&a,
                     pc_on_origin_connected) != 0)
    pc_close(pc);
}

// Run the negotiation parser over the accumulated client bytes (plaintext).
internal void pc_negotiate(PC *pc) {
  if (pc->phase == PXP_HTTP_CONNECT) {
    U64 end = 0;
    for (U64 i = 0; i + 4 <= pc->nlen; ++i)
      if (memcmp(pc->nbuf + i, "\r\n\r\n", 4) == 0) {
        end = i + 4;
        break;
      }
    if (!end) return;
    String8 hdr = str8(pc->nbuf, end);
    if (g_require_auth &&
        !str8_contains(hdr,
                       str8_lit("Proxy-Authorization: Basic dXNlcjpwYXNz"))) {
      static const char *no =
          "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
      pc_to_client(pc, (const U8 *)no, strlen(no));
      pc_close(pc);
      return;
    }
    CHECK(
        str8_starts_with(hdr, str8_lit("CONNECT ")));  // request-target present
    pc_connect_origin(pc);
    return;
  }
  if (pc->phase == PXP_S5_GREET) {
    if (pc->nlen < 2) return;
    U8 nm = pc->nbuf[1];
    if (pc->nlen < (U64)2 + nm) return;
    B32 has_up = 0;
    for (U64 i = 0; i < nm; ++i)
      if (pc->nbuf[2 + i] == 0x02) has_up = 1;
    pc->nlen = 0;
    if (g_require_auth) {
      U8 r[2] = {0x05, has_up ? 0x02 : 0xFF};
      pc_to_client(pc, r, 2);
      if (!has_up) {
        pc_close(pc);
        return;
      }
      pc->phase = PXP_S5_AUTH;
    } else {
      U8 r[2] = {0x05, 0x00};
      pc_to_client(pc, r, 2);
      pc->phase = PXP_S5_CONNECT;
    }
    return;
  }
  if (pc->phase == PXP_S5_AUTH) {
    if (pc->nlen < 2) return;
    U8 ul = pc->nbuf[1];
    if (pc->nlen < (U64)2 + ul + 1) return;
    U8 pl = pc->nbuf[2 + ul];
    if (pc->nlen < (U64)3 + ul + pl) return;
    String8 user = str8(pc->nbuf + 2, ul);
    String8 pass = str8(pc->nbuf + 3 + ul, pl);
    B32 ok = pc_creds_ok(user, pass);
    U8 r[2] = {0x01, ok ? 0x00 : 0x01};
    pc_to_client(pc, r, 2);
    pc->nlen = 0;
    if (!ok) {
      pc_close(pc);
      return;
    }
    pc->phase = PXP_S5_CONNECT;
    return;
  }
  if (pc->phase == PXP_S5_CONNECT) {
    if (pc->nlen < 5) return;
    if (pc->nbuf[3] != 0x03) {  // expect ATYP=DOMAINNAME
      pc_close(pc);
      return;
    }
    U8 dl = pc->nbuf[4];
    if (pc->nlen < (U64)5 + dl + 2) return;
    pc->nlen = 0;
    pc_connect_origin(pc);  // origin port is fixed (the test target)
    return;
  }
}

// Plaintext bytes from the client (already outer-decrypted for an HTTPS proxy).
internal void pc_consume(PC *pc, const U8 *d, U64 n) {
  if (pc->phase == PXP_RELAY) {  // tunnel: forward to the origin verbatim
    lb_raw_write(&pc->origin, d, n);
    return;
  }
  if (pc->nlen + n > sizeof pc->nbuf) {
    pc_close(pc);
    return;
  }
  MemoryCopy(pc->nbuf + pc->nlen, d, n);
  pc->nlen += n;
  pc_negotiate(pc);
}

internal void pc_client_read_cb(uv_stream_t *s, ssize_t nread,
                                const uv_buf_t *buf) {
  PC *pc = (PC *)s->data;
  if (pc->closing) return;
  if (nread < 0) {
    pc_close(pc);
    return;
  }
  if (nread == 0) return;
  const U8 *d = (const U8 *)buf->base;
  U64 n = (U64)nread;
  if (!pc->tls) {
    pc_consume(pc, d, n);
    return;
  }
  // HTTPS proxy: drive the outer (server) TLS, then surface plaintext.
  BIO_write(pc->rb, d, (int)n);
  if (!SSL_is_init_finished(pc->ssl)) {
    int r = SSL_do_handshake(pc->ssl);
    U8 b[16384];
    int m;
    while ((m = BIO_read(pc->wb, b, (int)sizeof b)) > 0)
      lb_raw_write(&pc->client, b, (U64)m);
    if (r != 1) {
      int e = SSL_get_error(pc->ssl, r);
      if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) pc_close(pc);
      return;
    }
    pc->phase = PXP_HTTP_CONNECT;
  }
  U8 b[16384];
  int m;
  while ((m = SSL_read(pc->ssl, b, (int)sizeof b)) > 0)
    pc_consume(pc, b, (U64)m);
}

internal void proxy_on_conn(uv_stream_t *srv, int status) {
  if (status < 0) return;
  PC *pc = (PC *)calloc(1, sizeof(PC));
  uv_tcp_init(srv->loop, &pc->client);
  pc->client.data = pc;
  if (uv_accept(srv, (uv_stream_t *)&pc->client) != 0) {
    pc_close(pc);
    return;
  }
  pc->next = g_proxies;
  g_proxies = pc;
  if (g_proxy_type == ProxyType_Https) {
    pc->tls = 1;
    pc->ssl = SSL_new(g_proxy_ctx);
    pc->rb = BIO_new(BIO_s_mem());
    pc->wb = BIO_new(BIO_s_mem());
    SSL_set_bio(pc->ssl, pc->rb, pc->wb);
    SSL_set_accept_state(pc->ssl);
    pc->phase = PXP_TLS;
  } else if (g_proxy_type == ProxyType_Socks5) {
    pc->phase = PXP_S5_GREET;
  } else {
    pc->phase = PXP_HTTP_CONNECT;
  }
  uv_read_start((uv_stream_t *)&pc->client, lb_alloc_cb, pc_client_read_cb);
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
internal B32 run_scenario(const char *name, ProxyType type, B32 auth) {
  g_proxy_type = type;
  g_require_auth = auth;
  g_resp_ok = 0;
  g_resp_status = 0;

  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;

  uv_tcp_t proxy;
  LbServer *origin_srv =
      lb_server_start(&loop, LB_ALPN_H1, ok_handler, 0, &g_origin_port);
  U16 pport = lb_listen(&loop, &proxy, proxy_on_conn, 0);

  Client c;
  client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/0);
  client_set_http_version(&c, HttpVersion_H1);
  const char *scheme = type == ProxyType_Http    ? "http"
                       : type == ProxyType_Https ? "https"
                                                 : "socks5";
  char purl[128];
  if (auth)
    snprintf(purl, sizeof purl, "%s://user:pass@127.0.0.1:%u", scheme, pport);
  else
    snprintf(purl, sizeof purl, "%s://127.0.0.1:%u", scheme, pport);
  CHECK(client_set_proxy(&c, str8_cstring(purl), /*verify_proxy=*/0));

  char ourl[64];
  snprintf(ourl, sizeof ourl, "https://127.0.0.1:%u/", g_origin_port);

  uv_timer_t wd;
  uv_timer_init(loop_uv(&loop), &wd);
  uv_timer_start(&wd, wd_cb, 5000, 0);

  client_get(&c, str8_cstring(ourl), on_resp, 0);
  loop_run(&loop);

  uv_timer_stop(&wd);
  uv_close((uv_handle_t *)&wd, 0);
  client_cleanup(&c);
  for (int g = 0; g < 200 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  while (g_proxies) pc_close(g_proxies);
  lb_server_stop(origin_srv);
  uv_close((uv_handle_t *)&proxy, 0);
  for (int g = 0; g < 200 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);

  B32 ok = g_resp_ok && g_resp_status == 200;
  fprintf(stderr, "  [%s] ok=%d status=%d -> %s\n", name, g_resp_ok,
          g_resp_status, ok ? "PASS" : "FAIL");
  return ok;
}

int main(void) {
  g_proxy_ctx = lb_server_ctx(LB_ALPN_H1);
  if (!g_proxy_ctx) {
    fprintf(stderr, "ctx setup failed\n");
    return 1;
  }

  CHECK(run_scenario("http", ProxyType_Http, 0));
  CHECK(run_scenario("http+auth", ProxyType_Http, 1));
  CHECK(run_scenario("socks5", ProxyType_Socks5, 0));
  CHECK(run_scenario("socks5+auth", ProxyType_Socks5, 1));
  CHECK(run_scenario("https", ProxyType_Https, 0));
  CHECK(run_scenario("https+auth", ProxyType_Https, 1));

  SSL_CTX_free(g_proxy_ctx);
  fprintf(stderr, "[proxy_loopback_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
