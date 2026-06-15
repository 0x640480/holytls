// Offline runtime proxy-switching test. One loop hosts a persistent HTTP/2
// loopback origin (tests/support) + TWO counting HTTP-CONNECT proxies; on a
// single Client we rotate direct -> proxyA -> proxyB -> direct and assert each
// request routed through the CURRENT proxy. Run with pooling on AND off — the
// pooling-on pass is the regression guard for pool_evict_all: a switch must NOT
// reuse a connection established through the old proxy. H2 is required because
// H1 is never pooled.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"
#include "support/loopback_server.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

global U16 g_origin_port;
global EventLoop *g_loop;
global B32 g_resp_ok;
global int g_resp_status;
global U64 g_origin_reqs;  // total request streams the origin served
global U64 g_tunnels[2];   // CONNECT tunnels established through proxy A / B

// The shared origin just counts requests and answers 200.
static void origin_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)req;
  (void)user;
  g_origin_reqs++;
  resp->status = 200;
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
internal void px_client_read(uv_stream_t *s, ssize_t nread,
                             const uv_buf_t *buf);
internal void px_origin_read(uv_stream_t *s, ssize_t nread,
                             const uv_buf_t *buf) {
  PX *pc = (PX *)s->data;
  if (pc->closing) return;
  if (nread < 0) {
    px_close(pc);
    return;
  }
  if (nread > 0) lb_raw_write(&pc->client, (const U8 *)buf->base, (U64)nread);
}
internal void px_on_origin_connected(uv_connect_t *req, int status) {
  PX *pc = (PX *)req->data;
  if (pc->closing) return;
  if (status < 0) {
    px_close(pc);
    return;
  }
  static const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
  lb_raw_write(&pc->client, (const U8 *)ok, strlen(ok));
  pc->tunneled = 1;
  pc->nlen = 0;
  uv_read_start((uv_stream_t *)&pc->origin, lb_alloc_cb, px_origin_read);
}
internal void px_client_read(uv_stream_t *s, ssize_t nread,
                             const uv_buf_t *buf) {
  PX *pc = (PX *)s->data;
  if (pc->closing) return;
  if (nread < 0) {
    px_close(pc);
    return;
  }
  if (nread == 0) return;
  if (pc->tunneled) {  // relay client -> origin verbatim
    lb_raw_write(&pc->origin, (const U8 *)buf->base, (U64)nread);
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
  uv_read_start((uv_stream_t *)&pc->client, lb_alloc_cb, px_client_read);
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
  uv_tcp_t pa, pb;
  LbServer *origin =
      lb_server_start(&loop, LB_ALPN_H2, origin_handler, 0, &g_origin_port);
  U16 pa_port = lb_listen(&loop, &pa, proxy_on_conn, &g_tunnels[0]);
  U16 pb_port = lb_listen(&loop, &pb, proxy_on_conn, &g_tunnels[1]);

  Client c;
  client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/0);
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
  CHECK(do_request(&loop, &wd, &c));             // via B
  CHECK(client_set_proxy(&c, str8_lit(""), 0));  // back to direct
  CHECK(do_request(&loop, &wd, &c));             // direct

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
  lb_server_stop(origin);
  uv_close((uv_handle_t *)&pa, 0);
  uv_close((uv_handle_t *)&pb, 0);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);
}

int main(void) {
  run_rotation(/*pooling=*/0);
  run_rotation(/*pooling=*/1);
  fprintf(stderr, "[proxy_switch_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
