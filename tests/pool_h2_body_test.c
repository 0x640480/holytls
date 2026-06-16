// Functional pooled-H2 large-body test over the in-process H2 loopback origin
// (which echoes the request body). Complements h2_arena_test (the flat-arena
// lock) by exercising the per-stream-arena RECYCLE path on a reused keep-alive
// connection under ASan (which poisons recycled arena regions, so a premature
// recycle / cross-stream alias traps):
//   1) concurrent distinct-body POSTs multiplexed on ONE conn each echo back
//      their OWN body — proves per-stream arenas don't alias across streams;
//   2) many sequential large-body POSTs reuse the one conn (conns_created==1)
//      and all round-trip intact — exercises acquire/recycle churn.
#include <stdio.h>
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

#define BODY (64 * 1024)
#define NCONC 8
global U8 g_bodies[NCONC][BODY];  // distinct per-request payloads

global EventLoop *g_loop;

// Echo the request body straight back (the server copies it).
static void echo_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)user;
  resp->status = 200;
  resp->body = req->body;
  resp->body_len = req->body_len;
}

typedef struct Batch Batch;
struct Batch {
  int outstanding;
  int ok;
};
typedef struct ReqCtx {
  int idx;  // which g_bodies[] this request sent (-1 => sequential body 0)
  Batch *batch;
} ReqCtx;

static void on_resp(void *user, const Response *r) {
  ReqCtx *c = (ReqCtx *)user;
  const U8 *want = g_bodies[c->idx < 0 ? 0 : c->idx];
  if (r->ok && r->status == 200 && r->body_len == BODY &&
      memcmp(r->body, want, BODY) == 0)
    c->batch->ok++;
  if (--c->batch->outstanding == 0) uv_stop(loop_uv(g_loop));
}

global uv_timer_t g_wd;
static void wd_cb(uv_timer_t *t) {
  (void)t;
  fprintf(stderr, "  [watchdog] timed out\n");
  uv_stop(loop_uv(g_loop));
}

int main(void) {
  for (int i = 0; i < NCONC; ++i)
    for (U64 j = 0; j < BODY; ++j) g_bodies[i][j] = (U8)(i * 131 + (int)j);

  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  uv_timer_init(loop_uv(&loop), &g_wd);

  U16 port = 0;
  LbServer *srv = lb_server_start(&loop, LB_ALPN_H2, echo_handler, 0, &port);
  char url[64];
  snprintf(url, sizeof url, "https://127.0.0.1:%u/", port);

  Client c;
  client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/0);
  client_set_max_conns_per_origin(&c, 1);  // one multiplexed keep-alive conn

  // 1) NCONC concurrent POSTs with DISTINCT bodies, multiplexed on one conn —
  //    each must echo back its own body (per-stream arenas mustn't alias).
  {
    Batch b = {NCONC, 0};
    ReqCtx ctx[NCONC];
    uv_timer_start(&g_wd, wd_cb, 15000, 0);
    for (int i = 0; i < NCONC; ++i) {
      ctx[i].idx = i;
      ctx[i].batch = &b;
      RequestParams p = {.method = Method_POST,
                         .url = str8_cstring(url),
                         .body = str8(g_bodies[i], BODY),
                         .no_redirects = 1};
      client_request(&c, &p, on_resp, &ctx[i]);
    }
    loop_run(&loop);
    uv_timer_stop(&g_wd);
    CHECK(b.ok == NCONC);  // every concurrent stream got its OWN body intact
    CHECK(client_pool_stats(&c).conns_created == 1);  // multiplexed on one conn
  }

  // 2) Many SEQUENTIAL large-body POSTs reuse the one conn; all round-trip and
  //    no new conns are opened (per-stream arenas recycled between requests).
  {
    const int K = 24;
    Batch b = {0, 0};
    for (int k = 0; k < K; ++k) {
      ReqCtx ctx = {0, &b};
      b.outstanding = 1;
      uv_timer_start(&g_wd, wd_cb, 15000, 0);
      RequestParams p = {.method = Method_POST,
                         .url = str8_cstring(url),
                         .body = str8(g_bodies[0], BODY),
                         .no_redirects = 1};
      client_request(&c, &p, on_resp, &ctx);
      loop_run(&loop);
      uv_timer_stop(&g_wd);
    }
    CHECK(b.ok == K);
    CHECK(client_pool_stats(&c).conns_created == 1);  // still the one conn
  }

  client_cleanup(&c);
  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  uv_close((uv_handle_t *)&g_wd, 0);
  for (int g = 0; g < 100 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);
  fprintf(stderr, "[pool_h2_body_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
