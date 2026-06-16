// Offline header-order tests over the shared in-process H2 loopback origin
// (tests/support/loopback_server), which records the received request header
// NAMES in wire order. Locks the bug fix + the new feature:
//   1) the POOLED path now applies the header order (it used to skip it, so
//      client_set_header_order was a silent no-op when max_conns_per_origin>0);
//   2) a PER-REQUEST header_order overrides the client-level order, on both the
//      pooled and non-pooled paths AND across redirect hops;
//   3) the default (no custom order) wire order is byte-identical pooled vs
//      non-pooled (the fix must not move the default fingerprint).
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

global EventLoop *g_loop;
global char g_seen[2048];  // last request's received header-name order, CSV
global char g_expect_first[32];  // if set, every hop must list this name first
global B32 g_hops_ok;            // AND of the per-hop "first == expect" checks
global int g_hop_count;          // requests the server saw this run
global B32 g_redirect;           // first hop ("/") replies 302 -> "/next"

// Record the received header order; in redirect mode bounce "/" once.
static void order_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)user;
  U64 off = 0;
  g_seen[0] = 0;
  for (U64 i = 0; i < req->header_name_count; ++i) {
    int w = snprintf(g_seen + off, sizeof g_seen - off, "%s%s", i ? "," : "",
                     req->header_names[i]);
    if (w > 0) off += (U64)w;
  }
  if (g_expect_first[0]) {
    g_hop_count++;
    // first token of g_seen == g_expect_first ?
    U64 ln = strlen(g_expect_first);
    if (!(strncmp(g_seen, g_expect_first, ln) == 0 &&
          (g_seen[ln] == ',' || g_seen[ln] == 0)))
      g_hops_ok = 0;
  }
  if (g_redirect && str8_match(req->path, str8_lit("/"))) {
    resp->status = 302;
    resp->extra_names[0] = "location";
    resp->extra_values[0] = "/next";
    resp->extra_count = 1;
    return;
  }
  resp->status = 200;
}

typedef struct RC {
  B32 ok;
  int status;
} RC;
static void on_resp(void *user, const Response *r) {
  RC *rc = (RC *)user;
  rc->ok = r->ok;
  rc->status = r->status;
  uv_stop(loop_uv(g_loop));
}

global uv_timer_t g_wd;
static void wd_cb(uv_timer_t *t) {
  (void)t;
  fprintf(stderr, "  [watchdog] timed out\n");
  uv_stop(loop_uv(g_loop));
}

// Three marker caller headers; reorder targets one of them to the absolute
// front so the assertion is a crisp "received[0] == x-ccc".
global Header g_markers[] = {
    {{(U8 *)"x-aaa", 5}, {(U8 *)"1", 1}, 0},
    {{(U8 *)"x-bbb", 5}, {(U8 *)"2", 1}, 0},
    {{(U8 *)"x-ccc", 5}, {(U8 *)"3", 1}, 0},
};

// Send one GET (markers attached), no redirects, with `order` as the
// per-request header_order (empty = none). Captures the wire order into g_seen.
static RC send_one(Client *c, const char *url, String8 order) {
  RC rc;
  MemoryZeroStruct(&rc);
  g_seen[0] = 0;
  uv_timer_start(&g_wd, wd_cb, 8000, 0);
  RequestParams p = {.method = Method_GET,
                     .url = str8_cstring(url),
                     .headers = g_markers,
                     .header_count = ArrayCount(g_markers),
                     .no_redirects = 1,
                     .header_order = order};
  client_request(c, &p, on_resp, &rc);
  loop_run(g_loop);
  uv_timer_stop(&g_wd);
  return rc;
}

static Client *make_client(EventLoop *loop, U64 max_conns) {
  Client *c = (Client *)malloc(sizeof *c);
  client_init(c, loop, profile_chrome148(), NULL, HttpVersion_H2, /*verify=*/0);
  client_set_http_version(c, HttpVersion_H2);
  if (max_conns) client_set_max_conns_per_origin(c, max_conns);  // pooled path
  return c;
}
static void free_client(Client *c) {
  client_cleanup(c);
  free(c);
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  uv_timer_init(loop_uv(&loop), &g_wd);

  U16 port = 0;
  LbServer *srv = lb_server_start(&loop, LB_ALPN_H2, order_handler, 0, &port);
  char url[64];
  snprintf(url, sizeof url, "https://127.0.0.1:%u/", port);

  Client *np = make_client(&loop, 0);  // non-pooled
  Client *pl = make_client(&loop, 4);  // pooled (max_conns_per_origin)

  // 1) Default order (no custom order): pooled wire order == non-pooled wire
  //    order. The fix must not move the default fingerprint.
  char def_np[2048];
  CHECK(send_one(np, url, str8_zero()).ok);
  strncpy(def_np, g_seen, sizeof def_np - 1);
  def_np[sizeof def_np - 1] = 0;
  CHECK(send_one(pl, url, str8_zero()).ok);
  fprintf(stderr, "  default np=[%s]\n  default pl=[%s]\n", def_np, g_seen);
  CHECK(strcmp(def_np, g_seen) == 0);

  // 2) Client-level header order moves x-ccc to the front — honored on BOTH the
  //    non-pooled and the pooled path (the bug: pooled used to skip
  //    reordering).
  client_set_header_order_str(np, "x-ccc");
  client_set_header_order_str(pl, "x-ccc");
  CHECK(send_one(np, url, str8_zero()).ok);
  CHECK(strncmp(g_seen, "x-ccc", 5) == 0);  // non-pooled
  CHECK(send_one(pl, url, str8_zero()).ok);
  fprintf(stderr, "  client-order pooled seen=[%s]\n", g_seen);
  CHECK(strncmp(g_seen, "x-ccc", 5) == 0);  // pooled — the regression lock
  client_set_header_order_str(np, "");
  client_set_header_order_str(pl, "");

  // 3) A per-request header_order REPLACES the client-level order, on both
  //    paths. Client-level says x-aaa first; the request asks for x-bbb first.
  client_set_header_order_str(np, "x-aaa");
  client_set_header_order_str(pl, "x-aaa");
  CHECK(send_one(np, url, str8_zero()).ok);
  CHECK(strncmp(g_seen, "x-aaa", 5) == 0);  // client-level applies w/o override
  CHECK(send_one(np, url, str8_lit("x-bbb")).ok);
  CHECK(strncmp(g_seen, "x-bbb", 5) == 0);  // per-request wins (non-pooled)
  CHECK(send_one(pl, url, str8_lit("x-bbb")).ok);
  fprintf(stderr, "  per-request pooled seen=[%s]\n", g_seen);
  CHECK(strncmp(g_seen, "x-bbb", 5) == 0);  // per-request wins (pooled)
  client_set_header_order_str(np, "");
  client_set_header_order_str(pl, "");

  // 4) A per-request header_order is preserved across a redirect hop: both the
  //    "/" hop and the "/next" hop must list x-ccc first.
  Client *rc = make_client(&loop, 0);
  client_set_max_redirects(rc, 5);
  g_redirect = 1;
  g_hops_ok = 1;
  g_hop_count = 0;
  strcpy(g_expect_first, "x-ccc");
  {
    RC r;
    MemoryZeroStruct(&r);
    uv_timer_start(&g_wd, wd_cb, 8000, 0);
    RequestParams p = {.method = Method_GET,
                       .url = str8_cstring(url),
                       .headers = g_markers,
                       .header_count = ArrayCount(g_markers),
                       .header_order = str8_lit("x-ccc")};
    client_request(rc, &p, on_resp, &r);
    loop_run(&loop);
    uv_timer_stop(&g_wd);
    CHECK(r.ok && r.status == 200);
  }
  fprintf(stderr, "  redirect hops=%d all-first-x-ccc=%d\n", g_hop_count,
          g_hops_ok);
  CHECK(g_hop_count == 2);  // "/" (302) then "/next" (200)
  CHECK(g_hops_ok);         // every hop kept the per-request order
  g_expect_first[0] = 0;
  g_redirect = 0;
  free_client(rc);

  free_client(np);
  free_client(pl);
  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  uv_close((uv_handle_t *)&g_wd, 0);
  for (int g = 0; g < 100 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);
  fprintf(stderr, "[header_order_pool_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
