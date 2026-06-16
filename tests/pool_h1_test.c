// Offline HTTP/1.1 keep-alive connection-pooling tests over the in-process H1
// loopback origin. Locks the perf fix: forced-H1 used to open a fresh TCP+TLS
// connection (full handshake) per request; now, with max_conns_per_origin>0,
// it reuses keep-alive connections.
//   1) FAN-OUT: a concurrent burst of N opens at most M==max_conns_per_origin
//      conns (H1 can't multiplex), then reuses them for the rest;
//   2) reuse ACROSS batches: a second burst opens no new conns;
//   3) `Connection: close` retires a conn (the next request opens a fresh one);
//   4) NON-POOLED control: max_conns_per_origin==0 never touches the pool.
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
global const char g_body[] = "hello-from-h1";

// Echo-ish handler: 200 + a fixed body; the "/close" path adds Connection:
// close so the server retires the socket after that response.
static void h1_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)user;
  resp->status = 200;
  resp->body = (const U8 *)g_body;
  resp->body_len = sizeof g_body - 1;
  if (str8_match(req->path, str8_lit("/close"))) {
    resp->extra_names[0] = "Connection";
    resp->extra_values[0] = "close";
    resp->extra_count = 1;
  }
}

typedef struct Batch {
  int n;         // requests outstanding
  int ok_count;  // successful 200s with the right body
} Batch;
static void on_resp(void *user, const Response *r) {
  Batch *b = (Batch *)user;
  if (r->ok && r->status == 200 && r->body_len == sizeof g_body - 1 &&
      memcmp(r->body, g_body, r->body_len) == 0 &&
      str8_match(r->alpn, str8_lit("http/1.1")))
    b->ok_count++;
  if (--b->n == 0) uv_stop(loop_uv(g_loop));
}

global uv_timer_t g_wd;
static void wd_cb(uv_timer_t *t) {
  (void)t;
  fprintf(stderr, "  [watchdog] timed out\n");
  uv_stop(loop_uv(g_loop));
}

// Fire `n` concurrent GETs to `path` and run the loop until all complete.
static int burst(Client *c, const char *url_base, const char *path, int n) {
  char url[96];
  snprintf(url, sizeof url, "%s%s", url_base, path);
  Batch b = {n, 0};
  uv_timer_start(&g_wd, wd_cb, 10000, 0);
  for (int i = 0; i < n; ++i) {
    RequestParams p = {
        .method = Method_GET, .url = str8_cstring(url), .no_redirects = 1};
    client_request(c, &p, on_resp, &b);
  }
  loop_run(g_loop);
  uv_timer_stop(&g_wd);
  return b.ok_count;
}

static Client *make_client(EventLoop *loop, U64 max_conns) {
  Client *c = (Client *)malloc(sizeof *c);
  client_init(c, loop, profile_chrome148(), NULL, HttpVersion_H1, /*verify=*/0);
  client_set_http_version(c, HttpVersion_H1);
  if (max_conns) client_set_max_conns_per_origin(c, max_conns);
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
  LbServer *srv = lb_server_start(&loop, LB_ALPN_H1, h1_handler, 0, &port);
  char base[64];
  snprintf(base, sizeof base, "https://127.0.0.1:%u", port);

  // 1) Fan-out under the cap: N=6 concurrent, M=2 conns. H1 can't multiplex, so
  //    it opens exactly M conns and reuses them for the other N-M requests.
  Client *pl = make_client(&loop, 2);
  CHECK(burst(pl, base, "/a", 6) == 6);
  PoolStats s1 = client_pool_stats(pl);
  fprintf(stderr, "  batch1: conns_created=%llu reuses=%llu requests=%llu\n",
          (unsigned long long)s1.conns_created, (unsigned long long)s1.reuses,
          (unsigned long long)s1.requests);
  CHECK(s1.conns_created == 2);  // the bug today: this would be 6 (no reuse)
  CHECK(s1.reuses == 4);         // N - M served by reusing the 2 conns
  CHECK(s1.requests == 6);

  // 2) Reuse across batches: a second burst opens NO new conns (the 2 idle
  //    keep-alive conns are reused).
  CHECK(burst(pl, base, "/b", 6) == 6);
  PoolStats s2 = client_pool_stats(pl);
  fprintf(stderr, "  batch2: conns_created=%llu reuses=%llu\n",
          (unsigned long long)s2.conns_created, (unsigned long long)s2.reuses);
  CHECK(s2.conns_created == 2);       // unchanged — fully reused
  CHECK(s2.reuses == s1.reuses + 6);  // all 6 of batch 2 were reuses
  free_client(pl);

  // 3) `Connection: close` retires a conn: on a single-conn client, a normal
  //    request opens conn #1 (kept), the "/close" response closes it, so the
  //    next request must open conn #2.
  Client *cc = make_client(&loop, 1);
  CHECK(burst(cc, base, "/a", 1) == 1);
  CHECK(client_pool_stats(cc).conns_created == 1);
  CHECK(burst(cc, base, "/close", 1) == 1);  // delivered AND closed the conn
  CHECK(client_pool_stats(cc).conns_created ==
        1);  // no new conn for the close req itself
  CHECK(burst(cc, base, "/a", 1) == 1);
  CHECK(client_pool_stats(cc).conns_created ==
        2);  // conn #1 was retired -> fresh conn
  free_client(cc);

  // 4) Non-pooled control: max_conns_per_origin==0 -> the legacy per-request
  //    path; the pool is never allocated, stats stay zero, requests still work.
  Client *np = make_client(&loop, 0);
  CHECK(burst(np, base, "/a", 3) == 3);
  PoolStats sn = client_pool_stats(np);
  CHECK(sn.conns_created == 0 && sn.requests == 0 && sn.reuses == 0);
  free_client(np);

  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  uv_close((uv_handle_t *)&g_wd, 0);
  for (int g = 0; g < 100 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);
  fprintf(stderr, "[pool_h1_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
