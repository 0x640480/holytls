// Offline request-timeout tests. The shared in-process H2 loopback origin
// (tests/support) answers by request path: 200 immediately ("/fast"), a 302 to
// /slow ("/redir"), or NEVER answers ("/slow"). With a short client timeout we
// assert:
//   - a hung non-pooled request fails once with "timeout", within ~the budget;
//   - a fast request with a generous timeout succeeds (no spurious timeout);
//   - a pooled request that times out is cancelled per-stream — its connection
//     survives and a later request reuses it (conns_created stays 1);
//   - the timeout spans a redirect chain (a redirect to /slow still times out).
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

global U16 g_port;
global char g_slow_url[64];  // https://127.0.0.1:<port>/slow (the redirect target)
global EventLoop *g_loop;

// Per-path behavior: /slow never answers, /redir 302s to /slow, else 200.
static void timeout_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)user;
  if (str8_contains(req->path, str8_lit("slow"))) {
    resp->withhold = 1;
  } else if (str8_contains(req->path, str8_lit("redir"))) {
    resp->status = 302;
    resp->extra_names[0] = "location";
    resp->extra_values[0] = g_slow_url;
    resp->extra_count = 1;
  } else {
    resp->status = 200;
  }
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

int main(void) {
  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  LbServer *srv = lb_server_start(&loop, LB_ALPN_H2, timeout_handler, 0, &g_port);
  snprintf(g_slow_url, sizeof g_slow_url, "https://127.0.0.1:%u/slow", g_port);
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
  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);
  fprintf(stderr, "[timeout_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
