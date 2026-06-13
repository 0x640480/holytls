// Live timing test: make a real request and print + sanity-check the
// per-request timing breakdown (DNS / TCP / TLS / Total, in ms). Network-gated:
// set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>

#include "base/base.h"
#include "base/defer.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

typedef struct Ctx Ctx;
struct Ctx {
  B32 ok;
  int status;
  Timing t;
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->ok = r->ok;
  cx->status = r->status;
  cx->t = r->timing;
  if (!r->ok)
    fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[timing_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
  defer { client_cleanup(&c); };
  CHECK(client_ok(&c));

  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(&c, str8_cstring("https://www.cloudflare.com/"), on_resp, &cx);
  loop_run(&loop);

  // The httpcloak-style breakdown.
  printf("DNS: %llums, TCP: %llums, TLS: %llums, Total: %llums\n",
         (unsigned long long)cx.t.dns_ms, (unsigned long long)cx.t.tcp_ms,
         (unsigned long long)cx.t.tls_ms, (unsigned long long)cx.t.total_ms);

  CHECK(cx.ok && cx.status == 200);
  CHECK(cx.t.total_ms > 0);  // a live request always takes some milliseconds
  // Connection setup is a prefix of the request, so the phases fit within
  // total.
  CHECK(cx.t.dns_ms + cx.t.tcp_ms + cx.t.tls_ms <= cx.t.total_ms);

  fprintf(stderr, "[timing_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
