// Live Sec-Fetch coherence: a Cors fetch to httpbin /headers (which echoes the
// request headers) must report mode=cors, dest=empty, site=same-origin (from
// the Referer), and NO Sec-Fetch-User — i.e. it looks like an XHR, not a
// navigation. Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and
// passes).
#include <stdio.h>
#include <stdlib.h>

#include "base/base.h"
#include "base/defer.h"
#include "core/client.h"
#include "core/session.h"
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
  B32 got, mode_cors, dest_empty, site_same, site_cross, no_user;
  int status;
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->got = 1;
  cx->status = r->status;
  String8 b = str8((U8 *)r->body, r->body_len);  // the echo service's JSON
  cx->mode_cors = str8_contains(b, str8_lit("\"Sec-Fetch-Mode\"")) &&
                  str8_contains(b, str8_lit("cors"));
  cx->dest_empty = str8_contains(b, str8_lit("\"Sec-Fetch-Dest\"")) &&
                   str8_contains(b, str8_lit("empty"));
  cx->site_same = str8_contains(b, str8_lit("\"Sec-Fetch-Site\"")) &&
                  str8_contains(b, str8_lit("same-origin"));
  cx->site_cross = str8_contains(b, str8_lit("\"Sec-Fetch-Site\"")) &&
                   str8_contains(b, str8_lit("cross-site"));
  cx->no_user = !str8_contains(b, str8_lit("Sec-Fetch-User"));
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[sec_fetch_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
  defer { client_cleanup(&c); };
  CHECK(client_ok(&c));

  Header headers[1] = {
      {str8_lit("referer"), str8_lit("https://httpbin.org/"), 0}};
  Ctx cx;
  MemoryZeroStruct(&cx);
  RequestParams params = {.method = Method_GET,
                          .url = str8_lit("https://httpbin.org/headers"),
                          .headers = headers,
                          .header_count = 1,
                          .fetch_mode = FetchMode_Cors};
  client_request(&c, &params, on_resp, &cx);
  loop_run(&loop);
  fprintf(stderr, "  status=%d cors=%d empty=%d same=%d no_user=%d\n",
          cx.status, cx.mode_cors, cx.dest_empty, cx.site_same, cx.no_user);
  CHECK(cx.got && cx.status == 200);
  CHECK(cx.mode_cors);   // Sec-Fetch-Mode: cors (not navigate)
  CHECK(cx.dest_empty);  // Sec-Fetch-Dest: empty (not document)
  CHECK(cx.site_same);   // Sec-Fetch-Site: same-origin (from the referer)
  CHECK(cx.no_user);     // Sec-Fetch-User suppressed for a fetch

  // A Cors fetch that 302s cross-origin (httpbin -> httpbingo, a different
  // registrable domain) must DOWNGRADE Sec-Fetch-Site to cross-site on the
  // final hop (recomputed across the redirect). Driven via a session (its own
  // loop).
  Session s;
  session_init(&s, 0);
  defer { session_cleanup(&s); };
  Header rh[1] = {{str8_lit("referer"), str8_lit("https://httpbin.org/"), 0}};
  Ctx cx2;
  MemoryZeroStruct(&cx2);
  RequestParams redirect_params = {
      .method = Method_GET,
      .url = str8_lit("https://httpbin.org/redirect-to?url=https%3A%2F%2F"
                      "httpbingo.org%2Fheaders&status_code=302"),
      .headers = rh,
      .header_count = 1,
      .fetch_mode = FetchMode_Cors};
  session_request(&s, &c, &redirect_params, on_resp, &cx2);
  loop_run(&loop);
  fprintf(stderr, "  redirect: status=%d site_cross=%d\n", cx2.status,
          cx2.site_cross);
  CHECK(cx2.got && cx2.status == 200);
  CHECK(cx2.site_cross);  // same-origin hop -> cross-origin hop => cross-site

  fprintf(stderr, "[sec_fetch_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
