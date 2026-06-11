// Live Session test: a lightweight session over a SHARED Client. A GET to
// httpbin's /cookies/set?holytls=1 (which 302s to /cookies) must absorb the
// Set-Cookie on hop 1 and re-send it on the redirect — the final /cookies body
// echoes it. The jar persists across a second request, and a SECOND session's
// jar is independent (no cookie leak).
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  B32 got, has_cookie;
  int status;
  char final_url[256];
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->got = 1;
  cx->status = r->status;
  String8 body = str8((U8 *)r->body, r->body_len);
  // httpbin /cookies echoes {"cookies": {"holytls": "1"}}.
  cx->has_cookie = str8_contains(body, str8_lit("holytls")) &&
                   str8_contains(body, str8_lit("\"1\""));
  U64 n = r->final_url.size < sizeof cx->final_url - 1 ? r->final_url.size
                                                       : sizeof cx->final_url - 1;
  if (r->final_url.str) MemoryCopy(cx->final_url, r->final_url.str, n);
  cx->final_url[n] = 0;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[session_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client client;  // one shared transport for every session
  client_init(&client, &loop, profile_chrome148(), /*verify=*/1);
  defer { client_cleanup(&client); };
  CHECK(client_ok(&client));

  // Session 1: set a cookie across a redirect, then prove it round-trips.
  Session s1;
  session_init(&s1, 0);  // defaults: cookies on, 10 redirects
  defer { session_cleanup(&s1); };
  Ctx c1;
  MemoryZeroStruct(&c1);
  session_get(&s1, &client, str8_lit("https://httpbin.org/cookies/set?holytls=1"),
              on_resp, &c1);
  loop_run(&loop);
  fprintf(stderr, "  set: status=%d has_cookie=%d final=%s\n", c1.status,
          c1.has_cookie, c1.final_url);
  CHECK(c1.got && c1.status == 200);
  CHECK(c1.has_cookie);  // absorbed on hop 1, re-sent on the redirect to /cookies
  CHECK(strstr(c1.final_url, "/cookies") != 0);

  // Same session again: the jar persists across requests on the shared client.
  Ctx c2;
  MemoryZeroStruct(&c2);
  session_get(&s1, &client, str8_lit("https://httpbin.org/cookies"), on_resp, &c2);
  loop_run(&loop);
  fprintf(stderr, "  reuse: status=%d has_cookie=%d\n", c2.status, c2.has_cookie);
  CHECK(c2.got && c2.status == 200 && c2.has_cookie);

  // A second session has an independent jar (no cookie leak).
  Session s2;
  session_init(&s2, 0);
  defer { session_cleanup(&s2); };
  Ctx c3;
  MemoryZeroStruct(&c3);
  session_get(&s2, &client, str8_lit("https://httpbin.org/cookies"), on_resp, &c3);
  loop_run(&loop);
  fprintf(stderr, "  other session: status=%d has_cookie=%d\n", c3.status,
          c3.has_cookie);
  CHECK(c3.got && c3.status == 200 && !c3.has_cookie);

  fprintf(stderr, "[session_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
