// Offline tests for the blocking (sync) request API: client_request_sync /
// _get_sync / _post_sync / client_request_all + session_request_sync. Drives a
// dead loopback port (connection refused -> a fast ok=0 Response, no network) and
// asserts the returned ARENA-OWNED Response is non-NULL, ok==0, and its error
// string is still readable AFTER the call returned (loop_run already exited) —
// proving the deep-copy + arena lifetime, which is the whole point of the API.
#include <stdio.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
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

#define DEAD "https://127.0.0.1:1/"  // port 1: refused -> fast ok=0 completion

int main(void) {
  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_template(), NULL, HttpVersion_H2, /*verify=*/1);
  client_set_timeout_ms(&c, 3000);  // bound it (refused is instant anyway)
  Arena *a = arena_alloc();

  // 1) single sync GET to a dead port. The arena-owned ok=0 Response and its
  //    error are read AFTER the call -> they outlived loop_run (the copy works).
  Response *r = client_get_sync(&c, str8_lit(DEAD), a);
  CHECK(r != 0);
  CHECK(!r->ok);
  CHECK(r->status == 0);
  CHECK(r->error != 0 && strlen(r->error) > 0);

  // 2) the POST (body) wrapper takes the same refused path.
  Response *rp = client_post_sync(&c, str8_lit(DEAD), str8_lit("x=1"), a);
  CHECK(rp != 0 && !rp->ok && rp->error != 0);

  // 3) client_request_all: N requests, ONE loop_run, N arena Responses (in
  //    order). An empty-url slot yields its own ok=0 "invalid request".
  RequestParams reqs[3] = {0};
  reqs[0] = (RequestParams){.method = Method_GET, .url = str8_lit(DEAD)};
  reqs[1] = (RequestParams){.method = Method_GET, .url = str8_lit(DEAD)};
  reqs[2] = (RequestParams){.method = Method_GET, .url = str8_zero()};  // no url
  Response **rs = client_request_all(&c, reqs, 3, a);
  CHECK(rs != 0);
  CHECK(rs[0] != 0 && !rs[0]->ok && rs[0]->error != 0);
  CHECK(rs[1] != 0 && !rs[1]->ok && rs[1]->error != 0);
  CHECK(rs[2] != 0 && !rs[2]->ok && rs[2]->error != 0);  // invalid (no url)

  // 4) session_request_sync: same blocking shape over the session's redirect +
  //    cookie loop.
  Session s;
  session_init(&s, 0);  // NULL cfg -> defaults (cookies + follow + 10)
  Response *sr = session_request_sync(
      &s, &c, &(RequestParams){.method = Method_GET, .url = str8_lit(DEAD)}, a);
  CHECK(sr != 0 && !sr->ok && sr->error != 0);
  session_cleanup(&s);

  arena_release(a);
  client_cleanup(&c);
  loop_shutdown(&loop);
  fprintf(stderr, "[sync_api_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
