// Live test for the blocking (sync) request API (network-gated: HOLYTLS_LIVE=1).
// The real proof: the returned ARENA-OWNED Response is fully populated AND usable
// AFTER the call returns — body parsed as JSON, a response header found, final_url
// + alpn set — the deep-copy + lifetime end to end against a real response. Also
// exercises client_request_all (N on one loop_run) and session_request_sync.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/defer.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/json.h"
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

#define URL "https://tls.browserleaks.com/json"

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[sync_api_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }

  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client c;
  client_init(&c, &loop, profile_template(), NULL, HttpVersion_H2, /*verify=*/1);
  defer { client_cleanup(&c); };
  client_set_timeout_ms(&c, 30000);
  Arena *a = arena_alloc();
  defer { arena_release(a); };

  // 1) single sync GET — every field is read AFTER the call returns.
  Response *r = client_get_sync(&c, str8_lit(URL), a);
  CHECK(r->ok);
  CHECK(r->status == 200);
  CHECK(r->body_len > 0);
  CHECK(r->final_url.size > 0);
  CHECK(str8_match_ci(r->alpn, str8_lit("h2")));
  // body parses as JSON -> the copied bytes are intact past loop_run.
  char ja4[80] = {0};
  json_get_str(str8((U8 *)r->body, r->body_len), "ja4", ja4, sizeof ja4);
  CHECK(strlen(ja4) > 0);
  // a response header survived the copy.
  String8 ctype = response_get_header(r, str8_lit("content-type"));
  CHECK(ctype.size > 0);

  // 2) batch: 3 GETs driven on ONE loop_run, all populated.
  RequestParams reqs[3] = {0};
  for (int i = 0; i < 3; ++i)
    reqs[i] = (RequestParams){.method = Method_GET, .url = str8_lit(URL)};
  Response **rs = client_request_all(&c, reqs, 3, a);
  for (int i = 0; i < 3; ++i) {
    CHECK(rs[i]->ok);
    CHECK(rs[i]->status == 200);
    CHECK(rs[i]->body_len > 0);
  }

  // 3) session sync GET (cookies + redirect loop).
  Session s;
  session_init(&s, 0);
  Response *sr = session_request_sync(
      &s, &c, &(RequestParams){.method = Method_GET, .url = str8_lit(URL)}, a);
  CHECK(sr->ok && sr->status == 200 && sr->body_len > 0);
  session_cleanup(&s);

  fprintf(stderr, "[sync_api_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
