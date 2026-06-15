// Live client verification: GET https://tls.browserleaks.com/json through the
// full Client API (template profile, H2/TCP) and assert browserleaks reports
// the fingerprints byte-exact — the same goldens as conn_test, but exercising
// the whole client stack (URL parse, ordered headers, transparent decode).
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/base.h"
#include "base/defer.h"
#include "core/client.h"
#include "core/json.h"
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
  B32 got;
  int status;
  char ja4[80];
  char akamai[64];
};

internal void on_response(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  if (!r->ok) {
    fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
    return;
  }
  cx->got = 1;
  cx->status = r->status;
  String8 body = str8((U8 *)r->body, r->body_len);
  json_get_str(body, "ja4", cx->ja4, sizeof cx->ja4);
  json_get_str(body, "akamai_hash", cx->akamai, sizeof cx->akamai);
}

// One GET https://tls.browserleaks.com/json through the full Client stack with
// |prof|, asserting browserleaks reports the byte-exact fresh-handshake goldens.
internal void run_profile(EventLoop *loop, const Profile *prof,
                          const char *want_ja4, const char *want_akamai) {
  Client client;
  client_init(&client, loop, prof, /*verify=*/1);
  defer { client_cleanup(&client); };
  CHECK(client_ok(&client));

  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(&client, str8_lit("https://tls.browserleaks.com/json"),
             on_response, &cx);
  loop_run(loop);

  CHECK(cx.got);
  fprintf(stderr, "  %-10s status=%d ja4=%s akamai=%s\n", prof->name, cx.status,
          cx.ja4, cx.akamai);
  CHECK(cx.status == 200);
  CHECK(str8_match(str8_cstring(cx.akamai), str8_cstring(want_akamai)));
  CHECK(str8_match(str8_cstring(cx.ja4), str8_cstring(want_ja4)));
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[client_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }

  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };

  run_profile(&loop, profile_template(), "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
              "6ea73faa8fc5aac76bded7bd238f6433");
  // Firefox 151 H2/TCP, fresh handshake (session_ticket(0023), no PSK) — the
  // JA4_c 3cbfd9057e0d browserleaks reports for fresh Firefox (a resumed one
  // would carry PSK(0029) -> e6dcd7ae0a9e). Same akamai as the template (their
  // H2 SETTINGS coincide). Exercises the fork EMS/reneg + record_size_limit.
  run_profile(&loop, profile_firefox151(),
              "t13d1617h2_86a278354501_3cbfd9057e0d",
              "6ea73faa8fc5aac76bded7bd238f6433");

  fprintf(stderr, "[client_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
