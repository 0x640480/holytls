// Live ECH test: with ECH enabled, a GET to Cloudflare's trace endpoint must
// report sni=encrypted (proving the client fetched the ECHConfigList over DoH and
// actually encrypted the ClientHello — not just GREASE).
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>

#include "base/base.h"
#include "base/defer.h"
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
  B32 got, sni_encrypted;
  int status;
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->got = 1;
  cx->status = r->status;
  String8 body = str8((U8 *)r->body, r->body_len);
  cx->sni_encrypted = str8_contains(body, str8_lit("sni=encrypted"));
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[ech_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
  defer { client_cleanup(&c); };
  CHECK(client_ok(&c));
  client_set_ech_enabled(&c, 1);  // fetch ECHConfigList over DoH + offer real ECH

  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(&c, str8_lit("https://crypto.cloudflare.com/cdn-cgi/trace"), on_resp,
             &cx);
  loop_run(&loop);  // DoH prefetch -> real request, both on this loop
  fprintf(stderr, "  status=%d sni_encrypted=%d\n", cx.status, cx.sni_encrypted);
  CHECK(cx.got && cx.status == 200);
  CHECK(cx.sni_encrypted);  // real ECH succeeded end-to-end

  fprintf(stderr, "[ech_live_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
