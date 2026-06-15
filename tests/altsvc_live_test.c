// Live verification of Chrome-style Alt-Svc discovery through the unified
// Client: request #1 over H2 (Chrome 148 fingerprint), request #2 to cloudflare
// learns `alt-svc: h3`, then request #3 to that origin routes over H3/QUIC.
//   req1 (H2):  akamai_hash == 52d84b11737d980aef856699f885ca86
//   req2 (H2):  alpn == h2, alt-svc h3 cached
//   req3 (H3):  alpn == h3, status >= 200
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

#define BL "https://tls.browserleaks.com/json"
#define CF "https://www.cloudflare.com/"

typedef struct Ctx Ctx;
struct Ctx {
  Client *client;
  B32 got_bl, got_cf2, got_cf3, h3_cached;
  char akamai[64], alpn_h2[8], alpn_h3[8];
  int cf3_status;
};

internal void copy_str8(char *dst, U64 cap, String8 v) {
  U64 n = v.size < cap - 1 ? v.size : cap - 1;
  MemoryCopy(dst, v.str, n);
  dst[n] = 0;
}

internal void on_req3(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  if (r->ok) {
    cx->got_cf3 = 1;
    copy_str8(cx->alpn_h3, sizeof cx->alpn_h3, r->alpn);
    cx->cf3_status = r->status;
  } else {
    fprintf(stderr, "  req3 failed: %s\n", r->error ? r->error : "?");
  }
}

internal void on_req2(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  if (r->ok) {
    cx->got_cf2 = 1;
    copy_str8(cx->alpn_h2, sizeof cx->alpn_h2, r->alpn);
    cx->h3_cached =
        client_h3_available(cx->client, str8_lit("www.cloudflare.com:443"));
  }
  // req3: same origin -> should now route over H3/QUIC.
  client_get(cx->client, str8_lit(CF), on_req3, cx);
}

internal void on_req1(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  if (r->ok) {
    cx->got_bl = 1;
    json_get_str(str8((U8 *)r->body, r->body_len), "akamai_hash", cx->akamai,
                 sizeof cx->akamai);
  }
  // req2: H2 to cloudflare -> learns alt-svc h3.
  client_get(cx->client, str8_lit(CF), on_req2, cx);
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[altsvc_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client client;
  client_init(&client, &loop, profile_chrome148(), profile_chrome148_h3(),
              HttpVersion_Auto, /*verify=*/1);
  defer { client_cleanup(&client); };
  CHECK(client_ok(&client));

  Ctx cx;
  MemoryZeroStruct(&cx);
  cx.client = &client;
  client_get(&client, str8_lit(BL), on_req1, &cx);
  loop_run(&loop);

  fprintf(stderr, "  Chrome H2 akamai = %s\n", cx.akamai);
  fprintf(stderr, "  cloudflare req2 alpn=%s, h3 cached=%d\n", cx.alpn_h2,
          cx.h3_cached);
  fprintf(stderr, "  cloudflare req3 alpn=%s status=%d\n", cx.alpn_h3,
          cx.cf3_status);

  CHECK(cx.got_bl);
  CHECK(str8_match(str8_cstring(cx.akamai),
                   str8_lit("52d84b11737d980aef856699f885ca86")));
  CHECK(cx.got_cf2);
  CHECK(strcmp(cx.alpn_h2, "h2") == 0);
  CHECK(cx.h3_cached);
  CHECK(cx.got_cf3);
  CHECK(strcmp(cx.alpn_h3, "h3") == 0);
  CHECK(cx.cf3_status >= 200);

  fprintf(stderr, "[altsvc_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
