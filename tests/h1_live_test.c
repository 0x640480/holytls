// Live proof of the HTTP/1.1 path end-to-end through the Client. We force the
// server onto HTTP/1.1 by advertising ONLY "http/1.1" in ALPN (a test-only
// profile tweak), then GET tls.browserleaks.com/json and assert the request
// went over h1 (alpn == "http/1.1"), returned 200, and the (possibly
// compressed) body decoded to the fingerprint JSON. This exercises the client's
// h1 branch + serializer + picohttpparser response parsing + transparent decode
// against a real server. Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it
// skips and passes).
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
  char alpn[16];
  U64 body_len;
  char body[8192];
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  if (!r->ok) {
    fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
    return;
  }
  cx->got = 1;
  cx->status = r->status;
  U64 an =
      r->alpn.size < sizeof cx->alpn - 1 ? r->alpn.size : sizeof cx->alpn - 1;
  MemoryCopy(cx->alpn, r->alpn.str, an);
  cx->alpn[an] = 0;
  cx->body_len = r->body_len;
  U64 bn =
      r->body_len < sizeof cx->body - 1 ? r->body_len : sizeof cx->body - 1;
  if (r->body && bn) MemoryCopy(cx->body, r->body, bn);
  cx->body[bn] = 0;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[h1_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }

  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };

  // Force HTTP/1.1: a copy of the template profile advertising only http/1.1 in
  // ALPN, so the server cannot pick h2 and the client takes its h1 branch.
  Profile prof = *profile_template();
  static const U8 h1_alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  prof.tls.alpn_wire = h1_alpn;
  prof.tls.alpn_wire_len = (U16)sizeof h1_alpn;

  Client client;
  client_init(&client, &loop, &prof, NULL, HttpVersion_H2, /*verify=*/1);
  defer { client_cleanup(&client); };
  CHECK(client_ok(&client));

  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(&client, str8_lit("https://tls.browserleaks.com/json"), on_resp,
             &cx);
  loop_run(&loop);

  CHECK(cx.got);
  fprintf(stderr, "  status=%d alpn=%s body=%llu bytes\n", cx.status, cx.alpn,
          (unsigned long long)cx.body_len);
  CHECK(strcmp(cx.alpn, "http/1.1") ==
        0);  // proves it routed over the h1 branch
  CHECK(cx.status == 200);
  CHECK(cx.body_len > 0);
  // The body decoded to the fingerprint JSON: extract a field to prove it
  // parses.
  char ja4[80];
  CHECK(
      json_get_str(str8((U8 *)cx.body, cx.body_len), "ja4", ja4, sizeof ja4) &&
      ja4[0] != 0);

  fprintf(stderr, "[h1_live_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
