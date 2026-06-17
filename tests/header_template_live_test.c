// Live integration test for the named-slot header template (network-gated:
// HOLYTLS_LIVE=1). A Session POST in override-default-headers mode with a caller
// template that includes EMPTY `content-length` and `cookie` slots: holytls fills
// content-length from the body and cookie from the jar IN PLACE, keeping the
// caller's exact wire order. A PreRequestHook captures the fully-assembled header
// list just before it is written, so we assert the order + filled values
// byte-for-byte (httpbin's JSON echo normalizes order, so the hook is the source
// of truth). Driven via session_request_sync (the blocking sync API).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/defer.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/cookie.h"
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

typedef struct Cap Cap;
struct Cap {
  B32 fired;
  char order[512];   // comma-joined header names, in wire order
  char cl[32];       // the content-length value as sent
  char cookie[256];  // the cookie value as sent
};

// Fires after assembly, just before the write — sees the final ordered headers.
internal int pre_hook(HookRequest *req, void *user) {
  Cap *c = (Cap *)user;
  c->fired = 1;
  int off = 0;
  for (U64 i = 0; i < req->headers->count; ++i) {
    Header *h = &req->headers->v[i];
    off += snprintf(c->order + off, sizeof c->order - (size_t)off,
                    "%s" STR8_Fmt, i ? "," : "", STR8_Arg(h->name));
    if (str8_match_ci(h->name, str8_lit("content-length")))
      snprintf(c->cl, sizeof c->cl, STR8_Fmt, STR8_Arg(h->value));
    if (str8_match_ci(h->name, str8_lit("cookie")))
      snprintf(c->cookie, sizeof c->cookie, STR8_Fmt, STR8_Arg(h->value));
  }
  return 0;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[header_template_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }

  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client client;
  client_init(&client, &loop, profile_chrome149(), NULL, HttpVersion_H2,
              /*verify=*/1);
  defer { client_cleanup(&client); };
  client_set_timeout_ms(&client, 30000);
  client_override_default_headers(&client, 1);  // the caller array IS the order
  Cap cap = {0};
  client_set_pre_hook(&client, pre_hook, &cap);

  Session s;
  session_init(&s, 0);  // cookies + redirects on
  defer { session_cleanup(&s); };
  // Seed an out-of-band cookie into the jar (no Set-Cookie delivered it).
  cookie_jar_put(&s.jar, str8_lit("sid"), str8_lit("xyz"),
                 str8_lit("httpbin.org"), str8_lit("/"), 0, /*host_only=*/0,
                 /*secure=*/1, /*http_only=*/0, /*same_site=*/0);

  Arena *a = arena_alloc();
  defer { arena_release(a); };
  // Template with empty cookie + content-length slots in chosen positions.
  Header tmpl[] = {
      {str8_lit("x-first"), str8_lit("1"), 0},
      {str8_lit("content-length"), str8_zero(), 0},  // filled from the body
      {str8_lit("cookie"), str8_zero(), 0},          // filled from the jar
      {str8_lit("x-last"), str8_lit("2"), 0},
  };
  RequestParams p = {.method = Method_POST,
                     .url = str8_lit("https://httpbin.org/post"),
                     .headers = tmpl,
                     .header_count = ArrayCount(tmpl),
                     .body = str8_lit("hello")};  // 5 bytes
  Response *r = session_request_sync(&s, &client, &p, a);

  CHECK(r->ok);
  CHECK(r->status == 200);
  CHECK(cap.fired);
  // The slots were filled IN PLACE — exact caller order preserved.
  CHECK(strcmp(cap.order, "x-first,content-length,cookie,x-last") == 0);
  CHECK(strcmp(cap.cl, "5") == 0);          // content-length from the body
  CHECK(strcmp(cap.cookie, "sid=xyz") == 0);  // cookie from the jar
  fprintf(stderr, "  order=[%s] content-length=%s cookie=%s\n", cap.order,
          cap.cl, cap.cookie);

  fprintf(stderr, "[header_template_live_test] %d checks, %d failures\n",
          g_checks, g_fails);
  return g_fails ? 1 : 0;
}
