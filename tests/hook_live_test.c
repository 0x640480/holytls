// Live request-hook test: a pre-hook injects a custom header (and is refused when
// it tries to overwrite the User-Agent), and a post-hook observes the response.
// We GET https://httpbin.org/headers, which echoes the request headers back as
// JSON, so we can assert the injected header reached the wire and the fingerprint
// User-Agent was preserved.
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define MARKER "holytlshooktest123"   // injected header value (echoed verbatim)
#define EVIL "EvilBot9000xyz"         // bogus UA the hook tries (must be refused)

typedef struct PostCap PostCap;
struct PostCap {
  B32 fired;
  int status;
  U64 header_count;
};

typedef struct Ctx Ctx;
struct Ctx {
  B32 done;
  B32 ok;
  int status;
  char body[16384];
  U64 body_len;
};

// Pre-hook: inject an allowed custom header; attempt to overwrite User-Agent.
internal int pre_hook(HookRequest *req, void *user) {
  (void)user;
  CHECK(hook_request_set_header(req, str8_lit("X-Hook-Test"), str8_lit(MARKER)));
  CHECK(!hook_request_set_header(req, str8_lit("user-agent"), str8_lit(EVIL)));
  return 0;
}

internal void post_hook(Response *r, void *user) {
  PostCap *p = (PostCap *)user;
  p->fired = 1;
  p->status = r->status;
  p->header_count = r->header_count;
}

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->done = 1;
  cx->ok = r->ok;
  cx->status = r->status;
  U64 n = r->body_len < sizeof cx->body - 1 ? r->body_len : sizeof cx->body - 1;
  if (r->body && n) MemoryCopy(cx->body, r->body, n);
  cx->body_len = n;
  cx->body[n] = 0;
  if (!r->ok) fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
}

internal B32 body_has(const Ctx *cx, const char *sub) {
  return strstr(cx->body, sub) != 0;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[hook_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
  defer { client_cleanup(&c); };
  CHECK(client_ok(&c));

  PostCap pc;
  MemoryZeroStruct(&pc);
  client_set_pre_hook(&c, pre_hook, 0);
  client_set_post_hook(&c, post_hook, &pc);

  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(&c, str8_cstring("https://httpbin.org/headers"), on_resp, &cx);
  loop_run(&loop);

  fprintf(stderr, "  resp: ok=%d status=%d body=%llu bytes\n", cx.ok, cx.status,
          (unsigned long long)cx.body_len);
  CHECK(cx.ok && cx.status == 200);

  // The injected header reached the wire (echoed back).
  CHECK(body_has(&cx, MARKER));
  // The User-Agent override was refused: the real Chrome UA is present, the
  // bogus one is not.
  CHECK(body_has(&cx, "Chrome"));
  CHECK(!body_has(&cx, EVIL));

  // The post-hook observed the final response.
  CHECK(pc.fired);
  CHECK(pc.status == 200);
  CHECK(pc.header_count > 0);

  fprintf(stderr, "[hook_live_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
