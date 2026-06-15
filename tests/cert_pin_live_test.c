// Live certificate-pinning test: a connection whose leaf SPKI does not match
// the pin must be REJECTED end-to-end (the custom verify fires during the real
// handshake and fails it), while an unpinned control client to the same origin
// succeeds. Proves pinning rejects a real, otherwise-CA-valid certificate.
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/base64.h"
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

typedef struct Ctx Ctx;
struct Ctx {
  B32 done;
  B32 ok;
  int status;
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->done = 1;
  cx->ok = r->ok;
  cx->status = r->status;
}

internal Ctx fetch_once(Client *c, EventLoop *loop, const char *url) {
  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(c, str8_cstring(url), on_resp, &cx);
  loop_run(loop);
  return cx;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[cert_pin_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  const char *host = "www.cloudflare.com";
  const char *url = "https://www.cloudflare.com/";

  Arena *a = arena_alloc();
  defer { arena_release(a); };
  // A deliberately wrong pin: base64 of 32 zero bytes (cannot match any real
  // SPKI).
  U8 zero[32];
  MemoryZero(zero, sizeof zero);
  String8 b = base64_encode(a, str8(zero, sizeof zero));
  char bogus[128];
  U64 m = b.size < sizeof bogus - 1 ? b.size : sizeof bogus - 1;
  MemoryCopy(bogus, b.str, m);
  bogus[m] = 0;

  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };

  //- pinned with the wrong SPKI -> the handshake must be rejected
  //--------------
  Client pinned;
  client_init(&pinned, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  CHECK(client_ok(&pinned));
  CHECK(client_pin_certificate(&pinned, host, bogus, /*subdomains=*/0));
  Ctx r1 = fetch_once(&pinned, &loop, url);
  fprintf(stderr, "  pinned(wrong): done=%d ok=%d status=%d\n", r1.done, r1.ok,
          r1.status);
  CHECK(r1.done);
  CHECK(!r1.ok);  // pin mismatch -> connection rejected
  client_cleanup(&pinned);

  //- control: no pin -> normal verification succeeds
  //---------------------------
  Client ctrl;
  client_init(&ctrl, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  CHECK(client_ok(&ctrl));
  Ctx r2 = fetch_once(&ctrl, &loop, url);
  fprintf(stderr, "  control:       done=%d ok=%d status=%d\n", r2.done, r2.ok,
          r2.status);
  CHECK(r2.ok && r2.status == 200);  // unpinned host verifies normally
  client_cleanup(&ctrl);

  fprintf(stderr, "[cert_pin_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
