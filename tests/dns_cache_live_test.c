// Live DNS-cache test: two requests to the same host on one Client (pooling off ->
// two fresh connections that share the Client's DNS cache). The first resolves and
// caches the address; the second hits the cache, so its timing.dns_ms is 0.
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>

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

typedef struct Ctx Ctx;
struct Ctx {
  B32 ok;
  int status;
  U64 dns_ms;
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->ok = r->ok;
  cx->status = r->status;
  cx->dns_ms = r->timing.dns_ms;
  if (!r->ok) fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
}

internal Ctx fetch(Client *c, EventLoop *loop, const char *url) {
  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(c, str8_cstring(url), on_resp, &cx);
  loop_run(loop);
  return cx;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[dns_cache_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  const char *url = "https://www.cloudflare.com/";

  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };  // runs last (LIFO): after client_cleanup
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/1);  // cache on by default
  defer { client_cleanup(&c); };    // runs first on scope exit
  CHECK(client_ok(&c));

  Ctx a = fetch(&c, &loop, url);  // miss: resolves + caches
  Ctx b = fetch(&c, &loop, url);  // hit: cached address, dns_ms == 0
  fprintf(stderr, "  first:  ok=%d status=%d dns=%llums\n", a.ok, a.status,
          (unsigned long long)a.dns_ms);
  fprintf(stderr, "  second: ok=%d status=%d dns=%llums (cache hit)\n", b.ok,
          b.status, (unsigned long long)b.dns_ms);
  CHECK(a.ok && a.status == 200);
  CHECK(b.ok && b.status == 200);
  CHECK(b.dns_ms == 0);  // the second connection skipped DNS via the cache

  // loop_shutdown + client_cleanup run here via defer (LIFO), as the scope exits.
  fprintf(stderr, "[dns_cache_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
