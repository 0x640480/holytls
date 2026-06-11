// Live verification of redirect following. https://google.com/ replies 301 with
// Location: https://www.google.com/. With following disabled (default) the client
// surfaces the 301; with client_set_max_redirects() it follows to a 200 and reports
// final_url == the www host.
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  B32 got;
  int status;
  char final_url[256];
};

internal void on_response(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->got = 1;
  cx->status = r->status;
  U64 n = r->final_url.size < sizeof cx->final_url - 1 ? r->final_url.size
                                                       : sizeof cx->final_url - 1;
  if (r->final_url.str && n) MemoryCopy(cx->final_url, r->final_url.str, n);
  cx->final_url[n] = 0;
}

// One GET against `url` with `max_redirects` follow budget; returns the result.
internal Ctx fetch(U64 max_redirects, const char *url) {
  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client client;
  client_init(&client, &loop, profile_chrome148(), /*verify=*/1);
  defer { client_cleanup(&client); };
  CHECK(client_ok(&client));
  client_set_max_redirects(&client, max_redirects);
  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(&client, str8_cstring(url), on_response, &cx);
  loop_run(&loop);
  return cx;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[redirect_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  const char *url = "https://google.com/";

  // Following disabled (default): the 301 is surfaced as-is.
  Ctx off = fetch(0, url);
  fprintf(stderr, "  no-follow: status=%d\n", off.status);
  CHECK(off.got);
  CHECK(off.status == 301 || off.status == 302);  // google apex -> www

  // Following enabled: chases the redirect to a 200 at www.google.com.
  Ctx on = fetch(5, url);
  fprintf(stderr, "  follow:    status=%d final_url=%s\n", on.status,
          on.final_url);
  CHECK(on.got);
  CHECK(on.status == 200);
  CHECK(strstr(on.final_url, "www.google.com") != 0);

  fprintf(stderr, "[redirect_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
