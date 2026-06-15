// Live TLS 1.3 session resumption (1-RTT ticket reuse). With resumption
// enabled, the FIRST request to an origin is a fresh full handshake (the server
// issues a NewSessionTicket the client caches); the SECOND request to the same
// origin offers that ticket and completes via an abbreviated handshake ->
// r->resumed. A control client with resumption OFF must never resume (the
// opt-in is real, so the default path stays a byte-exact fresh handshake every
// time). Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and
// passes).
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
  B32 got;
  int status;
  B32 resumed;
  String8 alpn;
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->got = r->ok;
  cx->status = r->status;
  cx->resumed = r->resumed;
  cx->alpn = r->alpn;
  if (!r->ok)
    fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
}

// Issue one request to `url` on `c` and drive the loop until it finishes.
internal Ctx fetch_once(Client *c, EventLoop *loop, const char *url) {
  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(c, str8_cstring(url), on_resp, &cx);
  loop_run(loop);
  return cx;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[resumption_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  const char *url = "https://www.cloudflare.com/";

  EventLoop loop;
  loop_init(&loop);
  defer {
    loop_shutdown(&loop);
  };  // clients are cleaned explicitly below (one
      // freed before the next is created)

  //- resumption ENABLED: first fresh, second resumes -------------------------
  Client on;
  client_init(&on, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  CHECK(client_ok(&on));
  client_set_resumption_enabled(&on, 1);

  Ctx a = fetch_once(&on, &loop, url);  // fresh handshake; caches the ticket
  Ctx b = fetch_once(&on, &loop, url);  // offers the cached ticket -> resumes
  fprintf(stderr,
          "  enabled:  a{got=%d status=%d resumed=%d} "
          "b{got=%d status=%d resumed=%d}\n",
          a.got, a.status, a.resumed, b.got, b.status, b.resumed);
  CHECK(a.got && a.status == 200);
  CHECK(b.got && b.status == 200);
  CHECK(!a.resumed);  // the very first connection can't resume
  CHECK(b.resumed);   // the reconnect resumes the cached session (1-RTT)

  client_cleanup(&on);

  //- resumption DISABLED (default): never resumes ----------------------------
  Client off;
  client_init(&off, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  CHECK(client_ok(&off));  // resumption left OFF

  Ctx c = fetch_once(&off, &loop, url);
  Ctx d = fetch_once(&off, &loop, url);
  fprintf(stderr, "  disabled: c{resumed=%d} d{resumed=%d}\n", c.resumed,
          d.resumed);
  CHECK(c.got && c.status == 200 && d.got && d.status == 200);
  CHECK(!c.resumed && !d.resumed);  // opt-in: default path never resumes

  client_cleanup(&off);

  fprintf(stderr, "[resumption_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
