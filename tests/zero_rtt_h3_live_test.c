// Live HTTP/3 (QUIC) 0-RTT. A dual client warms alt-svc over H2, then routes to
// H3: the first H3 request is a fresh handshake (capturing the session ticket +
// ngtcp2 0-RTT transport params), and the next H3 request opens its request
// stream as 0-RTT data — r->early_data set when the server accepts it. The
// control with 0-RTT OFF must never report early_data.
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
  B32 called, got;
  int status;
  B32 resumed, early_data;
  char alpn[16];
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->called = 1;
  cx->got = r->ok;
  cx->status = r->status;
  cx->resumed = r->resumed;
  cx->early_data = r->early_data;
  U64 n =
      r->alpn.size < sizeof cx->alpn - 1 ? r->alpn.size : sizeof cx->alpn - 1;
  if (n) MemoryCopy(cx->alpn, r->alpn.str, n);
  cx->alpn[n] = 0;
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
    printf("[zero_rtt_h3_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  const char *url = "https://www.cloudflare.com/";
  EventLoop loop;
  loop_init(&loop);
  defer {
    loop_shutdown(&loop);
  };  // the two clients are cleaned explicitly
      // below (one freed before the next is created)

  //- 0-RTT ENABLED over H3
  //-----------------------------------------------------
  Client c;
  client_init(&c, &loop, profile_chrome148(), profile_chrome148_h3(),
              HttpVersion_Auto, /*verify=*/1);
  CHECK(client_ok(&c));
  client_set_early_data_enabled(&c, 1);  // implies resumption

  Ctx a = fetch_once(&c, &loop, url);  // #1 H2 -> learns alt-svc h3
  Ctx b =
      fetch_once(&c, &loop, url);  // #2 H3 fresh -> caches ticket + 0-RTT TP
  Ctx d = fetch_once(&c, &loop, url);  // #3 H3 -> offers 0-RTT
  fprintf(stderr,
          "  a{alpn=%s} b{alpn=%s resumed=%d early=%d} "
          "d{alpn=%s resumed=%d early=%d}\n",
          a.alpn, b.alpn, b.resumed, b.early_data, d.alpn, d.resumed,
          d.early_data);
  CHECK(a.got);
  CHECK(b.got &&
        str8_match(str8_cstring(b.alpn), str8_lit("h3")));  // routed H3
  CHECK(!b.early_data);  // the fresh H3 conn can't 0-RTT
  CHECK(d.got && str8_match(str8_cstring(d.alpn), str8_lit("h3")));
  CHECK(d.resumed);     // the H3 reconnect resumed the TLS session
  CHECK(d.early_data);  // ...and the request went as 0-RTT (server accepted it)
  client_cleanup(&c);

  //- control: H3 with 0-RTT OFF never reports early_data
  //------------------------
  Client off;
  client_init(&off, &loop, profile_chrome148(), profile_chrome148_h3(),
              HttpVersion_Auto, /*verify=*/1);
  client_set_resumption_enabled(&off, 1);  // 1-RTT resumption, NO early data
  fetch_once(&off, &loop, url);            // #1 H2
  fetch_once(&off, &loop, url);            // #2 H3 fresh
  Ctx e = fetch_once(&off, &loop, url);    // #3 H3 resumed (1-RTT)
  fprintf(stderr, "  control: e{alpn=%s resumed=%d early=%d}\n", e.alpn,
          e.resumed, e.early_data);
  CHECK(!e.early_data);  // opt-in: default path never 0-RTTs
  client_cleanup(&off);

  fprintf(stderr, "[zero_rtt_h3_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
