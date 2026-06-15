// Live TLS 1.3 0-RTT (early data). With early data enabled, the first request
// to an origin is a fresh full handshake (capturing a 0-RTT-capable ticket);
// the second request writes the GET as early data DURING the handshake and,
// when the server accepts it, completes in 1-RTT with r->early_data set. The
// control with 0-RTT OFF must never report early_data. Probes several origins
// so the assertion targets one that actually supports 0-RTT. Network-gated: set
// HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "base/base.h"
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
  B32 called;  // the response callback fired at all (distinguishes a hang)
  B32 got;     // and it reported success (r->ok)
  int status;
  B32 resumed;
  B32 early_data;
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->called = 1;
  cx->got = r->ok;
  cx->status = r->status;
  cx->resumed = r->resumed;
  cx->early_data = r->early_data;
  if (!r->ok)
    fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
}

internal void watchdog_cb(uv_timer_t *t) { uv_stop(t->loop); }

internal Ctx fetch_once(Client *c, EventLoop *loop, const char *url) {
  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(c, str8_cstring(url), on_resp, &cx);
  loop_run(loop);
  return cx;
}

// Drive one origin twice with 0-RTT enabled; report whether req2 used early
// data.
internal B32 probe_origin(EventLoop *loop, const char *url) {
  Client c;
  client_init(&c, loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  client_set_early_data_enabled(&c, 1);  // implies resumption
  Ctx a = fetch_once(&c, loop, url);     // fresh; captures the ticket
  Ctx b = fetch_once(&c, loop, url);     // offers it as 0-RTT
  fprintf(stderr,
          "  %-32s a{ok=%d resumed=%d early=%d} b{ok=%d resumed=%d early=%d}\n",
          url, a.got, a.resumed, a.early_data, b.got, b.resumed, b.early_data);
  B32 ok = a.got && b.got && !a.early_data && b.resumed;
  CHECK(ok);
  client_cleanup(&c);
  return b.early_data;  // did 0-RTT actually get accepted?
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[zero_rtt_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  EventLoop loop;
  loop_init(&loop);

  // Candidate 0-RTT-capable origins (Cloudflare pioneered 0-RTT).
  const char *origins[] = {
      "https://cloudflare.com/",
      "https://www.cloudflare.com/",
      "https://blog.cloudflare.com/",
  };
  B32 any_0rtt = 0;
  for (U64 i = 0; i < ArrayCount(origins); ++i)
    if (probe_origin(&loop, origins[i])) any_0rtt = 1;
  CHECK(any_0rtt);  // at least one origin accepted our 0-RTT early data

  // A request LARGER than the server's early-data limit must still complete:
  // the bytes past the cap are queued and flushed as 1-RTT after the handshake
  // (the overflow-resend path). Without it the truncated request would hang —
  // so a watchdog stops the loop and the test fails loudly instead of hanging.
  {
    Client big;
    client_init(&big, &loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/1);
    client_set_early_data_enabled(&big, 1);
    fetch_once(&big, &loop,
               "https://cloudflare.com/");  // warm the 0-RTT ticket

    uv_timer_t watchdog;
    uv_timer_init(loop_uv(&loop), &watchdog);
    uv_timer_start(&watchdog, watchdog_cb, 25000, 0);
    uv_unref((uv_handle_t *)&watchdog);  // don't keep the loop alive on success

    // ~18KB of header value — over the typical 16KB early-data cap (so the
    // request straddles the 0-RTT / 1-RTT boundary) but under the server's
    // header limit, so it should still succeed end-to-end.
    Arena *a = arena_alloc();
    U64 n = 18000;
    U8 *big_val = push_array(a, U8, n + 1);
    for (U64 i = 0; i < n; ++i) big_val[i] = 'a' + (U8)(i % 26);
    big_val[n] = 0;
    Header hdr[1] = {{str8_lit("x-holytls-big"), str8((U8 *)big_val, n), 0}};
    Ctx e;
    MemoryZeroStruct(&e);
    RequestParams params = {.method = Method_GET,
                            .url = str8_lit("https://cloudflare.com/"),
                            .headers = hdr,
                            .header_count = 1};
    client_request(&big, &params, on_resp, &e);
    loop_run(&loop);
    uv_close((uv_handle_t *)&watchdog, 0);
    loop_run(&loop);  // let the watchdog handle finish closing
    fprintf(stderr,
            "  big-request over 0-RTT: called=%d got=%d status=%d early=%d\n",
            e.called, e.got, e.status, e.early_data);
    CHECK(e.called);  // it RESOLVED (any status) rather than hanging on
                      // truncation
    arena_release(a);
    client_cleanup(&big);
  }

  // A failed DNS resolution must cleanly error (and not leak the request arena
  // — checked under ASan): the connection now always has a handle to close.
  {
    Client dns;
    client_init(&dns, &loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/1);
    Ctx f;
    MemoryZeroStruct(&f);
    client_get(&dns, str8_lit("https://no-such-host.invalid.holytls/"), on_resp,
               &f);
    loop_run(&loop);
    fprintf(stderr, "  dns-failure: called=%d ok=%d\n", f.called, f.got);
    CHECK(f.called &&
          !f.got);  // the failure was delivered (ok=0), no leak/hang
    client_cleanup(&dns);
  }

  // Control: with 0-RTT OFF, early_data must never be reported (default path).
  Client off;
  client_init(&off, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  client_set_resumption_enabled(&off,
                                1);  // 1-RTT resumption, but NO early data
  Ctx c = fetch_once(&off, &loop, "https://cloudflare.com/");
  Ctx d = fetch_once(&off, &loop, "https://cloudflare.com/");
  fprintf(stderr, "  control(no-0rtt): c{early=%d} d{resumed=%d early=%d}\n",
          c.early_data, d.resumed, d.early_data);
  CHECK(!c.early_data && !d.early_data);
  client_cleanup(&off);

  loop_shutdown(&loop);
  fprintf(stderr, "[zero_rtt_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
