// Live real-world reachability check: drive the Chrome-148 Client (H2-first,
// alt-svc -> QUIC) at the current top-10 most-visited websites and confirm a
// TLS + HTTP exchange completes with each — i.e. the impersonation works
// against real CDNs / WAFs, not just the fingerprint oracles. Thresholds are
// lenient (real sites redirect / rate-limit / block, and DNS can flake).
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

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

typedef struct SiteResult SiteResult;
struct SiteResult {
  const char *url;
  B32 ok;
  int status;
  char alpn[8];
  U64 bytes;
  Timing timing;  // per-request DNS/TCP/TLS/Total (ms)
  const char *error;
};

typedef struct TopCtx TopCtx;
struct TopCtx {
  SiteResult results[16];
  int n;
  int done;
  uv_timer_t *watchdog;
  B32 watchdog_closed;
};

typedef struct Slot Slot;
struct Slot {
  TopCtx *ctx;
  int i;
};

internal void on_watchdog(uv_timer_t *t) { uv_stop((uv_loop_t *)t->data); }

// Format a millisecond count with a trailing "ms" unit into `buf`.
internal const char *fmt_ms(char *buf, U64 cap, U64 ms) {
  snprintf(buf, cap, "%llums", (unsigned long long)ms);
  return buf;
}

internal void on_site(void *user, const Response *r) {
  Slot *sl = (Slot *)user;
  TopCtx *cx = sl->ctx;
  SiteResult *s = &cx->results[sl->i];
  s->ok = r->ok;
  s->status = r->status;
  U64 an =
      r->alpn.size < sizeof s->alpn - 1 ? r->alpn.size : sizeof s->alpn - 1;
  MemoryCopy(s->alpn, r->alpn.str, an);
  s->alpn[an] = 0;
  s->bytes = r->body_len;
  s->timing = r->timing;
  s->error = (!r->ok && r->error) ? r->error : "";
  if (++cx->done == cx->n && !cx->watchdog_closed) {
    cx->watchdog_closed = 1;
    uv_timer_stop(cx->watchdog);
    uv_close((uv_handle_t *)cx->watchdog, 0);
  }
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[top_sites_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }

  // Top-10 most-visited sites (global). www. forms avoid the apex->www 301
  // since the client does not follow redirects yet.
  const char *sites[] = {
      "https://www.google.com/",
      "https://www.youtube.com/",
      "https://www.facebook.com/",
      "https://www.instagram.com/",
      "https://x.com/",
      "https://www.wikipedia.org/",
      "https://www.reddit.com/",
      "https://www.amazon.com/",
      "https://chatgpt.com/",
      "https://www.tiktok.com/",
  };
  int n = (int)ArrayCount(sites);

  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client client;
  client_init_dual(&client, &loop, profile_chrome148(), profile_chrome148_h3(),
                   /*verify=*/1);
  defer { client_cleanup(&client); };
  CHECK(client_ok(&client));

  TopCtx cx;
  MemoryZeroStruct(&cx);
  cx.n = n;
  uv_timer_t watchdog;
  cx.watchdog = &watchdog;
  Slot slots[16];

  // Watchdog: stop the loop after 60s so one stuck site can't hang the test.
  uv_timer_init(loop_uv(&loop), &watchdog);
  watchdog.data = loop_uv(&loop);
  uv_timer_start(&watchdog, on_watchdog, 60000, 0);

  for (int i = 0; i < n; ++i) {
    cx.results[i].url = sites[i];
    slots[i].ctx = &cx;
    slots[i].i = i;
    client_get(&client, str8_cstring(sites[i]), on_site, &slots[i]);
  }
  loop_run(&loop);

  int reachable = 0, ok_http = 0, h2 = 0, h3 = 0;
  U64 total_sum = 0, slowest = 0;
  const char *slowest_url = "-";
  // Timing columns (dns/tcp/tls/total); tcp is 0 over HTTP/3.
  fprintf(stderr, "\n  %-30s %-3s %-6s %-4s %8s %6s %6s %6s %7s  %s\n", "site",
          "ok", "status", "alpn", "bytes", "dns", "tcp", "tls", "total",
          "note");
  for (int i = 0; i < n; ++i) {
    SiteResult *s = &cx.results[i];
    char db[12], tb[12], lb[12], tob[12];
    fprintf(stderr, "  %-30s %-3s %-6d %-4s %8llu %6s %6s %6s %7s  %s\n",
            s->url, s->ok ? "yes" : "NO", s->status, s->alpn[0] ? s->alpn : "-",
            (unsigned long long)s->bytes,
            fmt_ms(db, sizeof db, s->timing.dns_ms),
            fmt_ms(tb, sizeof tb, s->timing.tcp_ms),
            fmt_ms(lb, sizeof lb, s->timing.tls_ms),
            fmt_ms(tob, sizeof tob, s->timing.total_ms), s->error);
    if (s->ok) {
      reachable++;
      CHECK(s->timing.total_ms > 0);  // a real exchange always takes ms
      total_sum += s->timing.total_ms;
      if (s->timing.total_ms > slowest) {
        slowest = s->timing.total_ms;
        slowest_url = s->url;
      }
    }
    if (s->status >= 200 && s->status < 400) ok_http++;
    if (strcmp(s->alpn, "h2") == 0) h2++;
    if (strcmp(s->alpn, "h3") == 0) h3++;
  }
  fprintf(stderr,
          "\n  reachable (TLS+HTTP ok): %d/%d   2xx-3xx: %d   alpn: h2=%d "
          "h3=%d\n",
          reachable, n, ok_http, h2, h3);
  fprintf(stderr, "  timing: avg total=%llums   slowest=%llums (%s)\n",
          (unsigned long long)(reachable ? total_sum / (U64)reachable : 0),
          (unsigned long long)slowest, slowest_url);

  // Lenient: tolerate the odd block / redirect / DNS flake.
  CHECK(reachable >= 7);
  CHECK(ok_http >= 5);

  fprintf(stderr, "[top_sites_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
