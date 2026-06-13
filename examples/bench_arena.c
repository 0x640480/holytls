// bench_arena — measures per-request arena churn (and the throughput it costs)
// so we can decide, with numbers, whether to recycle per-request arenas instead
// of arena_alloc()/arena_release()ing one per request (raddebugger's model).
//
// It stands up the shared in-process loopback origin (tests/support/loopback_server)
// answering bodyless 200s, drives it with a holytls Client for exactly N requests
// (seq = one in flight; concurrent = C in flight, multiplexed when pooled), and
// reports req/s plus the per-request arena deltas from HOLYTLS_ARENA_STATS:
//   arenas_created/N, arenas_released/N, blocks_allocated/N, bytes_reserved/N,
//   peak_live_arenas.
// In steady state today each request is ~1 arena_alloc + ~1 block malloc; the
// recycle target is ~0. Build with -DHOLYTLS_ARENA_STATS=ON or the arena deltas
// read as zero (a warning is printed). Bodyless 200s carry no DATA frames, so the
// H2 static receive window is never touched and the run is unbounded.
//
// Build:  cmake -B build -DHOLYTLS_ARENA_STATS=ON && cmake --build build --target bench_arena
// Run:    ./build/bench_arena [--mode seq|concurrent] [--requests N] [--concurrency C]
//                             [--pool 0|1] [--proto h2|h1]
//
// Optional malloc/free attribution (what share of total per-request allocator
// traffic the arena is): configure with -DHOLYTLS_BENCH_WRAP=ON, which links the
// --wrap shims below and prints malloc/calloc/realloc/free counts too.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"
#include "support/loopback_server.h"

// --- optional --wrap allocator counters (HOLYTLS_BENCH_WRAP) ------------------
#ifdef HOLYTLS_BENCH_WRAP
global U64 g_n_malloc, g_n_calloc, g_n_realloc, g_n_free;
extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);
extern void __real_free(void *);
void *__wrap_malloc(size_t n) {
  g_n_malloc++;
  return __real_malloc(n);
}
void *__wrap_calloc(size_t a, size_t b) {
  g_n_calloc++;
  return __real_calloc(a, b);
}
void *__wrap_realloc(void *p, size_t n) {
  g_n_realloc++;
  return __real_realloc(p, n);
}
void __wrap_free(void *p) {
  g_n_free++;
  __real_free(p);
}
#endif

// --- driver: keep `concurrency` round-trips in flight for `target` requests ---
typedef struct Bench Bench;
struct Bench {
  EventLoop *loop;
  Client *client;
  String8 url;
  U64 target;    // total requests to run
  U64 issued;    // requests started
  U64 done;      // requests completed
  U64 errors;    // non-200 / transport failures
  int inflight;  // currently outstanding
};

internal void on_resp(void *user, const Response *r);
internal void fire(Bench *b) {
  b->issued++;
  b->inflight++;
  client_get(b->client, b->url, on_resp, b);
}
internal void on_resp(void *user, const Response *r) {
  Bench *b = (Bench *)user;
  b->done++;
  b->inflight--;
  if (!r->ok || r->status != 200) b->errors++;
  if (b->issued < b->target)
    fire(b);  // refill the slot
  else if (b->done >= b->target)
    uv_stop(loop_uv(b->loop));
}

// Server: every request -> bodyless 200 (no DATA frames; window untouched).
internal void bench_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)req;
  (void)user;
  resp->status = 200;
}

global Bench *g_b;
internal void wd_cb(uv_timer_t *t) {
  (void)t;
  fprintf(stderr, "  [watchdog] timed out: done=%llu inflight=%d\n",
          (unsigned long long)g_b->done, g_b->inflight);
  uv_stop(loop_uv(g_b->loop));
}

internal void usage(const char *a0) {
  fprintf(stderr,
          "usage: %s [--mode seq|concurrent] [--requests N] [--concurrency C]\n"
          "          [--pool 0|1] [--proto h2|h1]\n"
          "  --mode         seq = 1 in flight; concurrent = C in flight (default seq)\n"
          "  --requests N   total requests to run (default 50000)\n"
          "  --concurrency  in-flight requests in concurrent mode (default 256)\n"
          "  --pool 0|1     0 = direct per-request conn; 1 = one pooled multiplexed\n"
          "                 conn per origin (default 1)\n"
          "  --proto h2|h1  forced transport (default h2)\n",
          a0);
}

int main(int argc, char **argv) {
  const char *mode = "seq";
  U64 requests = 50000;
  int concurrency = 256;
  int pool = 1;
  const char *proto = "h2";
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--mode") && i + 1 < argc)
      mode = argv[++i];
    else if (!strcmp(argv[i], "--requests") && i + 1 < argc)
      requests = strtoull(argv[++i], 0, 10);
    else if (!strcmp(argv[i], "--concurrency") && i + 1 < argc)
      concurrency = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--pool") && i + 1 < argc)
      pool = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--proto") && i + 1 < argc)
      proto = argv[++i];
    else {
      usage(argv[0]);
      return 2;
    }
  }
  B32 seq = strcmp(mode, "concurrent") != 0;
  if (seq) concurrency = 1;
  if (concurrency < 1) concurrency = 1;
  if (requests < (U64)concurrency) requests = (U64)concurrency;
  B32 h1 = strcmp(proto, "h1") == 0;

  EventLoop loop;
  loop_init(&loop);

  U16 port = 0;
  LbServer *srv = lb_server_start(&loop, h1 ? LB_ALPN_H1 : LB_ALPN_H2,
                                  bench_handler, 0, &port);
  char url[64];
  snprintf(url, sizeof url, "https://127.0.0.1:%u/", port);

  Client client;
  client_init(&client, &loop, profile_chrome148(), /*verify=*/0);
  client_set_http_version(&client, h1 ? HttpVersion_H1 : HttpVersion_H2);
  if (pool) client_set_max_conns_per_origin(&client, 1);

  Bench b;
  MemoryZeroStruct(&b);
  b.loop = &loop;
  b.client = &client;
  b.url = str8_cstring(url);
  b.target = requests;
  g_b = &b;

  uv_timer_t wd;
  uv_timer_init(loop_uv(&loop), &wd);
  uv_timer_start(&wd, wd_cb, 120000, 0);  // generous: this is a long run

  // Measure: reset the arena counters, run exactly N requests, read the deltas.
  // The first conn's setup arenas (conn + H2Session) are counted too but are O(1)
  // and negligible against a 50k run.
  arena_stats_reset();
  U64 t0 = uv_hrtime();
  for (int i = 0; i < concurrency; ++i) fire(&b);
  loop_run(&loop);
  U64 t1 = uv_hrtime();
  ArenaStats st = arena_stats();

  uv_timer_stop(&wd);
  uv_close((uv_handle_t *)&wd, 0);

  double secs = (double)(t1 - t0) / 1e9;
  double N = (double)b.done;
  printf("\n=== holytls arena per-request benchmark ===\n");
  printf("transport     : %s%s\n", h1 ? "HTTP/1.1" : "HTTP/2",
         pool ? ", pooled (1 conn/origin)" : ", direct (conn/request)");
  printf("mode          : %s", seq ? "sequential (1 in flight)" : "concurrent");
  if (!seq) printf(" (%d in flight)", concurrency);
  printf("\n");
  printf("requests      : %llu done, %llu errors\n", (unsigned long long)b.done,
         (unsigned long long)b.errors);
  printf("wall time     : %.3f s\n", secs);
  printf("throughput    : %.0f req/s\n", N > 0 ? N / secs : 0);
  printf("\nper-request arena deltas (HOLYTLS_ARENA_STATS):\n");
  if (st.arenas_created == 0) {
    printf("  (zero — rebuild with -DHOLYTLS_ARENA_STATS=ON to see arena churn)\n");
  } else {
    printf("  arenas_created   : %llu total  (%.3f / req)\n",
           (unsigned long long)st.arenas_created, st.arenas_created / N);
    printf("  arenas_released  : %llu total  (%.3f / req)\n",
           (unsigned long long)st.arenas_released, st.arenas_released / N);
    printf("  blocks_allocated : %llu total  (%.3f / req)\n",
           (unsigned long long)st.blocks_allocated, st.blocks_allocated / N);
    printf("  bytes_reserved   : %llu total  (%.0f / req)\n",
           (unsigned long long)st.bytes_reserved, st.bytes_reserved / N);
    printf("  peak_live_arenas : %llu\n",
           (unsigned long long)st.peak_live_arenas);
  }
#ifdef HOLYTLS_BENCH_WRAP
  printf("\nprocess allocator traffic (--wrap, incl. server + libs):\n");
  printf("  malloc  : %llu  (%.3f / req)\n", (unsigned long long)g_n_malloc,
         g_n_malloc / N);
  printf("  calloc  : %llu  (%.3f / req)\n", (unsigned long long)g_n_calloc,
         g_n_calloc / N);
  printf("  realloc : %llu  (%.3f / req)\n", (unsigned long long)g_n_realloc,
         g_n_realloc / N);
  printf("  free    : %llu  (%.3f / req)\n", (unsigned long long)g_n_free,
         g_n_free / N);
  printf("  arena alloc share : %.1f%% of malloc+calloc\n",
         (g_n_malloc + g_n_calloc)
             ? 100.0 * (double)st.blocks_allocated /
                   (double)(g_n_malloc + g_n_calloc)
             : 0.0);
#endif

  // Teardown: drain the client pool, pump close callbacks, stop the origin, pump.
  client_cleanup(&client);
  for (int g = 0; g < 2000 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  lb_server_stop(srv);
  for (int g = 0; g < 2000 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);
  return b.errors ? 1 : 0;
}
