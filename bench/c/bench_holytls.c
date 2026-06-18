// holytls benchmark harness — one of the per-client native programs that share
// a CLI + JSON-output contract (see bench/HARNESS.md), so the orchestrator can
// compare clients apples-to-apples.
//
// Model: a single libuv loop (holytls is single-threaded by design) drives up to
// --concurrency requests in flight via a slot-based refill driver. Two phases:
// a warmup phase (discarded; primes the connection/caches) then a measured phase
// (records per-request latency, handshake time, bytes, ALPN, errors). Closed
// loop (each slot waits for full delivery before its next request) → throughput
// is measured/wall and the latency samples are per-request service times.
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE  // getrusage + clock_gettime/CLOCK_MONOTONIC on glibc
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

#include "base/base.h"
#include "base/arena.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

typedef struct {
  const char *url, *protocol, *mode, *ca, *out;
  U64 requests, concurrency, warmup, max_conns;
  B32 single_thread, max_conns_set;
} Cfg;

typedef struct Bench Bench;
typedef struct { Bench *b; U64 start_ns; } Slot;

struct Bench {
  Client *c;
  EventLoop *loop;
  RequestParams req;
  U64 target, launched, completed, measured;
  B32 measuring;
  double *lat_ms;   // [requests]
  double *hs_ms;    // [requests] handshake (timing.tls_ms)
  U64 bytes, errors;
  int status;
  char alpn[16];
  B32 first_set;
  char err_sample[160];
};

static U64 now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (U64)ts.tv_sec * 1000000000ull + (U64)ts.tv_nsec;
}

static int cmp_dbl(const void *a, const void *b) {
  double x = *(const double *)a, y = *(const double *)b;
  return (x > y) - (x < y);
}

// Nearest-rank percentile over a SORTED array.
static double pct(const double *sorted, U64 n, double p) {
  if (n == 0) return 0.0;
  U64 rank = (U64)((p / 100.0) * (double)n + 0.999999);  // ceil(p%*n)
  if (rank == 0) rank = 1;
  if (rank > n) rank = n;
  return sorted[rank - 1];
}

static void fire(Bench *b, Slot *s);  // forward decl (used by on_resp)

static void on_resp(void *user, const Response *resp) {
  Slot *s = (Slot *)user;
  Bench *b = s->b;
  U64 end = now_ns();
  double ms = (double)(end - s->start_ns) / 1e6;
  if (resp->ok) {
    if (b->measuring) {
      b->lat_ms[b->measured] = ms;
      b->hs_ms[b->measured] = (double)resp->timing.tls_ms;
      b->bytes += resp->body_len;
      if (!b->first_set) {
        b->first_set = 1;
        b->status = resp->status;
        if (getenv("BENCH_DEBUG"))
          fprintf(stderr, "[dbg] ok=%d status=%d body_len=%llu alpn=%.*s\n",
                  (int)resp->ok, resp->status,
                  (unsigned long long)resp->body_len, (int)resp->alpn.size,
                  resp->alpn.str ? (const char *)resp->alpn.str : "");
        U64 n = resp->alpn.size < sizeof(b->alpn) - 1 ? resp->alpn.size
                                                      : sizeof(b->alpn) - 1;
        if (resp->alpn.str && n) memcpy(b->alpn, resp->alpn.str, n);
        b->alpn[n] = 0;
      }
      b->measured++;
    }
  } else {
    b->errors++;
    if (b->err_sample[0] == 0 && resp->error) {
      strncpy(b->err_sample, resp->error, sizeof(b->err_sample) - 1);
    }
  }
  b->completed++;
  if (b->launched < b->target)
    fire(b, s);
  else if (b->completed >= b->target)
    loop_stop(b->loop);
}

// launch_one passes NULL cb above to keep the signature simple; redo it here so
// the real callback is wired (client_request needs the cb at call time).
static void fire(Bench *b, Slot *s) {
  if (b->launched >= b->target) return;
  b->launched++;
  s->start_ns = now_ns();
  client_request(b->c, &b->req, on_resp, s);
}

// Run one phase to completion at concurrency `conc`. Returns wall seconds.
static double run_phase(Bench *b, Slot *slots, U64 conc, U64 target,
                        B32 measuring) {
  b->target = target;
  b->launched = b->completed = b->measured = 0;
  b->measuring = measuring;
  b->bytes = b->errors = 0;
  U64 first = target < conc ? target : conc;
  U64 t0 = now_ns();
  for (U64 i = 0; i < first; i++) fire(b, &slots[i]);
  loop_run(b->loop);
  return (double)(now_ns() - t0) / 1e9;
}

static const char *norm_alpn(const char *a) {
  if (strcmp(a, "h2") == 0) return "h2";
  if (strcmp(a, "h3") == 0) return "h3";
  if (a[0] == 0 || strncmp(a, "http/1", 6) == 0 || strcmp(a, "h1") == 0)
    return "h1";
  return a;
}

int main(int argc, char **argv) {
  Cfg cfg = {0};
  cfg.protocol = "h2";
  cfg.mode = "keepalive";
  cfg.requests = 1000;
  cfg.concurrency = 1;
  cfg.warmup = 200;
  cfg.single_thread = 1;
  for (int i = 1; i < argc - 1; i++) {
    const char *k = argv[i], *v = argv[i + 1];
#define ARG(name) (strcmp(k, "--" name) == 0)
    if (ARG("url")) cfg.url = v, i++;
    else if (ARG("protocol")) cfg.protocol = v, i++;
    else if (ARG("mode")) cfg.mode = v, i++;
    else if (ARG("requests")) cfg.requests = strtoull(v, 0, 10), i++;
    else if (ARG("concurrency")) cfg.concurrency = strtoull(v, 0, 10), i++;
    else if (ARG("warmup")) cfg.warmup = strtoull(v, 0, 10), i++;
    else if (ARG("single-thread")) cfg.single_thread = (B32)atoi(v), i++;
    else if (ARG("max-conns")) cfg.max_conns = strtoull(v, 0, 10), cfg.max_conns_set = 1, i++;
    else if (ARG("ca")) cfg.ca = v, i++;
    else if (ARG("out")) cfg.out = v, i++;
#undef ARG
  }
  if (!cfg.url) { fprintf(stderr, "bench_holytls: --url required\n"); return 2; }
  if (cfg.concurrency == 0) cfg.concurrency = 1;

  B32 keepalive = strcmp(cfg.mode, "keepalive") == 0;
  HttpVersion mode;
  const QuicProfile *h3 = NULL;
  if (strcmp(cfg.protocol, "h1") == 0) mode = HttpVersion_H1;
  else if (strcmp(cfg.protocol, "h3") == 0) { mode = HttpVersion_H3; h3 = profile_chrome149_h3(); }
  else mode = HttpVersion_H2;

  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_chrome149(), h3, mode, /*verify=*/1);
  if (cfg.ca && !client_add_ca_file(&c, cfg.ca)) {
    fprintf(stderr, "bench_holytls: could not load CA %s\n", cfg.ca);
    return 2;
  }
  // Controlled runs: resumption / 0-RTT / ECH stay off (defaults). Pooling on
  // for keepalive (reuse one conn), off for cold (fresh conn per request).
  U64 maxc = cfg.max_conns_set ? cfg.max_conns : (keepalive ? 1 : 0);
  client_set_max_conns_per_origin(&c, maxc);
  // Resumption/0-RTT/ECH stay OFF (defaults): holytls cold does a full handshake
  // per connection. NOTE the cold caveat (bench/HARNESS.md + the report): some
  // clients (e.g. httpcloak) keep TLS tickets and 1-RTT *resume* the fresh
  // connection, so cold = "new-connection cost", not a strict full-handshake
  // comparison. Keepalive (steady-state) is the rigorous headline.

  Bench b = {0};
  b.c = &c;
  b.loop = &loop;
  b.req.url = str8_cstring(cfg.url);
  b.req.no_redirects = 1;  // single hop — measure one request, not a chain
  b.lat_ms = (double *)malloc(sizeof(double) * (cfg.requests ? cfg.requests : 1));
  b.hs_ms = (double *)malloc(sizeof(double) * (cfg.requests ? cfg.requests : 1));
  Slot *slots = (Slot *)calloc(cfg.concurrency, sizeof(Slot));
  for (U64 i = 0; i < cfg.concurrency; i++) slots[i].b = &b;

  // Warmup (discarded), then rebase arena stats + CPU + pool counters and run
  // the measured phase. connections_created reports NEW connections opened
  // *during* the measured phase (keepalive reuses the warmup conn => 0; cold is
  // non-pooled => one per request).
  if (cfg.warmup) run_phase(&b, slots, cfg.concurrency, cfg.warmup, /*measuring=*/0);
  arena_stats_reset();
  PoolStats ps0 = client_pool_stats(&c);
  struct rusage ru0;
  getrusage(RUSAGE_SELF, &ru0);
  double wall_s = run_phase(&b, slots, cfg.concurrency, cfg.requests, /*measuring=*/1);
  struct rusage ru1;
  getrusage(RUSAGE_SELF, &ru1);
  ArenaStats as = arena_stats();
  PoolStats ps = client_pool_stats(&c);

  qsort(b.lat_ms, b.measured, sizeof(double), cmp_dbl);
  qsort(b.hs_ms, b.measured, sizeof(double), cmp_dbl);
  double rps = wall_s > 0 ? (double)b.measured / wall_s : 0.0;
  double cpu_u = (double)(ru1.ru_utime.tv_sec - ru0.ru_utime.tv_sec) * 1000.0 +
                 (double)(ru1.ru_utime.tv_usec - ru0.ru_utime.tv_usec) / 1000.0;
  double cpu_s = (double)(ru1.ru_stime.tv_sec - ru0.ru_stime.tv_sec) * 1000.0 +
                 (double)(ru1.ru_stime.tv_usec - ru0.ru_stime.tv_usec) / 1000.0;
  U64 conns = keepalive ? (ps.conns_created - ps0.conns_created) : b.measured;
  U64 reuses = ps.reuses - ps0.reuses;

  char esc[200] = {0};  // minimal JSON-escape of the error sample
  for (size_t i = 0, j = 0; b.err_sample[i] && j < sizeof(esc) - 2; i++) {
    char ch = b.err_sample[i];
    if (ch == '"' || ch == '\\') esc[j++] = '\\';
    esc[j++] = ch;
  }

  FILE *f = stdout;
  if (cfg.out) { f = fopen(cfg.out, "w"); if (!f) f = stdout; }
  fprintf(f,
    "{\n"
    "  \"client\": \"holytls\",\n"
    "  \"client_version\": \"src\",\n"
    "  \"protocol_requested\": \"%s\",\n"
    "  \"protocol_negotiated\": \"%s\",\n"
    "  \"mode\": \"%s\",\n"
    "  \"concurrency\": %llu,\n"
    "  \"single_thread\": %d,\n"
    "  \"requests\": %llu,\n"
    "  \"warmup\": %llu,\n"
    "  \"throughput_rps\": %.2f,\n"
    "  \"latency_ms\": {\"p50\": %.3f, \"p90\": %.3f, \"p99\": %.3f, \"p999\": %.3f, \"max\": %.3f},\n"
    "  \"handshake_ms\": {\"p50\": %.3f},\n"
    "  \"connections_created\": %llu,\n"
    "  \"pool_reuses\": %llu,\n"
    "  \"bytes_received\": %llu,\n"
    "  \"status\": %d,\n"
    "  \"errors\": %llu,\n"
    "  \"error_sample\": \"%s\",\n"
    "  \"peak_rss_kb\": %ld,\n"
    "  \"cpu_user_ms\": %.1f,\n"
    "  \"cpu_sys_ms\": %.1f,\n"
    "  \"wall_ms\": %.1f,\n"
    "  \"alloc\": {\"arenas_created\": %llu, \"bytes_reserved\": %llu}\n"
    "}\n",
    cfg.protocol, norm_alpn(b.alpn), cfg.mode,
    (unsigned long long)cfg.concurrency, (int)cfg.single_thread,
    (unsigned long long)b.measured, (unsigned long long)cfg.warmup, rps,
    pct(b.lat_ms, b.measured, 50), pct(b.lat_ms, b.measured, 90),
    pct(b.lat_ms, b.measured, 99), pct(b.lat_ms, b.measured, 99.9),
    pct(b.lat_ms, b.measured, 100),
    pct(b.hs_ms, b.measured, 50),
    (unsigned long long)conns, (unsigned long long)reuses,
    (unsigned long long)b.bytes, b.status, (unsigned long long)b.errors, esc,
    ru1.ru_maxrss, cpu_u, cpu_s, wall_s * 1000.0,
    (unsigned long long)as.arenas_created, (unsigned long long)as.bytes_reserved);
  if (f != stdout) fclose(f);

  free(b.lat_ms); free(b.hs_ms); free(slots);
  client_cleanup(&c);
  loop_shutdown(&loop);
  return b.measured == 0 ? 1 : 0;
}
