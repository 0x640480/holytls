// Live verification of connection pooling + multiplexing.
//   H2: one origin, 3 sequential (each fired from the prior response callback —
//       the re-entrant path) + N concurrent GETs ride a SINGLE connection.
//   H3: a dual client warms alt-svc over H2, then sequential + concurrent GETs
//       over the now-h3 origin ride a SINGLE pooled QUIC connection (one new
//       conn for all of them; every request after the first reuses it).
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "base/base.h"
#include "base/defer.h"
#include "core/client.h"
#include "core/json.h"
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
  Client *client;
  const char *url;
  int seq_total, seq_done;  // sequential chaining (0 = concurrent phase)
  int done, ok, n_h2, n_h3;
};

internal void tally(Ctx *cx, const Response *r) {
  cx->done++;
  if (r->ok && r->status == 200) cx->ok++;
  if (str8_match(r->alpn, str8_lit("h2"))) cx->n_h2++;
  if (str8_match(r->alpn, str8_lit("h3"))) cx->n_h3++;
}

// Fires the next request from inside the response callback: the re-entrant path
// that must defer the submit (no transport re-entry) and reuse the same conn.
internal void seq_cb(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  tally(cx, r);
  cx->seq_done++;
  if (cx->seq_done < cx->seq_total)
    client_get(cx->client, str8_cstring(cx->url), seq_cb, cx);
}

internal void conc_cb(void *user, const Response *r) { tally((Ctx *)user, r); }

// H3 fingerprint through the pool: request #1 (H2) learns alt-svc h3, request #2
// (fired from its callback) routes over pooled HTTP/3 and reports the h3_hash —
// which must equal the direct-path golden (fingerprint_h3_test).
#define H3FP_URL "https://quic.browserleaks.com/?minify=1"
typedef struct H3Fp H3Fp;
struct H3Fp {
  Client *client;
  int phase;
  B32 got1, got2;
  char alpn1[8], alpn2[8], h3hash[64];
};
internal void h3fp_copy(char *dst, U64 cap, String8 v) {
  U64 n = v.size < cap - 1 ? v.size : cap - 1;
  MemoryCopy(dst, v.str, n);
  dst[n] = 0;
}
internal void h3fp_cb(void *user, const Response *r) {
  H3Fp *cx = (H3Fp *)user;
  if (cx->phase == 1) {
    cx->got1 = r->ok;
    h3fp_copy(cx->alpn1, sizeof cx->alpn1, r->alpn);
    cx->phase = 2;  // alt-svc now cached -> this one routes over H3/QUIC
    client_get(cx->client, str8_lit(H3FP_URL), h3fp_cb, cx);
  } else {
    cx->got2 = r->ok;
    h3fp_copy(cx->alpn2, sizeof cx->alpn2, r->alpn);
    if (r->ok)
      json_get_str(str8((U8 *)r->body, r->body_len), "h3_hash", cx->h3hash,
                   sizeof cx->h3hash);
  }
}

// Fire `total` sequential then `nconc` concurrent GETs at `url` on `client`,
// returning the combined h3 count via *out_h3 and h2 count via *out_h2.
internal void run_phase(Client *client, EventLoop *loop, const char *url,
                        int total, int nconc, int *out_h2, int *out_h3) {
  Ctx s;
  MemoryZeroStruct(&s);
  s.client = client;
  s.url = url;
  s.seq_total = total;
  client_get(client, str8_cstring(url), seq_cb, &s);
  loop_run(loop);

  Ctx p;
  MemoryZeroStruct(&p);
  p.client = client;
  p.url = url;
  for (int i = 0; i < nconc; ++i) client_get(client, str8_cstring(url), conc_cb, &p);
  loop_run(loop);

  *out_h2 = s.n_h2 + p.n_h2;
  *out_h3 = s.n_h3 + p.n_h3;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[pool_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  enum { N = 4 };

  //- H2: one origin, 3 sequential + N concurrent ride one connection.
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
    defer { client_cleanup(&c); };
    CHECK(client_ok(&c));
    client_set_max_conns_per_origin(&c, 1);

    int h2 = 0, h3 = 0;
    run_phase(&c, &loop, "https://www.google.com/", 3, N, &h2, &h3);
    PoolStats st = client_pool_stats(&c);
    fprintf(stderr, "  H2: n_h2=%d conns=%" PRIu64 " requests=%" PRIu64
                    " reuses=%" PRIu64 "\n",
            h2, st.conns_created, st.requests, st.reuses);
    CHECK(h2 == 3 + N);
    CHECK(st.conns_created == 1);
    CHECK(st.requests == (U64)(3 + N));
    CHECK(st.reuses == (U64)(3 + N - 1));

  }

  //- H3: warm alt-svc over H2, then sequential + concurrent over pooled QUIC.
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init_dual(&c, &loop, profile_chrome148(), profile_chrome148_h3(),
                     /*verify=*/1);
    defer { client_cleanup(&c); };
    CHECK(client_ok(&c));
    client_set_max_conns_per_origin(&c, 1);

    const char *url = "https://www.cloudflare.com/";
    Ctx warm;
    MemoryZeroStruct(&warm);
    warm.client = &c;
    warm.url = url;
    warm.seq_total = 1;
    client_get(&c, str8_cstring(url), seq_cb, &warm);  // H2 -> learns alt-svc h3
    loop_run(&loop);
    B32 h3_cached = client_h3_available(&c, str8_lit("www.cloudflare.com:443"));
    fprintf(stderr, "  H3 warm: alpn_h2=%d h3_cached=%d\n", warm.n_h2, h3_cached);
    CHECK(warm.n_h2 == 1 && h3_cached);

    PoolStats before = client_pool_stats(&c);  // after the H2 warm conn
    int h2 = 0, h3 = 0;
    run_phase(&c, &loop, url, 3, N, &h2, &h3);  // now routes over H3/QUIC
    PoolStats after = client_pool_stats(&c);
    U64 d_conns = after.conns_created - before.conns_created;
    U64 d_reuses = after.reuses - before.reuses;
    fprintf(stderr, "  H3: n_h3=%d new_conns=%" PRIu64 " new_reuses=%" PRIu64
                    "\n",
            h3, d_conns, d_reuses);
    CHECK(h3 == 3 + N);          // every request rode HTTP/3
    CHECK(d_conns == 1);         // a single pooled QUIC connection served them
    CHECK(d_reuses == (U64)(3 + N - 1));  // all but the first reused it

  }

  //- H3 fingerprint through the pool: a pooled GET to quic.browserleaks.com must
  //  report the same h3_hash the direct path does (proves the per-connection
  //  stream split didn't disturb the control-stream surface).
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init_dual(&c, &loop, profile_chrome148(), profile_chrome148_h3(),
                     /*verify=*/1);
    defer { client_cleanup(&c); };
    CHECK(client_ok(&c));
    client_set_max_conns_per_origin(&c, 1);

    H3Fp fp;
    MemoryZeroStruct(&fp);
    fp.client = &c;
    fp.phase = 1;
    client_get(&c, str8_lit(H3FP_URL), h3fp_cb, &fp);  // #1 H2 -> learns alt-svc
    loop_run(&loop);

    fprintf(stderr, "  H3 fp: alpn1=%s alpn2=%s h3_hash=%s\n", fp.alpn1,
            fp.alpn2, fp.h3hash);
    CHECK(fp.got1);  // #1 succeeded (h2 or h1 over TCP) and cached alt-svc h3
    CHECK(fp.got2 && str8_match(str8_cstring(fp.alpn2), str8_lit("h3")));
    CHECK(str8_match(str8_cstring(fp.h3hash),
                     str8_lit("ba909fc3dc419ea5c5b26c6323ac1879")));

  }

  fprintf(stderr, "[pool_live_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
