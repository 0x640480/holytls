// White-box regression lock for the per-stream H2 arena. Drives one H2Session
// through N sequential request/response cycles (each a large, content-length-
// delimited body) against an in-process nghttp2 server, asserting the SESSION
// arena stays FLAT. The bug this guards: per-request response bodies/headers
// used to accumulate on the session arena forever, so a reused
// (keep-alive-pooled) connection grew it to hundreds of MB. Per-stream arenas
// (recycled on stream close) make it flat. (ASan won't catch the original bug —
// it was unbounded growth, freed only on conn close, not a leak — so this
// arena_used assert is the only mechanism that locks it.)
#include <nghttp2/nghttp2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/base.h"
#include "base/string8.h"
#include "h2/h2.h"
#include "profile/profile.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

#define BODY_LEN (200 * 1024)
global U8 g_pattern[BODY_LEN];  // the response body the server serves

//- a malloc-growable byte buffer for the in-process pump
typedef struct Buf {
  U8 *p;
  U64 len, cap;
} Buf;
static void buf_put(Buf *b, const U8 *d, U64 n) {
  if (b->len + n > b->cap) {
    U64 c = b->cap ? b->cap : 65536;
    while (c < b->len + n) c *= 2;
    b->p = (U8 *)realloc(b->p, c);
    b->cap = c;
  }
  MemoryCopy(b->p + b->len, d, n);
  b->len += n;
}
global Buf g_c2s, g_s2c;  // client->server, server->client

//- client side
static void cli_send(void *user, const U8 *d, U64 n) {
  (void)user;
  buf_put(&g_c2s, d, n);
}
global int g_last_ok, g_body_match;
global U64 g_last_len;
static void cli_resp(void *user, const H2Response *r) {
  (void)user;
  g_last_ok = r->ok;
  g_last_len = r->body_len;
  g_body_match =
      (r->body_len == BODY_LEN && memcmp(r->body, g_pattern, BODY_LEN) == 0);
}

//- server side (raw nghttp2): respond to each request with the BODY_LEN body
global U64 g_srv_off;  // per-response read offset (requests are sequential)
static nghttp2_ssize srv_send(nghttp2_session *s, const U8 *d, size_t n, int f,
                              void *u) {
  (void)s;
  (void)f;
  (void)u;
  buf_put(&g_s2c, d, n);
  return (nghttp2_ssize)n;
}
static nghttp2_ssize srv_body_read(nghttp2_session *s, S32 sid, U8 *buf,
                                   size_t length, U32 *data_flags,
                                   nghttp2_data_source *src, void *u) {
  (void)s;
  (void)sid;
  (void)src;
  (void)u;
  U64 remain = BODY_LEN - g_srv_off;
  U64 n = remain < length ? remain : length;
  if (n) MemoryCopy(buf, g_pattern + g_srv_off, n);
  g_srv_off += n;
  if (g_srv_off >= BODY_LEN) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  return (nghttp2_ssize)n;
}
static int srv_frame(nghttp2_session *s, const nghttp2_frame *f, void *u) {
  (void)u;
  // Request complete (END_STREAM on its HEADERS or final DATA) -> respond.
  if ((f->hd.flags & NGHTTP2_FLAG_END_STREAM) &&
      (f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA)) {
    g_srv_off = 0;
    char clen[24];
    int cn = snprintf(clen, sizeof clen, "%d", BODY_LEN);
    nghttp2_nv nv[] = {
        {(U8 *)":status", (U8 *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(U8 *)"content-length", (U8 *)clen, 14, (size_t)cn,
         NGHTTP2_NV_FLAG_NONE},
    };
    nghttp2_data_provider2 prd;
    prd.source.ptr = 0;
    prd.read_callback = srv_body_read;
    nghttp2_submit_response2(s, f->hd.stream_id, nv, 2, &prd);
  }
  return 0;
}

// Pump both directions until no bytes flow (the request + the windowed body +
// the client's WINDOW_UPDATEs all settle).
static void pump(nghttp2_session *srv, H2Session *cli) {
  for (int guard = 0; guard < 100000; ++guard) {
    B32 progress = 0;
    if (g_c2s.len) {  // client -> server (request / window updates)
      nghttp2_session_mem_recv2(srv, g_c2s.p, g_c2s.len);
      g_c2s.len = 0;
      progress = 1;
    }
    g_s2c.len = 0;
    nghttp2_session_send(srv);  // server -> g_s2c (settings / response frames)
    if (g_s2c.len) {
      h2_session_recv(cli, g_s2c.p,
                      g_s2c.len);  // fires on_data + on_stream_close
      progress = 1;
    }
    h2_session_flush(cli);  // emit client WINDOW_UPDATEs into g_c2s
    if (g_c2s.len) progress = 1;
    if (!progress) break;
  }
}

int main(void) {
  for (U64 i = 0; i < BODY_LEN; ++i)
    g_pattern[i] = (U8)((i * 2654435761u) >> 24);

  const Http2Profile *prof = &profile_chrome148()->h2;
  H2Session *cli = h2_session_alloc(prof, cli_send, 0);
  h2_session_start(cli);

  nghttp2_session_callbacks *cbs = 0;
  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_send_callback2(cbs, srv_send);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, srv_frame);
  nghttp2_session *srv = 0;
  nghttp2_session_server_new(&srv, cbs, 0);
  nghttp2_session_callbacks_del(cbs);
  nghttp2_submit_settings(srv, NGHTTP2_FLAG_NONE, 0, 0);

  const int N = 64;
  U64 used_after_first = 0;
  for (int k = 0; k < N; ++k) {
    g_last_ok = 0;
    g_body_match = 0;
    h2_session_submit_request(cli, str8_lit("GET"), str8_lit("https"),
                              str8_lit("example.com"), str8_lit("/"), 0, 0, 0,
                              0, cli_resp, 0, /*on_chunk=*/0, 0);
    pump(srv, cli);
    CHECK(g_last_ok && g_body_match);  // every body round-trips intact
    if (k == 0) used_after_first = h2_session_arena_used(cli);
  }
  U64 used_after_n = h2_session_arena_used(cli);
  fprintf(stderr,
          "  session arena: after#1=%llu after#%d=%llu (grew %lld over %d "
          "x %dB bodies)\n",
          (unsigned long long)used_after_first, N,
          (unsigned long long)used_after_n,
          (long long)(used_after_n - used_after_first), N, BODY_LEN);
  // Per-request memory now lives in per-stream arenas recycled at close, so the
  // SESSION arena must NOT grow with request count. Pre-fix it grew ~N*BODY_LEN
  // (12.8 MB here); the slack is one arena block, far below even one body.
  CHECK(used_after_n <= used_after_first + KB(64));

  h2_session_release(cli);
  nghttp2_session_del(srv);
  free(g_c2s.p);
  free(g_s2c.p);
  fprintf(stderr, "[h2_arena_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
