// Live H3 verification: GET https://quic.browserleaks.com/?minify=1 over HTTP/3
// through the C QuicConnection + H3Session, and assert the fingerprints
// browserleaks reports for a FRESH handshake:
//   * QUIC JA4 == q13d0311h3_55b375c5d22e_653d80c3fe9d  (fresh/incognito Chrome)
//   * h3_hash  == ba909fc3dc419ea5c5b26c6323ac1879
// Runs BOTH the Chrome 148 and 149 QUIC profiles: they ship byte-identical
// QUIC/H3 tables, so a fresh handshake from either must hash to the same golden
// (verified against fresh 148 + 149 browserleaks captures, 2026-06-10).
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/base.h"
#include "core/json.h"
#include "h3/h3_session.h"
#include "net/loop.h"
#include "net/quic_connection.h"
#include "profile/profile.h"
#include "tls/ssl_ctx.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

#define HOST "quic.browserleaks.com"

// zstd (the body may be zstd-encoded; we don't send accept-encoding, but decode
// defensively, matching the C++ test).
extern size_t ZSTD_decompress(void *, size_t, const void *, size_t);
extern unsigned long long ZSTD_getFrameContentSize(const void *, size_t);
extern unsigned ZSTD_isError(size_t);

global U8 g_decoded[1 << 16];

typedef struct Ctx Ctx;
struct Ctx {
  QuicConnection *conn;
  H3Session *h3;
  const QuicProfile *prof;  // profile under test (148 or 149)
  const char *ua;           // user-agent header (cosmetic; not hashed into ja4/h3)
  B32 got;
  char ja4[80];
  char h3hash[64];
};

internal String8 maybe_unzstd(const H3Response *r) {
  String8 enc = {0, 0};
  for (U64 i = 0; i < r->header_count; ++i)
    if (str8_match(r->headers[i].name, str8_lit("content-encoding")))
      enc = r->headers[i].value;
  B32 is_zstd = 0;
  for (U64 i = 0; i + 4 <= enc.size; ++i)
    if (memcmp(enc.str + i, "zstd", 4) == 0) is_zstd = 1;
  if (!is_zstd) return str8((U8 *)r->body, r->body_len);
  unsigned long long n = ZSTD_getFrameContentSize(r->body, r->body_len);
  if (n == 0 || n > sizeof g_decoded) return str8_zero();
  size_t rv = ZSTD_decompress(g_decoded, sizeof g_decoded, r->body, r->body_len);
  if (ZSTD_isError(rv)) return str8_zero();
  return str8(g_decoded, rv);
}

internal void on_h3_resp(void *user, const H3Response *r) {
  Ctx *cx = (Ctx *)user;
  if (r->ok) {
    cx->got = 1;
    String8 body = maybe_unzstd(r);
    json_get_str(body, "ja4", cx->ja4, sizeof cx->ja4);
    json_get_str(body, "h3_hash", cx->h3hash, sizeof cx->h3hash);
  } else {
    fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
  }
  quic_conn_close(cx->conn);
}

internal void on_ready(void *user, B32 ok, const char *err) {
  Ctx *cx = (Ctx *)user;
  if (!ok) {
    fprintf(stderr, "  connect failed: %s\n", err ? err : "?");
    quic_conn_close(cx->conn);
    return;
  }
  String8 alpn = quic_conn_alpn(cx->conn);
  if (!str8_match(alpn, str8_lit("h3"))) {
    fprintf(stderr, "  ALPN = %.*s (expected h3)\n", (int)alpn.size, alpn.str);
    quic_conn_close(cx->conn);
    return;
  }
  cx->h3 = h3_session_alloc(cx->conn, &cx->prof->h3);
  if (!cx->h3) {
    quic_conn_close(cx->conn);
    return;
  }
  Header headers[] = {
      {str8_lit("user-agent"), str8_cstring(cx->ua), 0},
      {str8_lit("accept"), str8_lit("*/*"), 0},
  };
  if (!h3_session_request(cx->h3, str8_lit("GET"), str8_lit("https"),
                          str8_lit(HOST), str8_lit("/?minify=1"), headers, 2, 0,
                          0, on_h3_resp, cx)) {
    fprintf(stderr, "  h3 request submit failed\n");
    quic_conn_close(cx->conn);
  }
}

internal void run_profile(const QuicProfile *prof, const char *ua) {
  CtxResult cr = build_ctx(&prof->tls, /*verify=*/1);
  CHECK(ctx_ok(&cr));
  if (!ctx_ok(&cr)) {
    if (cr.ctx) SSL_CTX_free(cr.ctx);
    return;
  }

  EventLoop loop;
  loop_init(&loop);
  QuicConnection conn;
  quic_conn_init(&conn, &loop, cr.ctx, &prof->tls, &prof->h3);

  Ctx cx;
  MemoryZeroStruct(&cx);
  cx.conn = &conn;
  cx.prof = prof;
  cx.ua = ua;

  quic_conn_connect(&conn, HOST, 443, on_ready, &cx);
  loop_run(&loop);

  if (cx.h3) h3_session_release(cx.h3);
  quic_conn_close(&conn);
  loop_shutdown(&loop);
  quic_conn_cleanup(&conn);
  if (cr.ctx) SSL_CTX_free(cr.ctx);

  CHECK(cx.got);
  fprintf(stderr, "  %-12s ja4     = %s\n", prof->name, cx.ja4);
  fprintf(stderr, "  %-12s h3_hash = %s\n", prof->name, cx.h3hash);
  CHECK(str8_match(str8_cstring(cx.ja4),
                   str8_lit("q13d0311h3_55b375c5d22e_653d80c3fe9d")));
  CHECK(str8_match(str8_cstring(cx.h3hash),
                   str8_lit("ba909fc3dc419ea5c5b26c6323ac1879")));
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[fingerprint_h3_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }

  // 148 and 149 share identical QUIC/H3 tables -> identical fresh fingerprint.
  run_profile(profile_chrome148_h3(),
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36");
  run_profile(profile_chrome149_h3(),
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36");

  fprintf(stderr, "[fingerprint_h3_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
