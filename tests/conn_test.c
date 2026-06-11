// Connection integration: drive the full C TCP+TLS+H2 stack end-to-end against
// a real origin. Build an H2 SSL_CTX from the template profile, connect, assert
// the negotiated ALPN is "h2", run an HTTP/2 GET /json through the H2Session
// wired to the connection's plaintext stream, and assert a 200 with a body.
//
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/base.h"
#include "core/json.h"
#include "h2/h2.h"
#include "net/connection.h"
#include "net/loop.h"
#include "profile/profile.h"
#include "tls/ssl_ctx.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                     \
  Statement(g_checks += 1; if (!(c)) {                               \
    g_fails += 1;                                                    \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);   \
  })

#define HOST "tls.browserleaks.com"

typedef struct Ctx Ctx;
struct Ctx {
  Connection *conn;
  H2Session *h2;
  B32 ready_ok;
  B32 alpn_h2;
  B32 responded;
  int status;
  U64 body_len;
  char body[8192];  // captured copy of the response body (browserleaks JSON)
};

//- H2 send callback: encrypt + push plaintext out through the connection.
internal void on_h2_send(void *user, const U8 *data, U64 len) {
  Ctx *cx = (Ctx *)user;
  conn_send_plaintext(cx->conn, data, len);
}

//- Connection readable: pump decrypted bytes into the H2 session.
internal void on_readable(void *user) {
  Ctx *cx = (Ctx *)user;
  if (!cx->h2) return;
  U8 buf[16384];
  for (;;) {
    int n = conn_read_plaintext(cx->conn, buf, sizeof buf);
    if (n <= 0) break;
    if (h2_session_recv(cx->h2, buf, (U64)n) < 0) {
      conn_close(cx->conn);
      return;
    }
  }
}

//- H2 response: record status + body length, then tear down.
internal void on_h2_resp(void *user, const H2Response *r) {
  Ctx *cx = (Ctx *)user;
  if (cx->responded) return;
  cx->responded = 1;
  cx->status = r->status;
  cx->body_len = r->body_len;
  U64 n = r->body_len;
  if (n > sizeof cx->body - 1) n = sizeof cx->body - 1;
  if (r->body && n) MemoryCopy(cx->body, r->body, n);
  cx->body[n] = 0;
  conn_close(cx->conn);
}

//- Connection established: bring up H2 and submit the GET.
internal void on_ready(void *user, B32 ok, const char *err) {
  Ctx *cx = (Ctx *)user;
  cx->ready_ok = ok;
  if (!ok) {
    fprintf(stderr, "  connect failed: %s\n", err ? err : "unknown");
    conn_close(cx->conn);
    return;
  }
  String8 alpn = conn_alpn(cx->conn);
  cx->alpn_h2 = str8_match(alpn, str8_lit("h2"));
  if (!cx->alpn_h2) {
    fprintf(stderr, "  ALPN = %.*s (expected h2)\n", (int)alpn.size, alpn.str);
    conn_close(cx->conn);
    return;
  }
  cx->h2 = h2_session_alloc(&profile_template()->h2, on_h2_send, cx);
  if (!cx->h2 || !h2_session_start(cx->h2)) {
    conn_close(cx->conn);
    return;
  }
  conn_on_readable(cx->conn, on_readable, cx);
  Header hdr = {str8_lit("accept"), str8_lit("*/*"), 0};
  S32 sid = h2_session_submit_request(
      cx->h2, str8_lit("GET"), str8_lit("https"), str8_lit(HOST),
      str8_lit("/json"), &hdr, 1, 0, 0, on_h2_resp, cx);
  if (sid < 0) {
    conn_close(cx->conn);
    return;
  }
  on_readable(cx);  // flush anything already buffered
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[conn_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }

  EventLoop loop;
  loop_init(&loop);

  const Profile *prof = profile_template();
  CtxResult cr = build_ctx(&prof->tls, /*verify=*/1);
  CHECK(ctx_ok(&cr));

  Connection conn;
  conn_init(&conn, &loop, cr.ctx, &prof->tls);

  Ctx cx;
  MemoryZeroStruct(&cx);
  cx.conn = &conn;

  conn_on_fully_closed(&conn, 0, 0);  // no owner to free; loop drains naturally
  conn_connect(&conn, HOST, 443, on_ready, &cx);

  loop_run(&loop);

  if (cx.h2) h2_session_release(cx.h2);
  conn_close(&conn);
  loop_shutdown(&loop);
  conn_cleanup(&conn);  // free the SSL/BIOs now that the loop has drained
  if (cr.ctx) SSL_CTX_free(cr.ctx);

  CHECK(cx.ready_ok);
  CHECK(cx.alpn_h2);
  CHECK(cx.responded);
  fprintf(stderr, "  status = %d, body = %llu bytes\n", cx.status,
          (unsigned long long)cx.body_len);
  CHECK(cx.status == 200);
  CHECK(cx.body_len > 0);

  // The body is the browserleaks fingerprint JSON: assert the fingerprints it
  // reports over the live wire are byte-exact (template profile goldens).
  String8 body = str8((U8 *)cx.body, cx.body_len);
  char ja4[80], akamai[64];
  json_get_str(body, "ja4", ja4, sizeof ja4);
  json_get_str(body, "akamai_hash", akamai, sizeof akamai);
  fprintf(stderr, "  live ja4    = %s\n", ja4);
  fprintf(stderr, "  live akamai = %s\n", akamai);
  CHECK(str8_match(str8_cstring(akamai),
                   str8_lit("6ea73faa8fc5aac76bded7bd238f6433")));
  CHECK(str8_match(str8_cstring(ja4),
                   str8_lit("t13d1717h2_5b57614c22b0_3cbfd9057e0d")));

  fprintf(stderr, "[conn_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
