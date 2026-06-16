// Offline response-streaming test over the shared in-process loopback origin.
// The server returns a known 256 KB body; the client requests it with a
// streaming chunk callback (RequestParams.on_chunk). We verify, over both
// transports:
//   - the concatenated chunks equal the server body byte-for-byte (decoded);
//   - the final Response carries an EMPTY body (it was streamed, not buffered);
//   - H2 truly streams (the body arrives across multiple DATA frames => >1
//   chunk),
//     while H1 uses the buffered fallback (one chunk).
// Run under ASan to prove the per-stream StreamDecoder is freed (no leak) on
// the normal close path.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"
#include "support/loopback_server.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

global EventLoop *g_loop;
global U8 *g_body;  // the server's fixed response body
global U64 g_body_len;

static void body_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)user;
  resp->status = 200;
  resp->body = g_body;  // the server copies it
  resp->body_len = g_body_len;
  // "/stall": send the body but never END_STREAM, so the client streams the
  // body (decoder created) then must abort (timeout) with the stream still
  // open.
  if (str8_contains(req->path, str8_lit("stall"))) resp->stall = 1;
}

typedef struct Sink {
  U8 *buf;
  U64 len;
  U64 cap;
  int chunks;
} Sink;
static void on_chunk(void *user, const U8 *data, U64 len) {
  Sink *s = (Sink *)user;
  if (s->len + len <= s->cap) MemoryCopy(s->buf + s->len, data, len);
  s->len += len;  // count past cap so an overrun is detectable
  s->chunks++;
}

typedef struct RC {
  B32 ok, responded;
  int status;
  U64 resp_body_len;
} RC;
static void on_resp(void *user, const Response *r) {
  RC *rc = (RC *)user;
  rc->ok = r->ok;
  rc->status = r->status;
  rc->resp_body_len = r->body_len;
  rc->responded = 1;
  uv_stop(loop_uv(g_loop));
}

global uv_timer_t g_wd;
static void wd_cb(uv_timer_t *t) {
  (void)t;
  fprintf(stderr, "  [watchdog] timed out\n");
  uv_stop(loop_uv(g_loop));
}

static void run(EventLoop *loop, LbAlpn alpn, HttpVersion ver,
                const char *label, B32 expect_multi) {
  U16 port = 0;
  LbServer *srv = lb_server_start(loop, alpn, body_handler, 0, &port);
  char url[64];
  snprintf(url, sizeof url, "https://127.0.0.1:%u/", port);

  Client c;
  client_init(&c, loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/0);
  client_set_http_version(&c, ver);

  Sink sink = {(U8 *)malloc(g_body_len + 64), 0, g_body_len + 64, 0};
  RC rc;
  MemoryZeroStruct(&rc);
  uv_timer_start(&g_wd, wd_cb, 8000, 0);
  RequestParams p = {.method = Method_GET,
                     .url = str8_cstring(url),
                     .no_redirects = 1,
                     .on_chunk = on_chunk,
                     .chunk_user = &sink};
  client_request(&c, &p, on_resp, &rc);
  loop_run(loop);
  uv_timer_stop(&g_wd);

  fprintf(stderr,
          "  [%s] ok=%d status=%d chunks=%d streamed=%llu resp_body=%llu\n",
          label, rc.ok, rc.status, sink.chunks, (unsigned long long)sink.len,
          (unsigned long long)rc.resp_body_len);
  CHECK(rc.responded && rc.ok && rc.status == 200);
  CHECK(sink.len == g_body_len);
  CHECK(sink.len == g_body_len && memcmp(sink.buf, g_body, g_body_len) == 0);
  CHECK(rc.resp_body_len == 0);  // streamed => the final Response has no body
  CHECK(sink.chunks >= 1);
  if (expect_multi)
    CHECK(sink.chunks > 1);  // H2: body spans multiple DATA frames

  free(sink.buf);
  client_cleanup(&c);
  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(loop), UV_RUN_NOWAIT); ++g) {
  }
}

// Abort a streaming H2 request mid-flight: the server sends the whole body but
// never END_STREAM, so the decoder is created (and the body streams) but the
// stream stays open; a short client timeout aborts it, then client_cleanup ->
// h2_session_release tears the session down with the stream still open. The
// per-stream StreamDecoder MUST be freed there (nghttp2_session_del does not
// fire on_stream_close) — ASan/LSan proves no leak.
static void run_cancel(EventLoop *loop) {
  U16 port = 0;
  LbServer *srv = lb_server_start(loop, LB_ALPN_H2, body_handler, 0, &port);
  char url[64];
  snprintf(url, sizeof url, "https://127.0.0.1:%u/stall", port);

  Client c;
  client_init(&c, loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/0);
  client_set_http_version(&c, HttpVersion_H2);
  client_set_timeout_ms(&c, 400);  // abort: the server never sends fin

  Sink sink = {(U8 *)malloc(g_body_len + 64), 0, g_body_len + 64, 0};
  RC rc;
  MemoryZeroStruct(&rc);
  uv_timer_start(&g_wd, wd_cb, 8000, 0);
  RequestParams p = {.method = Method_GET,
                     .url = str8_cstring(url),
                     .no_redirects = 1,
                     .on_chunk = on_chunk,
                     .chunk_user = &sink};
  client_request(&c, &p, on_resp, &rc);
  loop_run(loop);
  uv_timer_stop(&g_wd);

  fprintf(
      stderr,
      "  [cancel] ok=%d chunks=%d streamed=%llu (decoder live at teardown)\n",
      rc.ok, sink.chunks, (unsigned long long)sink.len);
  CHECK(rc.responded && !rc.ok);  // aborted by the timeout, not a clean close
  CHECK(sink.chunks >= 1);        // the decoder WAS created (body streamed)

  free(sink.buf);
  client_cleanup(
      &c);  // h2_session_release with the streaming stream still open
  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(loop), UV_RUN_NOWAIT); ++g) {
  }
}

int main(void) {
  g_body_len = 256 * 1024;  // large enough to span many H2 DATA frames
  g_body = (U8 *)malloc(g_body_len);
  for (U64 i = 0; i < g_body_len; ++i)
    g_body[i] = (U8)((i * 131 + (i >> 7)) & 0xff);

  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  uv_timer_init(loop_uv(&loop), &g_wd);
  uv_unref((uv_handle_t *)&g_wd);

  run(&loop, LB_ALPN_H2, HttpVersion_H2, "h2-stream", /*expect_multi=*/1);
  run(&loop, LB_ALPN_H1, HttpVersion_H1, "h1-fallback", /*expect_multi=*/0);
  run_cancel(&loop);  // decoder-leak-on-abort (ASan)

  uv_close((uv_handle_t *)&g_wd, 0);
  loop_shutdown(&loop);
  free(g_body);
  fprintf(stderr, "[stream_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
