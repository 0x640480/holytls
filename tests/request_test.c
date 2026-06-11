// Offline request-dispatch tests over the shared in-process loopback origin
// (tests/support/loopback_server), run over BOTH HTTP/2 and HTTP/1.1. The server
// ECHOES: status 200, records the received method, and sends the request body
// straight back. For each transport we verify:
//   - all 7 HTTP methods reach the wire with the correct method;
//   - a request body round-trips byte-intact (small and a ~4MB upload — the
//     request DATA path + the per-connection egress ring, previously untested);
//   - HEAD yields a 200 with no response body.
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
global char g_seen_method[16];  // the method the server received
global const U8 *g_expect;      // expected echoed body
global U64 g_expect_len;

// Server: echo the body back, record the method.
static void echo_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)user;
  U64 n = req->method.size < sizeof g_seen_method - 1 ? req->method.size
                                                      : sizeof g_seen_method - 1;
  MemoryCopy(g_seen_method, req->method.str, n);
  g_seen_method[n] = 0;
  resp->status = 200;
  resp->body = req->body;  // the server copies it
  resp->body_len = req->body_len;
}

typedef struct RC {
  B32 ok, body_ok;
  int status;
  U64 body_len;
} RC;
static void on_resp(void *user, const Response *r) {
  RC *rc = (RC *)user;
  rc->ok = r->ok;
  rc->status = r->status;
  rc->body_len = r->body_len;
  rc->body_ok = r->body_len == g_expect_len &&
                (g_expect_len == 0 || memcmp(r->body, g_expect, g_expect_len) == 0);
  uv_stop(loop_uv(g_loop));
}

global uv_timer_t g_wd;
static void wd_cb(uv_timer_t *t) {
  (void)t;
  fprintf(stderr, "  [watchdog] timed out\n");
  uv_stop(loop_uv(g_loop));
}

static RC do_req(EventLoop *loop, Client *c, Method m, const char *url,
                 const U8 *body, U64 body_len) {
  RC rc;
  MemoryZeroStruct(&rc);
  g_seen_method[0] = 0;
  g_expect = body;  // echo => the response body equals the request body...
  g_expect_len = body_len;
  if (m == Method_HEAD) g_expect_len = 0;  // ...except HEAD (no response body)
  uv_timer_start(&g_wd, wd_cb, 8000, 0);
  client_send(c, m, str8_cstring(url), 0, 0, body, body_len, on_resp, &rc);
  loop_run(loop);
  uv_timer_stop(&g_wd);
  return rc;
}

// Run the full method + body suite over one transport.
static void run_suite(EventLoop *loop, LbAlpn alpn, HttpVersion ver,
                      const char *label) {
  U16 port = 0;
  LbServer *srv = lb_server_start(loop, alpn, echo_handler, 0, &port);
  char url[64];
  snprintf(url, sizeof url, "https://127.0.0.1:%u/", port);

  Client c;
  client_init(&c, loop, profile_chrome148(), /*verify=*/0);
  client_set_http_version(&c, ver);

  // 1) Every method reaches the wire with the right method (bodyless).
  struct {
    Method m;
    const char *name;
  } methods[] = {
      {Method_GET, "GET"},       {Method_POST, "POST"},
      {Method_PUT, "PUT"},       {Method_DELETE, "DELETE"},
      {Method_HEAD, "HEAD"},     {Method_PATCH, "PATCH"},
      {Method_OPTIONS, "OPTIONS"},
  };
  for (U64 i = 0; i < ArrayCount(methods); ++i) {
    RC rc = do_req(loop, &c, methods[i].m, url, 0, 0);
    fprintf(stderr, "  [%s %-7s] ok=%d status=%d seen=%s body=%llu\n", label,
            methods[i].name, rc.ok, rc.status, g_seen_method,
            (unsigned long long)rc.body_len);
    CHECK(rc.ok && rc.status == 200);
    CHECK(strcmp(g_seen_method, methods[i].name) == 0);
    CHECK(rc.body_len == 0);  // no request body -> no echoed body (HEAD too)
  }

  // 2) Small POST body round-trips byte-intact.
  {
    const char *small = "hello, body!";
    RC rc = do_req(loop, &c, Method_POST, url, (const U8 *)small, strlen(small));
    CHECK(rc.ok && rc.status == 200 && rc.body_len == strlen(small) && rc.body_ok);
  }

  // 3) Large POST (~4MB) round-trips byte-intact (request DATA + egress ring).
  {
    U64 big_len = 4u << 20;
    U8 *big = (U8 *)malloc(big_len);
    for (U64 i = 0; i < big_len; ++i) big[i] = (U8)((i * 2654435761u) >> 24);
    RC rc = do_req(loop, &c, Method_POST, url, big, big_len);
    fprintf(stderr, "  [%s POST 4MB] ok=%d status=%d body=%llu intact=%d\n",
            label, rc.ok, rc.status, (unsigned long long)rc.body_len, rc.body_ok);
    CHECK(rc.ok && rc.status == 200 && rc.body_len == big_len && rc.body_ok);
    free(big);
  }

  client_cleanup(&c);
  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(loop), UV_RUN_NOWAIT); ++g) {
  }
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  uv_timer_init(loop_uv(&loop), &g_wd);
  uv_unref((uv_handle_t *)&g_wd);

  run_suite(&loop, LB_ALPN_H2, HttpVersion_H2, "h2");
  run_suite(&loop, LB_ALPN_H1, HttpVersion_H1, "h1");

  uv_close((uv_handle_t *)&g_wd, 0);
  loop_shutdown(&loop);
  fprintf(stderr, "[request_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
