// Offline WebSocket-over-HTTP/2 test (RFC 8441 Extended CONNECT) against the
// in-process loopback echo origin (lb_ws_echo_start), which advertises
// SETTINGS_ENABLE_CONNECT_PROTOCOL, answers a CONNECT+:protocol stream with 200,
// and re-frames every client (masked) WS frame back as an unmasked server frame.
// We open a WsConn (forced onto h2 by an h2-only server), assert transport==H2,
// round-trip a text + a binary message, and close cleanly. This exercises the
// whole H2 path: the deferred data provider, ENABLE_CONNECT_PROTOCOL gating, the
// CONNECT submit, bidirectional DATA framing, and the H2 close. ASan-clean.
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
#include "ws/ws.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

// Send `payload` as `op`, then receive up to `budget` messages looking for the
// echo. Returns 1 if the exact payload echoed back.
static B32 send_and_expect_echo(WsConn *ws, WsOpcode op, const U8 *payload,
                                U64 len, int budget) {
  if (!ws_conn_send(ws, op, payload, len)) return 0;
  for (int i = 0; i < budget; ++i) {
    WsEvent ev;
    int rc = ws_conn_recv(ws, &ev, 10000);  // 10s deadline: don't hang the test
    if (rc != 1) return 0;
    if (ev.op == op && ev.len == len && memcmp(ev.data, payload, len) == 0)
      return 1;
  }
  return 0;
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);

  U16 port = 0;
  LbServer *srv = lb_ws_echo_start(&loop, &port);
  char url[64];
  snprintf(url, sizeof url, "wss://127.0.0.1:%u/chat", port);

  Client c;
  client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/0);                    // self-signed loopback
  client_set_http_version(&c, HttpVersion_H2);  // opt into Extended CONNECT
  client_set_timeout_ms(&c, 8000);              // connect watchdog

  WsConn *ws = ws_conn_alloc(&c);
  B32 ok = ws_conn_connect(ws, str8_cstring(url), 0, 0);
  if (!ok)
    fprintf(stderr, "  connect failed: %s\n",
            ws_conn_error(ws) ? ws_conn_error(ws) : "?");
  CHECK(ok);
  CHECK(ws_conn_transport(ws) == WsTransport_H2);

  const char *txt = "hello h2 websocket over extended connect";
  CHECK(send_and_expect_echo(ws, WsOp_Text, (const U8 *)txt, strlen(txt), 4));

  U8 bin[64];
  for (U64 i = 0; i < sizeof bin; ++i) bin[i] = (U8)(i * 11 + 5);
  bin[7] = 0;  // embedded NUL: not a C string
  CHECK(send_and_expect_echo(ws, WsOp_Binary, bin, sizeof bin, 4));

  // Large message: a 100 KB frame uses the 64-bit length, nghttp2 splits it
  // across many 16 KB DATA frames, the loopback re-frames a partial frame across
  // chunks, and the parser reassembles across reads — the deferred provider's
  // multi-read drain end-to-end.
  U64 big_len = 100 * 1024;
  U8 *big = (U8 *)malloc(big_len);
  for (U64 i = 0; i < big_len; ++i) big[i] = (U8)(i * 167 + (i >> 9));
  CHECK(send_and_expect_echo(ws, WsOp_Binary, big, big_len, 4));
  free(big);

  ws_conn_close(ws, 1000, str8_lit("bye"));
  ws_conn_free(ws);
  client_cleanup(&c);
  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);

  fprintf(stderr, "[ws_h2_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
