// Offline permessage-deflate (RFC 7692) round-trip over the loopback. The H2
// echo origin negotiates permessage-deflate and, for each message, INFLATES the
// client's compressed (RSV1) frame and RE-DEFLATES it for the reply — so a
// matching echo proves the whole client path engaged: handshake negotiation,
// deflate-on-send (the server inflates it), and inflate-on-recv (the server's
// re-deflated reply). A non-negotiated/uncompressed client would either send no
// RSV1 (server reply still RSV1 -> client rejects) or mis-deflate (server
// inflate fails) -> the echo would not match. Exercises highly-compressible,
// random, empty, and 00-00-ff-ff-containing payloads + a 100 KB message. Run
// under ASan to prove the zlib streams are freed on both sides.
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

// Send `payload` as `op`, then recv until the exact bytes echo back (budget
// caps the wait). Returns 1 on a byte-exact echo.
static B32 echo_ok(WsConn *ws, WsOpcode op, const U8 *payload, U64 len,
                   int budget) {
  if (!ws_conn_send(ws, op, payload, len)) return 0;
  for (int i = 0; i < budget; ++i) {
    WsEvent ev;
    int rc = ws_conn_recv(ws, &ev, 10000);
    if (rc != 1) return 0;
    if (ev.op == op && ev.len == len &&
        (len == 0 || memcmp(ev.data, payload, len) == 0))
      return 1;
  }
  return 0;
}

// One pmd session: connect, run the battery, close. `ncto` selects whether the
// server imposes client_no_context_takeover (the client then deflateReset's
// after each message) — both modes must round-trip identically.
static void run_session(EventLoop *loop, B32 ncto, const char *label) {
  U16 port = 0;
  LbServer *srv = ncto ? lb_ws_echo_start_pmd_ncto(loop, &port)
                       : lb_ws_echo_start_pmd(loop, &port);
  char url[64];
  snprintf(url, sizeof url, "wss://127.0.0.1:%u/", port);

  Client c;
  client_init(&c, loop, profile_chrome148(), /*verify=*/0);
  client_set_http_version(&c, HttpVersion_H2);
  client_set_timeout_ms(&c, 8000);

  WsConn *ws = ws_conn_alloc(&c);
  B32 ok = ws_conn_connect(ws, str8_cstring(url), 0, 0);
  if (!ok)
    fprintf(stderr, "  [%s] connect failed: %s\n", label,
            ws_conn_error(ws) ? ws_conn_error(ws) : "?");
  CHECK(ok);
  CHECK(ws_conn_transport(ws) == WsTransport_H2);

  // Highly compressible (context takeover should help across the two sends;
  // ncto resets between them — still round-trips, just larger on the wire).
  U8 zeros[4096];
  MemoryZero(zeros, sizeof zeros);
  CHECK(echo_ok(ws, WsOp_Binary, zeros, sizeof zeros, 4));
  CHECK(echo_ok(ws, WsOp_Binary, zeros, sizeof zeros, 4));

  const char *txt = "permessage-deflate round-trips this text message just fine";
  CHECK(echo_ok(ws, WsOp_Text, (const U8 *)txt, strlen(txt), 4));

  // Empty message in the MIDDLE: its compressed form is empty after the trailer
  // strip; without the RFC 7692 7.2.3.6 0x00-octet fix this corrupts the inflate
  // context and breaks every following message — so the sends below guard it.
  CHECK(echo_ok(ws, WsOp_Text, (const U8 *)"", 0, 4));

  // Payload literally containing the 00 00 ff ff marker bytes — must survive the
  // strip/append trailer handling intact.
  U8 marker[12] = {1, 2, 0x00, 0x00, 0xff, 0xff, 3, 4, 0x00, 0x00, 0xff, 0xff};
  CHECK(echo_ok(ws, WsOp_Binary, marker, sizeof marker, 4));

  // Pseudo-random (low compressibility) — deflate still round-trips it.
  U64 rlen = 8192;
  U8 *rnd = (U8 *)malloc(rlen);
  for (U64 i = 0; i < rlen; ++i) rnd[i] = (U8)(i * 2654435761u >> 13);
  CHECK(echo_ok(ws, WsOp_Binary, rnd, rlen, 4));
  free(rnd);

  // Large, mixed message (multi-DATA-frame, exercises the deferred provider too).
  U64 blen = 100 * 1024;
  U8 *big = (U8 *)malloc(blen);
  for (U64 i = 0; i < blen; ++i) big[i] = (U8)((i / 64) ^ (i * 7));
  CHECK(echo_ok(ws, WsOp_Binary, big, blen, 4));
  free(big);

  ws_conn_close(ws, 1000, str8_lit("bye"));
  ws_conn_free(ws);
  client_cleanup(&c);
  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(loop), UV_RUN_NOWAIT); ++g) {
  }
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);

  run_session(&loop, /*ncto=*/0, "context-takeover");
  run_session(&loop, /*ncto=*/1, "no-context-takeover");

  loop_shutdown(&loop);
  fprintf(stderr, "[ws_pmd_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
