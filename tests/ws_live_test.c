// Live proof of the WebSocket H1 (RFC 6455 Upgrade) path end-to-end. Forces
// http/1.1 ALPN (client_set_http_version), opens wss://echo.websocket.events,
// and round-trips a text + a binary message through the echo server, then closes
// cleanly. Asserts the transport negotiated H1, the handshake completed, and the
// echoed payloads come back byte-for-byte. This exercises the whole WsConn path:
// the TLS connection takeover, the manual GET handshake, Sec-WebSocket-Accept
// verification, leftover-bytes-after-101 feeding, the masked client frames, and
// the incremental parser delivering server frames. Network-gated: set
// HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/base.h"
#include "base/defer.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"
#include "ws/ws.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

// Send `payload` as `op`, then receive up to `budget` messages looking for the
// echo (the server greets with a banner first, so we skip non-matching ones).
// Returns 1 if the exact payload echoed back.
internal B32 send_and_expect_echo(WsConn *ws, WsOpcode op, const U8 *payload,
                                  U64 len, int budget) {
  if (!ws_conn_send(ws, op, payload, len)) return 0;
  for (int i = 0; i < budget; ++i) {
    WsEvent ev;
    int rc = ws_conn_recv(ws, &ev);
    if (rc != 1) return 0;  // close or error before the echo
    if (ev.op == op && ev.len == len && memcmp(ev.data, payload, len) == 0)
      return 1;
    // else: the greeting banner (or another message) — keep looking.
  }
  return 0;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[ws_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }

  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };

  Client client;
  client_init(&client, &loop, profile_chrome148(), /*verify=*/1);
  defer { client_cleanup(&client); };
  CHECK(client_ok(&client));
  client_set_http_version(&client, HttpVersion_H1);  // deterministic H1 upgrade
  client_set_timeout_ms(&client, 15000);             // connect watchdog

  WsConn *ws = ws_conn_alloc(&client);
  defer { ws_conn_free(ws); };

  B32 ok = ws_conn_connect(ws, str8_lit("wss://echo.websocket.org"), 0, 0);
  if (!ok)
    fprintf(stderr, "  connect failed: %s\n",
            ws_conn_error(ws) ? ws_conn_error(ws) : "?");
  CHECK(ok);
  CHECK(ws_conn_transport(ws) == WsTransport_H1);

  // Text round-trip.
  const char *txt = "hello holytls websocket";
  CHECK(send_and_expect_echo(ws, WsOp_Text, (const U8 *)txt, strlen(txt), 4));

  // Binary round-trip (includes a 0x00 to prove it is not treated as a C
  // string).
  U8 bin[64];
  for (U64 i = 0; i < sizeof bin; ++i) bin[i] = (U8)(i * 7 + 3);
  bin[10] = 0;
  CHECK(send_and_expect_echo(ws, WsOp_Binary, bin, sizeof bin, 4));

  // Clean close.
  ws_conn_close(ws, 1000, str8_lit("bye"));

  fprintf(stderr, "[ws_live_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
