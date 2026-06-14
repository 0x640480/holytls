// WsConn — a WebSocket connection over holytls's transport. Keeps Chrome's
// normal ALPN (h2,http/1.1) so the wss ClientHello stays byte-exact, then does
// the HTTP/1.1 Upgrade handshake when the server negotiates http/1.1 (HTTP/2
// Extended CONNECT, RFC 8441, is layered on in a later stage). The RFC 6455
// frame codec (ws_frame.h) rides on either transport. One WsConn is a single
// long-lived bidirectional socket, driven blocking-style: each call runs the
// loop until its event (connect done / one message / close).
#ifndef HOLYTLS_WS_H
#define HOLYTLS_WS_H

#include "core/client.h"
#include "ws/ws_frame.h"

typedef enum WsTransport {
  WsTransport_None = 0,
  WsTransport_H1,
  WsTransport_H2,
} WsTransport;

typedef struct WsConn WsConn;

// Allocate a WS handle bound to `client` (borrows its loop / profile / SSL_CTX).
// Pair with ws_conn_free.
WsConn *ws_conn_alloc(Client *client);
void ws_conn_free(WsConn *w);

// Blocking: open the WebSocket at `url` (wss://… ; https://… accepted as the
// same) with optional extra request headers. Returns 1 on a completed handshake,
// 0 on failure (see ws_conn_error).
B32 ws_conn_connect(WsConn *w, String8 url, const Header *headers,
                    U64 header_count);

// Queue + flush a text/binary message (masked). Returns 0 if the connection is
// closed/failed.
B32 ws_conn_send(WsConn *w, WsOpcode op, const U8 *data, U64 len);

// Blocking: receive the next application message (auto-answers pings). Returns 1
// and fills *out with a Message (out->data valid until the next ws_conn_* call);
// 0 and fills *out with the peer's Close; -1 on error / a dead transport; -2 if
// `timeout_ms` elapsed with no message (the connection stays usable). 0 timeout
// blocks indefinitely.
int ws_conn_recv(WsConn *w, WsEvent *out, U64 timeout_ms);

// Send a Close frame (code + optional reason) and begin teardown.
void ws_conn_close(WsConn *w, U16 code, String8 reason);

WsTransport ws_conn_transport(WsConn *w);
const char *ws_conn_error(WsConn *w);  // 0 when no error

#endif  // HOLYTLS_WS_H
