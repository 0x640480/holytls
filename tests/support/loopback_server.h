// Shared in-process loopback origin server for offline tests. One handler-based
// TLS server (libuv accept loop + memory-BIO BoringSSL + nghttp2 for H2, or raw
// HTTP/1.1) that replaces the byte-duplicated server scaffolding the timeout /
// proxy tests used to each carry. A test registers ONE LbHandler; the server
// owns all the TLS/protocol plumbing, accumulates the full request (incl. a
// multi-MB body), calls the handler, and frames the response per the negotiated
// ALPN.
#ifndef HOLYTLS_TEST_LOOPBACK_SERVER_H
#define HOLYTLS_TEST_LOOPBACK_SERVER_H

#include <openssl/ssl.h>
#include <uv.h>

#include "base/base.h"
#include "base/string8.h"
#include "net/loop.h"

// --- shared low-level helpers (reused by the proxy phase machines too) -------

// Queue a raw write on a tcp handle (malloc+copy, freed on completion). No-op
// on zero length or a closing handle.
void lb_raw_write(uv_tcp_t *t, const U8 *d, U64 n);
// uv_alloc_cb backed by a thread-local 64KB scratch buffer.
void lb_alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *b);
// Bind 127.0.0.1:0, listen, return the OS-assigned port; stores `data` on
// srv->data.
U16 lb_listen(EventLoop *loop, uv_tcp_t *srv, uv_connection_cb cb, void *data);

// ALPN the server advertises. A self-signed P-256 cert (CN=localhost), TLS1.2+.
typedef enum LbAlpn { LB_ALPN_H2, LB_ALPN_H1, LB_ALPN_BOTH } LbAlpn;
SSL_CTX *lb_server_ctx(LbAlpn alpn);

// --- handler-based origin server ---------------------------------------------

typedef struct LbRequest LbRequest;
struct LbRequest {
  String8 method;     // ":method" (H2) / request-line method (H1)
  String8 path;       // ":path" / request-target
  String8 authority;  // ":authority" / Host
  const U8 *body;  // fully accumulated request body (valid during the handler)
  U64 body_len;
  B32 is_h2;  // the negotiated protocol
};

typedef struct LbResponse LbResponse;
struct LbResponse {
  int status;      // 0 => 200
  const U8 *body;  // response body (the server copies it); may be 0
  U64 body_len;
  const char *extra_names[8];  // additional response headers (e.g. "location")
  const char *extra_values[8];
  U64 extra_count;
  B32 withhold;  // send NOTHING (keep the stream/conn open) — the timeout case
  B32 stall;     // send the body but never END_STREAM (hold the stream open) —
                 // the client gets the full body but no fin (mid-stream abort)
};

// Fired once per fully-received request. `resp` is zeroed before the call.
typedef void (*LbHandler)(const LbRequest *req, LbResponse *resp, void *user);

typedef struct LbServer LbServer;
// Start a persistent loopback origin on `loop`; writes the bound port to
// *out_port and returns a handle. Multiple servers may run on one loop.
LbServer *lb_server_start(EventLoop *loop, LbAlpn alpn, LbHandler handler,
                          void *user, U16 *out_port);
// Close the listener + all live connections and free the server. Call before
// loop_shutdown; the loop must still be able to run the close callbacks.
void lb_server_stop(LbServer *s);

#endif  // HOLYTLS_TEST_LOOPBACK_SERVER_H
