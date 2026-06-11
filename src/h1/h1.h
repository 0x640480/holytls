// H1Session — a client HTTP/1.1 request/response over a single connection,
// mirroring the h2 session shape so the client drives it the same way. It owns no
// transport: the serialized request goes to a send callback, received plaintext is
// fed to h1_session_recv, and the response is delivered through a callback. The
// request is serialized verbatim (caller hands wire-cased header names, in order)
// — Chrome/wreq HTTP/1.1 faithfulness lives in the caller's casing. Responses are
// parsed with h2o/picohttpparser.
#ifndef HOLYTLS_H1_H
#define HOLYTLS_H1_H

#include "base/base.h"
#include "base/string8.h"
#include "core/header.h"

typedef struct H1Response H1Response;
struct H1Response {
  int status;
  HeaderList *headers;  // arena-owned copies, valid until session release
  U8 *body;             // arena-owned (transfer-decoded), valid until release
  U64 body_len;
  B32 ok;  // false on parse error / premature close before headers complete
};

typedef void (*H1SendFn)(void *user, const U8 *data, U64 len);
typedef void (*H1RespFn)(void *user, const H1Response *resp);

typedef struct H1Session H1Session;

// Allocate a session (own arena). `send_fn` receives the serialized request
// plaintext (the TLS layer encrypts it).
H1Session *h1_session_alloc(H1SendFn send_fn, void *send_user);
void h1_session_release(H1Session *s);

// Serialize + emit the request: "<METHOD> <path> HTTP/1.1", Host first, then
// `headers` verbatim (names already wire-cased, in order), blank line, body. No
// Connection header (HTTP/1.1 keep-alive default). `is_head` suppresses the
// response body. Returns 0 on success, <0 on error.
S32 h1_session_submit_request(H1Session *s, String8 method, String8 authority,
                              String8 path, const Header *headers,
                              U64 header_count, const U8 *body, U64 body_len,
                              B32 is_head, H1RespFn cb, void *user);

// Feed received plaintext. Returns bytes consumed (>=0) or <0 on protocol error.
S64 h1_session_recv(H1Session *s, const U8 *data, U64 len);

// Peer closed the connection (clean EOF). Finalizes + delivers a close-delimited
// body; no-op if already delivered or if the response was incomplete (the caller
// then reports a connection-closed error).
void h1_session_eof(H1Session *s);

#endif  // HOLYTLS_H1_H
