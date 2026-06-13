// H3Session — client HTTP/3 over a QuicConnection, Option B: we hand-roll the
// HTTP/3 framing (control stream via h3_control.c for exact SETTINGS+GREASE+
// PRIORITY_UPDATE; request HEADERS/DATA frames) and use nghttp3 only as a
// standalone QPACK codec. This gives byte-exact fingerprint control (matches
// the offline-proven h3_hash) while leaving QPACK's complexity to nghttp3.
#ifndef HOLYTLS_H3_SESSION_H
#define HOLYTLS_H3_SESSION_H

#include "base/base.h"
#include "base/string8.h"
#include "core/header.h"
#include "net/quic_connection.h"
#include "profile/profile.h"

typedef struct H3Response H3Response;
struct H3Response {
  B32 ok;
  const char *error;
  int status;
  const Header *headers;  // views into the session's header arena
  U64 header_count;
  const U8 *body;  // view into the session's receive buffer
  U64 body_len;
};

typedef void (*H3RespFn)(void *user, const H3Response *resp);

typedef struct H3Session H3Session;

// Allocate a session (own arena + QPACK codecs) and register the connection's
// stream callbacks. Returns 0 on nghttp3 init failure.
H3Session *h3_session_alloc(QuicConnection *conn, const Http3Profile *prof);
void h3_session_release(H3Session *s);

// Open control/QPACK streams + submit the request. Call after the handshake.
// `headers` are emitted in order after the pseudo-headers (caller-owned views,
// valid for the duration of the call). A non-empty `body` is sent as a DATA
// frame after HEADERS. Returns false on a submit failure.
B32 h3_session_request(H3Session *s, String8 method, String8 scheme,
                       String8 authority, String8 path, const Header *headers,
                       U64 header_count, const U8 *body, U64 body_len,
                       H3RespFn cb, void *user);

#endif  // HOLYTLS_H3_SESSION_H
