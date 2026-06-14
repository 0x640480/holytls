// H2Session — a client HTTP/2 session over nghttp2, configured to emit the
// exact SETTINGS (values + order), connection WINDOW_UPDATE, request priority
// and pseudo-header order of a profile (the Akamai-fingerprint surface). It
// owns no transport: outgoing bytes go to a send callback, incoming plaintext
// is fed to h2_session_recv.
#ifndef HOLYTLS_H2_H
#define HOLYTLS_H2_H

#include "base/arena.h"
#include "base/string8.h"
#include "core/header.h"
#include "profile/profile.h"

typedef struct H2Response H2Response;
struct H2Response {
  S32 stream_id;
  int status;
  HeaderList *headers;  // valid until the session is released
  U8 *body;
  U64 body_len;
  B32 ok;  // false if the stream was reset / errored
};

typedef void (*H2SendFn)(void *user, const U8 *data, U64 len);
typedef void (*H2RespFn)(void *user, const H2Response *resp);
// Streaming response sink: invoked with DECODED body chunks as DATA frames
// arrive (Content-Encoding stripped), instead of buffering. When set on a
// submit, the delivered H2Response carries an empty body.
typedef void (*H2ChunkFn)(void *user, const U8 *data, U64 len);

typedef struct H2Session H2Session;

// Allocate a session (with its own arena). `send_fn` receives outgoing
// plaintext (which the TLS layer encrypts). Returns 0 on nghttp2 init failure.
H2Session *h2_session_alloc(const Http2Profile *prof, H2SendFn send_fn,
                            void *send_user);
void h2_session_release(H2Session *s);

// Emit the preface: SETTINGS (exact order) + connection WINDOW_UPDATE.
B32 h2_session_start(H2Session *s);
// Feed received plaintext into nghttp2. Returns bytes consumed, or <0 on error.
S64 h2_session_recv(H2Session *s, const U8 *data, U64 len);
B32 h2_session_flush(H2Session *s);

// Submit a request. Pseudo-headers go first in the profile's order, then
// `headers` in array order. `body` (may be empty) is copied + streamed as DATA.
// Returns the stream id (>=0) or a negative nghttp2 error. When `on_chunk` is
// non-null the response body is STREAMED (decoded chunks delivered to
// `on_chunk(chunk_user, ...)` as they arrive) rather than buffered, and the
// final H2Response body is empty; pass 0,0 for the normal buffered path.
S32 h2_session_submit_request(H2Session *s, String8 method, String8 scheme,
                              String8 authority, String8 path,
                              const Header *headers, U64 header_count,
                              const U8 *body, U64 body_len, H2RespFn cb,
                              void *user, H2ChunkFn on_chunk, void *chunk_user);

// Cancel an in-flight request stream (RST_STREAM, CANCEL): the server stops
// sending and the stream's response callback will NOT fire (its user data is
// cleared). Used to abort a single multiplexed request (e.g. a timeout) without
// disturbing the others on the connection.
void h2_session_cancel_stream(H2Session *s, S32 stream_id);

B32 h2_session_want_write(H2Session *s);
B32 h2_session_want_read(H2Session *s);
B32 h2_session_idle(H2Session *s);

// Peer's advertised SETTINGS_MAX_CONCURRENT_STREAMS (a large default until the
// server's SETTINGS arrive). True once a GOAWAY has been received.
U32 h2_session_max_concurrent_streams(H2Session *s);
B32 h2_session_goaway_received(H2Session *s);

#endif  // HOLYTLS_H2_H
