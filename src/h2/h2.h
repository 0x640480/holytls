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
  HeaderList *headers;  // valid ONLY during the callback (the stream's per-
                        // request arena is reclaimed right after it returns)
  U8 *body;             // valid ONLY during the callback (same as headers)
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

// --- WebSocket over HTTP/2 (RFC 8441 Extended CONNECT) ----------------------
// The CONNECT stream is bidirectional + long-lived: establishment fires
// on_connect(:status), inbound DATA streams to on_data, outbound bytes queue
// via h2_session_ws_send. DATA is opaque (no Content-Encoding handling): WS
// frames ride the stream body directly. response :status arrived; `extensions`
// is the Sec-WebSocket-Extensions response header value (str8_zero if absent)
// for permessage-deflate negotiation.
typedef void (*H2ConnectFn)(void *user, int status, String8 extensions);
// Inbound CONNECT-stream DATA. A final call with (data==0, len==0) signals the
// stream closed (EOF) — real DATA chunks are always non-empty.
typedef void (*H2DataFn)(void *user, const U8 *data, U64 len);

// True once the peer's SETTINGS advertised ENABLE_CONNECT_PROTOCOL=1 (Extended
// CONNECT permitted). Poll after h2_session_recv before h2_session_ws_connect.
B32 h2_session_connect_protocol_enabled(H2Session *s);

// Open a WebSocket CONNECT stream: :method=CONNECT, :protocol, :scheme, :path,
// :authority (profile pseudo order; :protocol right after :method) + `headers`.
// A deferred data provider carries the bidirectional body. Returns the stream
// id
// (>=0) or a negative nghttp2 error.
S32 h2_session_ws_connect(H2Session *s, String8 scheme, String8 authority,
                          String8 path, String8 protocol, const Header *headers,
                          U64 header_count, H2ConnectFn on_connect,
                          void *connect_user, H2DataFn on_data,
                          void *data_user);

// Queue outbound bytes on the CONNECT stream + un-defer its provider. Does NOT
// flush — call h2_session_flush after (or, when invoked from inside a recv
// callback, rely on h2_session_recv's trailing flush; nghttp2 forbids a
// reentrant nghttp2_session_send). Returns 0 if the stream is unknown/closed.
B32 h2_session_ws_send(H2Session *s, S32 stream_id, const U8 *data, U64 len);

// Half-close the CONNECT stream: EOF the provider so the next emitted DATA
// frame carries END_STREAM. Does NOT flush (see h2_session_ws_send).
void h2_session_ws_finish(H2Session *s, S32 stream_id);

B32 h2_session_want_write(H2Session *s);
B32 h2_session_want_read(H2Session *s);
B32 h2_session_idle(H2Session *s);

// Peer's advertised SETTINGS_MAX_CONCURRENT_STREAMS (a large default until the
// server's SETTINGS arrive). True once a GOAWAY has been received.
U32 h2_session_max_concurrent_streams(H2Session *s);
B32 h2_session_goaway_received(H2Session *s);

// Bytes currently used in the SESSION arena (introspection / tests). With per-
// request arenas this stays ~flat as streams come and go on a reused
// connection; a regression that re-routed per-request allocations back to the
// session arena would make it grow ~linearly with request count.
U64 h2_session_arena_used(H2Session *s);

#endif  // HOLYTLS_H2_H
