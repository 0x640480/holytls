// ConnPool — a per-Client, origin-keyed pool of reusable, multiplexed
// connections. It decouples the transport (Connection/QuicConnection + session)
// from the per-request struct: a pool-owned PoolConn outlives individual
// requests, and many PoolReqs ride one PoolConn as concurrent streams (H2 now;
// H3 in a later phase). The Client is single-threaded (one EventLoop), so the
// pool needs no locking. Opt-in: a Client with no pool takes the legacy
// per-request path (see core/client.c). Mirrors the alt-svc keyed-cache idiom
// (origin "host:port", linear scan, uv_now ms clock).
#ifndef HOLYTLS_POOL_H
#define HOLYTLS_POOL_H

#include <nghttp3/nghttp3.h>
#include <uv.h>

#include "base/u8buf.h"
#include "core/client.h"
#include "h2/h2.h"
#include "net/connection.h"
#include "net/quic_connection.h"

typedef enum PoolProto { PoolProto_H2, PoolProto_H3 } PoolProto;

typedef enum PoolConnState {
  PoolConnState_Handshaking,  // connect/handshake in flight; queue requests
  PoolConnState_Ready,        // established; submit streams immediately
  PoolConnState_Closing,      // close issued, waiting for fully-closed
} PoolConnState;

typedef struct PoolReq PoolReq;
typedef struct PoolConn PoolConn;
typedef struct H3Conn H3Conn;

// Server-initiated uni stream (control + QPACK enc/dec) type tracking — a tiny
// fixed set scanned linearly (mirrors h3_session.c's H3Uni; named distinctly to
// coexist with it in the unity translation unit).
typedef struct PoolH3Uni PoolH3Uni;
struct PoolH3Uni {
  S64 id;
  B32 type_read;
  U64 type;
};

// One HTTP exchange riding a pooled connection (its own short-lived arena, freed
// on completion). References — never owns — its PoolConn.
struct PoolReq {
  Arena *arena;
  Client *client;
  PoolConn *pc;
  PoolProto proto;

  ResponseFn cb;
  void *user;
  U64 t_start_ns;  // request start (uv_hrtime) for Response.timing.total_ms

  // Original request inputs (kept for the H1 fallback re-dispatch).
  Method method_enum;
  String8 url;  // arena-copied; the views below point into it
  Header *caller_headers;
  U64 caller_header_count;
  String8 caller_body;

  // Parsed origin/target.
  String8 host, scheme, authority, path, origin;
  U16 port;

  // Built per submit (H2): merged Chrome-default + caller headers.
  HeaderList req_headers;
  HeaderList resp_headers;  // filtered view when the body is decoded
  String8 body;             // dup'd body for the submit
  S32 h2_stream_id;         // H2 routing
  int retries_left;         // retry on a fresh conn (stale reuse / GOAWAY refusal)
  B32 responded;
  U64 deadline_ns;          // whole-operation timeout deadline (0 = none)
  ReqTimer *timeout;        // the armed deadline timer (0 = none)

  // H3 per-request state (proto == PoolProto_H3).
  S64 h3_stream_id;
  U8Buf h3_in;   // buffered response on the request stream
  int h3_status;
  B32 h3_fin;

  PoolReq *queue_next;   // intrusive: PoolConn.waiting list (pre-submit)
  PoolReq *active_next;  // intrusive: PoolConn.active list (submitted)
};

// A pooled connection (owns the transport + session + its own arena).
struct PoolConn {
  Arena *arena;
  Client *client;
  ConnPool *pool;
  PoolProto proto;
  char origin[256];  // "host:port" key (alt-svc convention)
  PoolConnState state;
  B32 broken;     // GOAWAY/error: stop new submits, evict once drained
  B32 in_drain;   // inside this conn's recv loop: defer submits (no nghttp2 re-entry)
  B32 idle;       // inflight==0 + unref'd (edge-triggered; H3 recv fires often)
  U32 inflight;
  U64 idle_since_ms;

  Connection h2_conn;  // H2 transport (by value, proto == PoolProto_H2)
  H2Session *h2;

  QuicConnection h3_conn;  // H3 transport (by value, proto == PoolProto_H3)
  H3Conn *h3c;

  PoolReq *waiting_head, *waiting_tail;  // queued pre-ready / over-capacity
  PoolReq *active_head;                  // submitted, awaiting response
};

// Per-connection HTTP/3 state: the shared QPACK codecs (encoder is static-only =
// stateless across requests; decoder's dynamic table is per-connection by spec)
// and the control + QPACK uni streams opened once per connection. Request bidi
// streams route back to their PoolReq via `streams[]`.
#define H3_MAX_STREAMS 16
struct H3Conn {
  const Http3Profile *prof;
  const nghttp3_mem *mem;
  nghttp3_qpack_encoder *qenc;
  nghttp3_qpack_decoder *qdec;
  B32 control_opened;
  S64 ctrl_id, qenc_id, qdec_id;
  PoolH3Uni uni[8];
  int uni_count;
  PoolReq *streams[H3_MAX_STREAMS];  // request stream_id -> owning PoolReq
  int stream_count;
};

#define POOL_MAX_CONNS 256
#define POOL_DEFAULT_IDLE_MS 5000
#define POOL_SWEEP_INTERVAL_MS 1000
#define POOL_MAX_RETRIES 2  // retry a request on a fresh conn this many times

struct ConnPool {
  Arena *arena;  // owns the ConnPool + the conns[] pointer array
  Client *client;
  PoolConn *conns[POOL_MAX_CONNS];
  int count;
  uv_timer_t sweep;
  B32 sweep_inited;
};

// Lifecycle (called from core/client.c).
ConnPool *pool_alloc(Client *c);
void pool_free(ConnPool *p);    // arena_release (call once conns are drained)
void pool_drain(ConnPool *p);   // begin closing all conns + the sweep timer
// Stop reusing every current conn (mark broken) and close the idle ones; in-flight
// conns finish then close. Keeps the pool live for new conns (runtime proxy switch).
void pool_evict_all(ConnPool *p);

// Dispatch a request through the pool (acquire/reuse a conn, multiplex a stream).
void pool_dispatch(Client *c, PoolProto proto, Method m, String8 url,
                   const Header *headers, U64 header_count, const U8 *body,
                   U64 body_len, ResponseFn cb, void *user, U64 deadline_ns);

#endif  // HOLYTLS_POOL_H
