#include "ws/ws.h"

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <picohttpparser.h>
#include <stdlib.h>

#include "base/base64.h"
#include "base/u8buf.h"
#include "core/url.h"
#include "h2/h2.h"
#include "net/connection.h"
#include "net/loop.h"
#include "profile/profile.h"

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// One received application message (or the peer Close), copied off the parser's
// transient buffer so it survives until the caller's recv pops it. Flexible
// array tail holds `len` payload bytes; malloc'd, freed when popped/dropped.
typedef struct WsMsg WsMsg;
struct WsMsg {
  WsMsg *next;
  WsOpcode op;
  U16 close_code;
  B32 is_close;
  U64 len;
  U8 data[];
};

struct WsConn {
  Arena *arena;
  Client *client;
  EventLoop *loop;
  Connection conn;
  B32 conn_inited;
  WsTransport transport;
  WsParser parser;

  // HTTP/2 (RFC 8441) transport: the WS rides a CONNECT stream on an H2Session
  // layered over the same Connection. (Unused for the H1 path.)
  H2Session *h2;
  S32 h2_stream;
  B32 h2_submitted;  // the CONNECT request has been sent
  B32 in_h2_recv;    // inside ws_h2_drain's recv loop: defer outbound flushes
                     // (nghttp2 forbids a reentrant session_send; the recv's
                     // own trailing flush ships queued auto-pongs)

  String8 authority, path, origin;
  U16 port;

  String8 accept_expected;  // base64(sha1(key + GUID)) for the 101 verify
  U8Buf hs_in;              // handshake-response accumulation (pre-established)
  const Header *hs_extra;   // caller's extra handshake headers (arena copies)
  U64 hs_extra_count;
  B32 established;

  // Inbound message queue (FIFO). The parser callback enqueues; recv dequeues.
  WsMsg *in_head, *in_tail;
  WsMsg *cur_msg;  // the message handed to the last recv (freed on the next)

  ReqTimer *connect_timer;
  B32 got_peer_close;    // the peer sent a Close (its half of the handshake)
  B32 close_timed_out;   // close-handshake wait expired (silent peer)
  B32 closed, fully_closed, fail;
  const char *err;
};

internal void ws_wake(WsConn *w) { loop_stop(w->loop); }

// --- the RFC 6455 parser's event sink --------------------------------------

internal void ws_on_event(void *user, const WsEvent *ev) {
  WsConn *w = (WsConn *)user;
  if (ev->kind == WsEvent_Ping) {
    ws_conn_send(w, WsOp_Pong, ev->data, ev->len);  // auto-reply (echo payload)
    return;
  }
  if (ev->kind == WsEvent_Pong) return;  // unsolicited pong: ignore
  // Message or Close: copy off the parser buffer + enqueue, then wake any recv.
  WsMsg *m = (WsMsg *)malloc(sizeof(WsMsg) + ev->len);
  if (!m) {
    w->fail = 1;
    w->err = "out of memory";
    ws_wake(w);
    return;
  }
  m->next = 0;
  m->op = ev->op;
  m->is_close = (ev->kind == WsEvent_Close);
  if (m->is_close) w->got_peer_close = 1;  // for ws_conn_close's bounded wait
  m->close_code = ev->close_code;
  m->len = ev->len;
  if (ev->len) MemoryCopy(m->data, ev->data, ev->len);
  if (w->in_tail)
    w->in_tail->next = m;
  else
    w->in_head = m;
  w->in_tail = m;
  ws_wake(w);
}

// --- HTTP/1.1 Upgrade -------------------------------------------------------

// Build + send the GET upgrade handshake. NOTE: this serializes the request
// directly (not h1_session_submit_request, which strips Connection + injects
// Host). The exact Chrome WS header set/order is finalized in the fingerprint
// pass; this is a functional, Chrome-coherent handshake.
internal void ws_h1_send_handshake(WsConn *w, const Header *headers,
                                   U64 header_count) {
  U8 keyb[16];
  RAND_bytes(keyb, sizeof keyb);
  String8 key = base64_encode(w->arena, str8(keyb, sizeof keyb));

  // accept_expected = base64(SHA1(key + GUID))
  String8 concat = push_str8_cat(w->arena, key, str8_lit(WS_GUID));
  U8 digest[20];
  SHA1(concat.str, concat.size, digest);
  w->accept_expected = base64_encode(w->arena, str8(digest, sizeof digest));

  const Profile *p = w->client->profile;
  U8Buf req;
  u8buf_init(&req, w->arena, 512);
#define WS_PUT(s) u8buf_append(&req, (const U8 *)(s).str, (s).size)
#define WS_PUTL(s) u8buf_append(&req, (const U8 *)(s), sizeof(s) - 1)
  WS_PUTL("GET ");
  WS_PUT(w->path);
  WS_PUTL(" HTTP/1.1\r\nHost: ");
  WS_PUT(w->authority);
  WS_PUTL(
      "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: "
      "13\r\nSec-WebSocket-Key: ");
  WS_PUT(key);
  WS_PUTL("\r\nUser-Agent: ");
  WS_PUT(profile_user_agent(p));
  WS_PUTL("\r\nOrigin: ");
  WS_PUT(w->origin);
  WS_PUTL("\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: ");
  WS_PUT(profile_accept_language(p));
  WS_PUTL("\r\n");
  for (U64 i = 0; i < header_count; ++i) {  // caller extras, verbatim
    WS_PUT(headers[i].name);
    WS_PUTL(": ");
    WS_PUT(headers[i].value);
    WS_PUTL("\r\n");
  }
  WS_PUTL("\r\n");
#undef WS_PUT
#undef WS_PUTL
  conn_send_plaintext(&w->conn, req.v, req.len);
}

// Try to parse the accumulated handshake response (101). On a complete + valid
// response: mark established, feed any leftover bytes (first frames) to the
// parser, wake connect. On a bad response: fail.
internal void ws_h1_try_handshake(WsConn *w) {
  int minor, status;
  const char *msg;
  size_t msg_len, nhdr = 32;
  struct phr_header hdrs[32];
  int rc = phr_parse_response((const char *)w->hs_in.v, w->hs_in.len, &minor,
                              &status, &msg, &msg_len, hdrs, &nhdr, 0);
  if (rc == -2) return;  // incomplete; await more bytes
  if (rc < 0) {
    w->fail = 1;
    w->err = "malformed upgrade response";
    ws_wake(w);
    return;
  }
  if (status != 101) {
    w->fail = 1;
    w->err = "upgrade rejected (not 101)";
    ws_wake(w);
    return;
  }
  // Verify Sec-WebSocket-Accept.
  String8 accept = str8_zero();
  for (size_t i = 0; i < nhdr; ++i) {
    String8 n = str8((U8 *)hdrs[i].name, hdrs[i].name_len);
    if (str8_match_ci(n, str8_lit("sec-websocket-accept")))
      accept = str8((U8 *)hdrs[i].value, hdrs[i].value_len);
  }
  if (!str8_match(accept, w->accept_expected)) {
    w->fail = 1;
    w->err = "bad Sec-WebSocket-Accept";
    ws_wake(w);
    return;
  }
  w->established = 1;
  // Bytes after the header terminator are the first WS frames.
  if ((U64)rc < w->hs_in.len)
    ws_parser_feed(&w->parser, w->hs_in.v + rc, w->hs_in.len - (U64)rc,
                   ws_on_event, w);
  ws_wake(w);
}

// Connection has decrypted bytes: pre-101 accumulate + parse the handshake;
// post-101 feed frames to the parser.
internal void ws_h1_drain(void *user) {
  WsConn *w = (WsConn *)user;
  U8 buf[16384];
  for (;;) {
    int n = conn_read_plaintext(&w->conn, buf, sizeof buf);
    if (n <= 0) break;
    if (!w->established) {
      u8buf_append(&w->hs_in, buf, (U64)n);
      ws_h1_try_handshake(w);
      if (!w->established) continue;  // need more handshake bytes (or failed)
    } else if (ws_parser_feed(&w->parser, buf, (U64)n, ws_on_event, w) < 0) {
      w->fail = 1;
      w->err = "ws protocol error";
      ws_wake(w);
      break;
    }
  }
}

// --- HTTP/2 Extended CONNECT (RFC 8441) -------------------------------------

// H2Session send sink: hand outgoing H2 plaintext to the connection (encrypted
// + written by the TLS layer).
internal void ws_h2_send(void *user, const U8 *data, U64 len) {
  WsConn *w = (WsConn *)user;
  conn_send_plaintext(&w->conn, data, len);
}

// The CONNECT response HEADERS arrived: 200 => established, else fail.
internal void ws_h2_on_connect(void *user, int status) {
  WsConn *w = (WsConn *)user;
  if (status == 200) {
    w->established = 1;
  } else {
    w->fail = 1;
    w->err = "h2 websocket rejected (status != 200)";
  }
  ws_wake(w);
}

// Inbound CONNECT-stream DATA = WS frame bytes (or a (0,0) EOF on stream close).
internal void ws_h2_on_data(void *user, const U8 *data, U64 len) {
  WsConn *w = (WsConn *)user;
  if (!data || len == 0) {  // the CONNECT stream closed
    w->closed = 1;
    ws_wake(w);
    return;
  }
  if (ws_parser_feed(&w->parser, data, len, ws_on_event, w) < 0) {
    w->fail = 1;
    w->err = "ws protocol error";
    ws_wake(w);
  }
}

// Submit the Extended CONNECT once the peer's ENABLE_CONNECT_PROTOCOL is known.
// WS-over-H2 carries NO Sec-WebSocket-Key (the H2 stream replaces the accept
// handshake); Sec-WebSocket-Version + UA + caller extras ride as regular fields.
internal void ws_h2_submit(WsConn *w) {
  w->h2_submitted = 1;
  const Profile *p = w->client->profile;
  U64 nh = 2 + w->hs_extra_count;
  Header *hs = push_array(w->arena, Header, nh);
  U64 k = 0;
  hs[k++] = (Header){str8_lit("sec-websocket-version"), str8_lit("13"), 0};
  hs[k++] = (Header){str8_lit("user-agent"), profile_user_agent(p), 0};
  for (U64 i = 0; i < w->hs_extra_count; ++i) hs[k++] = w->hs_extra[i];
  w->h2_stream = h2_session_ws_connect(
      w->h2, str8_lit("https"), w->authority, w->path, str8_lit("websocket"), hs,
      nh, ws_h2_on_connect, w, ws_h2_on_data, w);
  if (w->h2_stream < 0) {
    w->fail = 1;
    w->err = "h2 websocket CONNECT submit failed";
    ws_wake(w);
  }
}

// Connection readable (H2): feed plaintext into nghttp2; once the server's
// SETTINGS enable Extended CONNECT, submit the CONNECT.
internal void ws_h2_drain(void *user) {
  WsConn *w = (WsConn *)user;
  w->in_h2_recv = 1;
  U8 buf[16384];
  int n;
  while ((n = conn_read_plaintext(&w->conn, buf, sizeof buf)) > 0) {
    if (h2_session_recv(w->h2, buf, (U64)n) < 0) {
      w->fail = 1;
      w->err = "h2 protocol error";
      break;
    }
  }
  w->in_h2_recv = 0;
  if (!w->fail && !w->h2_submitted &&
      h2_session_connect_protocol_enabled(w->h2))
    ws_h2_submit(w);
  if (w->fail) ws_wake(w);
}

// --- connection lifecycle ---------------------------------------------------

internal void ws_on_ready(void *user, B32 ok, const char *err) {
  WsConn *w = (WsConn *)user;
  if (!ok) {
    w->fail = 1;
    w->err = err ? err : "connect failed";
    ws_wake(w);
    return;
  }
  String8 alpn = conn_alpn(&w->conn);
  if (str8_match(alpn, str8_lit("h2"))) {
    // HTTP/2 Extended CONNECT (RFC 8441): run an H2 session over this
    // connection and open a CONNECT stream once the server permits it. The
    // CONNECT is submitted later, from ws_h2_drain, after the server's SETTINGS
    // advertise ENABLE_CONNECT_PROTOCOL.
    w->transport = WsTransport_H2;
    w->h2 = h2_session_alloc(&w->client->profile->h2, ws_h2_send, w);
    if (!w->h2) {
      w->fail = 1;
      w->err = "h2 session init failed";
      ws_wake(w);
      return;
    }
    conn_on_readable(&w->conn, ws_h2_drain, w);
    if (!h2_session_start(w->h2)) {  // emit our preface (SETTINGS + WINDOW_UPDATE)
      w->fail = 1;
      w->err = "h2 session start failed";
      ws_wake(w);
    }
    return;
  }
  w->transport = WsTransport_H1;
  conn_on_readable(&w->conn, ws_h1_drain, w);
  ws_h1_send_handshake(w, w->hs_extra, w->hs_extra_count);
}

internal void ws_on_closed(void *user, const char *err) {
  WsConn *w = (WsConn *)user;
  if (!w->err && err) w->err = err;
  w->closed = 1;
  ws_wake(w);
}

internal void ws_on_fully_closed(void *user) {
  WsConn *w = (WsConn *)user;
  w->fully_closed = 1;
  ws_wake(w);
}

internal void ws_on_connect_timeout(void *user) {
  WsConn *w = (WsConn *)user;
  if (!w->established) {
    w->fail = 1;
    w->err = "timeout";
    ws_wake(w);
  }
}

internal void ws_on_close_timeout(void *user) {
  WsConn *w = (WsConn *)user;
  w->close_timed_out = 1;
  ws_wake(w);
}

// --- public API -------------------------------------------------------------

WsConn *ws_conn_alloc(Client *client) {
  Arena *a = arena_alloc();
  WsConn *w = push_struct(a, WsConn);
  w->arena = a;
  w->client = client;
  w->loop = client->loop;
  ws_parser_init(&w->parser, 0);
  u8buf_init(&w->hs_in, a, 1024);
  return w;
}

B32 ws_conn_connect(WsConn *w, String8 url, const Header *headers,
                    U64 header_count) {
  // Normalize wss:// -> https:// (ws:// -> http://) so url_parse handles it; WS
  // rides over the same TLS connection.
  String8 u = url;
  if (str8_starts_with(url, str8_lit("wss://")))
    u = push_str8_cat(w->arena, str8_lit("https://"), str8_skip(url, 6));
  else if (str8_starts_with(url, str8_lit("ws://")))
    u = push_str8_cat(w->arena, str8_lit("http://"), str8_skip(url, 5));
  ParsedUrl pu = url_parse(u);
  if (!pu.ok || !pu.https) {
    w->fail = 1;
    w->err = "invalid wss:// url";
    return 0;
  }
  w->authority = push_str8_copy(w->arena, pu.authority);
  w->path = push_str8_copy(w->arena, pu.path);
  w->port = pu.port;
  w->origin = push_str8_cat(w->arena, str8_lit("https://"), pu.authority);

  // Copy the extra headers into the arena so they survive into ws_on_ready.
  Header *hs = 0;
  if (header_count) {
    hs = push_array(w->arena, Header, header_count);
    for (U64 i = 0; i < header_count; ++i) {
      hs[i].name = push_str8_copy(w->arena, headers[i].name);
      hs[i].value = push_str8_copy(w->arena, headers[i].value);
      hs[i].flags = 0;
    }
  }
  w->hs_extra = hs;
  w->hs_extra_count = header_count;

  // Honor a forced http/1.1 (h1_tls = http/1.1-only ALPN); else the normal
  // h2,http/1.1 ALPN lets the server pick the transport (mirrors client.c).
  const TlsProfile *tls = w->client->http_version == HttpVersion_H1
                              ? &w->client->h1_tls
                              : &w->client->profile->tls;
  conn_init(&w->conn, w->client->loop, w->client->ctx.ctx, tls);
  w->conn_inited = 1;
  conn_on_closed(&w->conn, ws_on_closed, w);
  conn_on_fully_closed(&w->conn, ws_on_fully_closed, w);
  conn_set_dns_cache(&w->conn, &w->client->dns_cache);

  U64 t = client_get_timeout_ms(w->client);
  w->connect_timer = req_timer_arm(w->loop, t ? uv_hrtime() + t * 1000000ull : 0,
                                   ws_on_connect_timeout, w);
  conn_connect(&w->conn, push_str8_cstr(w->arena, pu.host), w->port, ws_on_ready,
               w);
  while (!w->established && !w->fail && !w->closed) loop_run(w->loop);
  req_timer_disarm(w->connect_timer);
  w->connect_timer = 0;
  return w->established ? 1 : 0;
}

B32 ws_conn_send(WsConn *w, WsOpcode op, const U8 *data, U64 len) {
  if (w->fail || w->closed || !w->established) return 0;
  U8 mask[4];
  RAND_bytes(mask, sizeof mask);
  // conn_send_plaintext copies the frame into the SSL write BIO synchronously,
  // so the build buffer is dead on return: rewind it so a long-lived, chatty
  // socket doesn't grow the arena one frame at a time.
  Temp t = temp_begin(w->arena);
  U8Buf f;
  u8buf_init(&f, w->arena, len + 16);
  ws_frame_build(&f, op, 1, data, len, mask);
  B32 ok;
  if (w->transport == WsTransport_H2) {
    // Queue the frame as CONNECT-stream DATA. Skip the flush when inside the
    // recv loop (an auto-pong) — that flush would reenter nghttp2_session_send;
    // ws_h2_drain's h2_session_recv flushes it instead.
    ok = h2_session_ws_send(w->h2, w->h2_stream, f.v, f.len);
    if (ok && !w->in_h2_recv) h2_session_flush(w->h2);
  } else {
    ok = conn_send_plaintext(&w->conn, f.v, f.len);
  }
  temp_end(t);
  return ok;
}

int ws_conn_recv(WsConn *w, WsEvent *out) {
  if (w->cur_msg) {  // free the message handed out by the previous recv
    free(w->cur_msg);
    w->cur_msg = 0;
  }
  for (;;) {
    if (w->in_head) {
      WsMsg *m = w->in_head;
      w->in_head = m->next;
      if (!w->in_head) w->in_tail = 0;
      w->cur_msg = m;  // keep alive until the next recv
      MemoryZeroStruct(out);
      out->op = m->op;
      out->data = m->data;  // flexible array: always non-null, even for len 0
      out->len = m->len;
      if (m->is_close) {
        out->kind = WsEvent_Close;
        out->close_code = m->close_code;
        return 0;
      }
      out->kind = WsEvent_Message;
      return 1;
    }
    if (w->fail || w->closed) return -1;
    loop_run(w->loop);  // blocks until an event / close wakes us
  }
}

void ws_conn_close(WsConn *w, U16 code, String8 reason) {
  if (w->established && !w->closed && !w->fail) {
    U8 payload[125];
    U64 plen = 0;
    payload[plen++] = (U8)(code >> 8);
    payload[plen++] = (U8)code;
    U64 rn = reason.size < sizeof payload - 2 ? reason.size : sizeof payload - 2;
    if (rn) MemoryCopy(payload + 2, reason.str, rn);
    plen += rn;
    ws_conn_send(w, WsOp_Close, payload, plen);
    // Run the loop to actually flush the Close (egress writes are async, so an
    // immediate conn_close would cancel it) and complete the RFC 6455 close
    // handshake by awaiting the peer's Close — bounded so a silent peer can't
    // hang teardown.
    w->close_timed_out = 0;
    ReqTimer *t =
        req_timer_arm(w->loop, uv_hrtime() + 2000000000ull /*2s*/,
                      ws_on_close_timeout, w);
    while (!w->got_peer_close && !w->closed && !w->fail && !w->close_timed_out)
      loop_run(w->loop);
    req_timer_disarm(t);
    // H2: half-close the CONNECT stream (END_STREAM) now that the WS Close is done.
    if (w->transport == WsTransport_H2 && w->h2) {
      h2_session_ws_finish(w->h2, w->h2_stream);
      h2_session_flush(w->h2);
    }
  }
  if (w->conn_inited) conn_close(&w->conn);
  w->closed = 1;
}

void ws_conn_free(WsConn *w) {
  if (!w) return;
  if (w->conn_inited) {
    conn_close(&w->conn);
    // Drain the close so on_fully_closed fires before we free the SSL/BIOs.
    w->fully_closed = 0;
    while (!w->fully_closed && uv_loop_alive(loop_uv(w->loop)))
      loop_run(w->loop);
    conn_cleanup(&w->conn);
  }
  if (w->h2) h2_session_release(w->h2);
  for (WsMsg *m = w->in_head; m;) {
    WsMsg *n = m->next;
    free(m);
    m = n;
  }
  if (w->cur_msg) free(w->cur_msg);
  ws_parser_free(&w->parser);
  arena_release(w->arena);
}

WsTransport ws_conn_transport(WsConn *w) { return w->transport; }
const char *ws_conn_error(WsConn *w) { return w->err; }
