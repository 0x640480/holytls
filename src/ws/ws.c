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

#ifdef HOLYTLS_HAVE_ZLIB
#include <zlib.h>
#endif

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// permessage-deflate (RFC 7692) is available only with zlib (always present in
// a real build — it backs gzip too). Without it the WS handshake does not
// advertise the extension.
#ifdef HOLYTLS_HAVE_ZLIB
#define WS_HAVE_DEFLATE 1
#else
#define WS_HAVE_DEFLATE 0
#endif

// ALPN wire (RFC 7301) advertising only http/1.1 — the default WS offer.
global const U8 g_ws_alpn_h11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

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
  TlsProfile ws_h1_tls;  // profile TLS with http/1.1-only ALPN (default WS)
  B32 established;

  // Inbound message queue (FIFO). The parser callback enqueues; recv dequeues.
  WsMsg *in_head, *in_tail;
  WsMsg *cur_msg;  // the message handed to the last recv (freed on the next)

  // permessage-deflate (RFC 7692), negotiated at the handshake. The deflate
  // (send) + inflate (recv) streams are PERSISTENT across messages (context
  // takeover): the deflate stream resets per message only if the server replied
  // client_no_context_takeover; the inflate stream is always kept (a persistent
  // window decodes both context-takeover and self-contained messages).
  B32 pmd;  // permessage-deflate negotiated
  B32 client_no_context_takeover;
  int client_max_window_bits;  // our deflate window (8..15; default 15)
#if WS_HAVE_DEFLATE
  z_stream deflate_zs;
  z_stream inflate_zs;
  B32 deflate_init, inflate_init;
#endif

  ReqTimer *connect_timer;
  B32 got_peer_close;   // the peer sent a Close (its half of the handshake)
  B32 close_timed_out;  // close-handshake wait expired (silent peer)
  B32 recv_timed_out;   // ws_conn_recv's deadline elapsed (connection stays up)
  B32 closed, fully_closed, fail;
  const char *err;
};

internal void ws_wake(WsConn *w) { loop_stop(w->loop); }

// --- permessage-deflate (RFC 7692) ------------------------------------------

// Parse the server's negotiated Sec-WebSocket-Extensions response. Enables
// compression only if it actually offered permessage-deflate; records the
// client-side params (no_context_takeover, max_window_bits) that govern OUR
// deflate stream. The server-side params need no action: we inflate with a
// max (-15) persistent window, which decodes any server window / takeover mode.
internal void ws_pmd_negotiate(WsConn *w, String8 ext) {
#if WS_HAVE_DEFLATE
  if (ext.size == 0) return;
  // Sec-WebSocket-Extensions is a comma-separated list; each item is an
  // extension name then ';'-separated params. Match the extension NAME exactly
  // (not a substring — "x-my-permessage-deflate" must not match), then read its
  // params from that item only.
  String8 pmd = str8_zero();
  String8 rest = ext;
  while (rest.size > 0) {
    String8 item = str8_chop_by_delim(&rest, ',');
    String8 name = item;
    U64 semi;
    if (str8_index_of(item, ';', &semi)) name = str8_prefix(item, semi);
    if (str8_match(str8_trim(name), str8_lit("permessage-deflate"))) {
      pmd = item;
      break;
    }
  }
  if (pmd.size == 0) return;
  w->pmd = 1;
  w->client_max_window_bits = 15;
  // Param names are distinct unambiguous tokens within this one extension item.
  if (str8_find(pmd, str8_lit("client_no_context_takeover")) >= 0)
    w->client_no_context_takeover = 1;
  S64 i = str8_find(pmd, str8_lit("client_max_window_bits"));
  if (i >= 0) {
    U64 j = (U64)i + 22;  // past "client_max_window_bits"
    if (j < pmd.size && pmd.str[j] == '=') {
      int n = 0;
      for (++j; j < pmd.size && pmd.str[j] >= '0' && pmd.str[j] <= '9'; ++j)
        n = n * 10 + (pmd.str[j] - '0');
      if (n >= 8 && n <= 15) w->client_max_window_bits = n;
    }
  }
  ws_parser_allow_compression(&w->parser);
#else
  (void)w;
  (void)ext;
#endif
}

#if WS_HAVE_DEFLATE
// Deflate one message into `out` per RFC 7692: raw deflate (no zlib header)
// with Z_SYNC_FLUSH, then drop the trailing 4-byte empty-block marker (00 00 ff
// ff) the flush emits. The stream persists across messages (context takeover)
// unless the server asked for client_no_context_takeover. Returns 0 on a zlib
// error.
internal B32 ws_deflate_message(WsConn *w, const U8 *data, U64 len,
                                U8Buf *out) {
  if (!w->deflate_init) {
    MemoryZeroStruct(&w->deflate_zs);
    if (deflateInit2(&w->deflate_zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     -w->client_max_window_bits, 8, Z_DEFAULT_STRATEGY) != Z_OK)
      return 0;
    w->deflate_init = 1;
  }
  w->deflate_zs.next_in = (Bytef *)data;
  w->deflate_zs.avail_in = (uInt)len;
  U8 buf[16384];
  do {
    w->deflate_zs.next_out = buf;
    w->deflate_zs.avail_out = sizeof buf;
    int rv = deflate(&w->deflate_zs, Z_SYNC_FLUSH);
    if (rv != Z_OK && rv != Z_BUF_ERROR) return 0;
    u8buf_append(out, buf, sizeof buf - w->deflate_zs.avail_out);
  } while (w->deflate_zs.avail_out == 0);
  if (out->len >= 4) out->len -= 4;  // strip the 00 00 ff ff sync marker
  // RFC 7692 7.2.3.6: if stripping left no data (an empty message whose flush
  // was byte-aligned), the payload MUST be a single 0x00 octet so the receiver
  // reconstructs a valid empty block instead of corrupting its inflate stream.
  if (out->len == 0) u8buf_push(out, 0x00);
  if (w->client_no_context_takeover) deflateReset(&w->deflate_zs);
  return 1;
}

// Inflate one received message into `out`: append the stripped marker, raw
// inflate (-15 window decodes any sender window). The stream is PERSISTENT
// across messages — context takeover requires the prior window. Bomb-capped.
internal B32 ws_inflate_message(WsConn *w, const U8 *data, U64 len,
                                U8Buf *out) {
  if (!w->inflate_init) {
    MemoryZeroStruct(&w->inflate_zs);
    if (inflateInit2(&w->inflate_zs, -15) != Z_OK) return 0;
    w->inflate_init = 1;
  }
  static const U8 tail[4] = {0x00, 0x00, 0xff, 0xff};
  const U8 *chunks[2] = {data, tail};
  U64 lens[2] = {len, 4};
  U8 buf[16384];
  for (int c = 0; c < 2; ++c) {
    w->inflate_zs.next_in = (Bytef *)chunks[c];
    w->inflate_zs.avail_in = (uInt)lens[c];
    int rv;
    do {
      w->inflate_zs.next_out = buf;
      w->inflate_zs.avail_out = sizeof buf;
      rv = inflate(&w->inflate_zs, Z_NO_FLUSH);
      if (rv != Z_OK && rv != Z_STREAM_END && rv != Z_BUF_ERROR) return 0;
      u8buf_append(out, buf, sizeof buf - w->inflate_zs.avail_out);
      if (out->len > (64ull << 20)) return 0;  // decompression-bomb cap
      if (rv == Z_BUF_ERROR) break;            // needs the next chunk
    } while (w->inflate_zs.avail_in > 0 || w->inflate_zs.avail_out == 0);
  }
  return 1;
}
#endif  // WS_HAVE_DEFLATE

// --- the RFC 6455 parser's event sink --------------------------------------

internal void ws_on_event(void *user, const WsEvent *ev) {
  WsConn *w = (WsConn *)user;
  if (ev->kind == WsEvent_Ping) {
    ws_conn_send(w, WsOp_Pong, ev->data, ev->len);  // auto-reply (echo payload)
    return;
  }
  if (ev->kind == WsEvent_Pong) return;  // unsolicited pong: ignore

  // The bytes to enqueue: the parser payload, or (permessage-deflate) its
  // inflated form. Inflate into a temp on the WsConn arena, copied into the
  // malloc'd WsMsg before the temp rewinds.
  const U8 *payload = ev->data;
  U64 plen = ev->len;
  Temp dtmp = {0};
  B32 dtmp_open = 0;
#if WS_HAVE_DEFLATE
  if (ev->kind == WsEvent_Message && ev->compressed) {
    dtmp = temp_begin(w->arena);
    dtmp_open = 1;
    U8Buf inf;
    u8buf_init(&inf, w->arena, ev->len ? ev->len * 4 : 64);
    if (!ws_inflate_message(w, ev->data, ev->len, &inf)) {
      temp_end(dtmp);
      w->fail = 1;
      w->err = "permessage-deflate inflate failed";
      ws_wake(w);
      return;
    }
    payload = inf.v;
    plen = inf.len;
  }
#endif

  // Copy off the parser/temp buffer + enqueue, then wake any recv.
  WsMsg *m = (WsMsg *)malloc(sizeof(WsMsg) + plen);
  if (!m) {
    if (dtmp_open) temp_end(dtmp);
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
  m->len = plen;
  if (plen) MemoryCopy(m->data, payload, plen);
  if (dtmp_open) temp_end(dtmp);
  if (w->in_tail)
    w->in_tail->next = m;
  else
    w->in_head = m;
  w->in_tail = m;
  ws_wake(w);
}

// --- HTTP/1.1 Upgrade -------------------------------------------------------

// Build + send the GET upgrade handshake. Serialized directly (not
// h1_session_submit_request, which strips Connection + injects Host). The
// header SET, ORDER, and CASING match a real Chrome 149 WebSocket handshake
// captured over the wire (powhttp): Host, Connection, Pragma, Cache-Control,
// User-Agent, Upgrade, Origin, Sec-WebSocket-Version, Accept-Encoding,
// Accept-Language, Sec-WebSocket-Key, Sec-WebSocket-Extensions. Values (UA /
// Accept-* ) are profile-sourced so they track the emulated browser. Caller
// extras append last.
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
      "\r\nConnection: Upgrade\r\nPragma: no-cache\r\nCache-Control: "
      "no-cache\r\nUser-Agent: ");
  WS_PUT(profile_user_agent(p));
  WS_PUTL("\r\nUpgrade: websocket\r\nOrigin: ");
  WS_PUT(w->origin);
  WS_PUTL("\r\nSec-WebSocket-Version: 13\r\nAccept-Encoding: ");
  WS_PUT(profile_accept_encoding(p));
  WS_PUTL("\r\nAccept-Language: ");
  WS_PUT(profile_accept_language(p));
  WS_PUTL("\r\nSec-WebSocket-Key: ");
  WS_PUT(key);
  if (WS_HAVE_DEFLATE)
    WS_PUTL(
        "\r\nSec-WebSocket-Extensions: permessage-deflate; "
        "client_max_window_bits");
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
  // Verify Sec-WebSocket-Accept; note any negotiated permessage-deflate.
  String8 accept = str8_zero(), ext = str8_zero();
  for (size_t i = 0; i < nhdr; ++i) {
    String8 n = str8((U8 *)hdrs[i].name, hdrs[i].name_len);
    String8 v = str8((U8 *)hdrs[i].value, hdrs[i].value_len);
    if (str8_match_ci(n, str8_lit("sec-websocket-accept")))
      accept = v;
    else if (str8_match_ci(n, str8_lit("sec-websocket-extensions")))
      ext = v;
  }
  if (!str8_match(accept, w->accept_expected)) {
    w->fail = 1;
    w->err = "bad Sec-WebSocket-Accept";
    ws_wake(w);
    return;
  }
  ws_pmd_negotiate(w, ext);
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
internal void ws_h2_on_connect(void *user, int status, String8 extensions) {
  WsConn *w = (WsConn *)user;
  if (status == 200) {
    ws_pmd_negotiate(w, extensions);
    w->established = 1;
  } else {
    w->fail = 1;
    w->err = "h2 websocket rejected (status != 200)";
  }
  ws_wake(w);
}

// Inbound CONNECT-stream DATA = WS frame bytes (or a (0,0) EOF on stream
// close).
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
// handshake); Sec-WebSocket-Version + UA + caller extras ride as regular
// fields.
internal void ws_h2_submit(WsConn *w) {
  w->h2_submitted = 1;
  const Profile *p = w->client->profile;
  U64 nh = 2 + (WS_HAVE_DEFLATE ? 1 : 0) + w->hs_extra_count;
  Header *hs = push_array(w->arena, Header, nh);
  U64 k = 0;
  hs[k++] = (Header){str8_lit("sec-websocket-version"), str8_lit("13"), 0};
  hs[k++] = (Header){str8_lit("user-agent"), profile_user_agent(p), 0};
  if (WS_HAVE_DEFLATE)
    hs[k++] =
        (Header){str8_lit("sec-websocket-extensions"),
                 str8_lit("permessage-deflate; client_max_window_bits"), 0};
  for (U64 i = 0; i < w->hs_extra_count; ++i) hs[k++] = w->hs_extra[i];
  w->h2_stream = h2_session_ws_connect(w->h2, str8_lit("https"), w->authority,
                                       w->path, str8_lit("websocket"), hs, nh,
                                       ws_h2_on_connect, w, ws_h2_on_data, w);
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
    if (!h2_session_start(
            w->h2)) {  // emit our preface (SETTINGS + WINDOW_UPDATE)
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

internal void ws_on_recv_timeout(void *user) {
  WsConn *w = (WsConn *)user;
  w->recv_timed_out = 1;
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

  // Transport / ALPN selection. WebSocket over h2 (RFC 8441 Extended CONNECT)
  // is rare — most servers (even h2-capable ones) only do the HTTP/1.1 Upgrade
  // — so the DEFAULT offers http/1.1 only, like a fresh browser WebSocket, and
  // the H2 path is opt-in via http_version=H2. This http/1.1 ALPN + dropped
  // ALPS yields a ClientHello byte-exact with real Chrome's WS hello (JA4
  // t13d1515h1_8daaf6152771_0a20fe35d3a5; verified offline in ja4_test).
  const TlsProfile *tls;
  if (w->client->http_version == HttpVersion_H2) {
    tls =
        &w->client->profile->tls;  // normal h2,http/1.1 ALPN -> server picks h2
  } else {
    w->ws_h1_tls = w->client->profile->tls;
    w->ws_h1_tls.alpn_wire = g_ws_alpn_h11;
    w->ws_h1_tls.alpn_wire_len = (U16)sizeof g_ws_alpn_h11;
    w->ws_h1_tls.alps_count = 0;  // ALPS is h2-only
    tls = &w->ws_h1_tls;
  }
  conn_init(&w->conn, w->client->loop, w->client->ctx.ctx, tls);
  w->conn_inited = 1;
  conn_on_closed(&w->conn, ws_on_closed, w);
  conn_on_fully_closed(&w->conn, ws_on_fully_closed, w);
  conn_set_dns_cache(&w->conn, &w->client->dns_cache);

  U64 t = client_get_timeout_ms(w->client);
  w->connect_timer = req_timer_arm(
      w->loop, t ? uv_hrtime() + t * 1000000ull : 0, ws_on_connect_timeout, w);
  conn_connect(&w->conn, push_str8_cstr(w->arena, pu.host), w->port,
               ws_on_ready, w);
  while (!w->established && !w->fail && !w->closed) loop_run(w->loop);
  req_timer_disarm(w->connect_timer);
  w->connect_timer = 0;
  if (!w->established && !w->err) w->err = "websocket connect failed";
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
  B32 rsv1 = 0;
#if WS_HAVE_DEFLATE
  // permessage-deflate: compress data messages (never control frames) and set
  // RSV1 on the (single) frame. Deflate into a temp buffer on the same arena.
  if (w->pmd && (op == WsOp_Text || op == WsOp_Binary)) {
    U8Buf comp;
    u8buf_init(&comp, w->arena, len ? len : 16);
    if (ws_deflate_message(w, data, len, &comp)) {
      data = comp.v;
      len = comp.len;
      rsv1 = 1;
    } else {
      temp_end(t);
      w->fail = 1;
      w->err = "permessage-deflate deflate failed";
      return 0;
    }
  }
#endif
  U8Buf f;
  u8buf_init(&f, w->arena, len + 16);
  ws_frame_build(&f, op, 1, rsv1, data, len, mask);
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

int ws_conn_recv(WsConn *w, WsEvent *out, U64 timeout_ms) {
  if (w->cur_msg) {  // free the message handed out by the previous recv
    free(w->cur_msg);
    w->cur_msg = 0;
  }
  w->recv_timed_out = 0;
  ReqTimer *t =
      timeout_ms ? req_timer_arm(w->loop, uv_hrtime() + timeout_ms * 1000000ull,
                                 ws_on_recv_timeout, w)
                 : 0;
  int rc;
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
        rc = 0;
      } else {
        out->kind = WsEvent_Message;
        rc = 1;
      }
      break;
    }
    if (w->fail || w->closed) {
      rc = -1;
      break;
    }
    if (w->recv_timed_out) {
      rc = -2;  // deadline elapsed; the connection is still usable
      break;
    }
    loop_run(w->loop);  // blocks until an event / close / the deadline wakes us
  }
  req_timer_disarm(t);
  return rc;
}

void ws_conn_close(WsConn *w, U16 code, String8 reason) {
  if (w->established && !w->closed && !w->fail) {
    U8 payload[125];
    U64 plen = 0;
    payload[plen++] = (U8)(code >> 8);
    payload[plen++] = (U8)code;
    U64 rn =
        reason.size < sizeof payload - 2 ? reason.size : sizeof payload - 2;
    if (rn) MemoryCopy(payload + 2, reason.str, rn);
    plen += rn;
    ws_conn_send(w, WsOp_Close, payload, plen);
    // Run the loop to actually flush the Close (egress writes are async, so an
    // immediate conn_close would cancel it) and complete the RFC 6455 close
    // handshake by awaiting the peer's Close — bounded so a silent peer can't
    // hang teardown.
    w->close_timed_out = 0;
    ReqTimer *t = req_timer_arm(w->loop, uv_hrtime() + 2000000000ull /*2s*/,
                                ws_on_close_timeout, w);
    while (!w->got_peer_close && !w->closed && !w->fail && !w->close_timed_out)
      loop_run(w->loop);
    req_timer_disarm(t);
    // H2: half-close the CONNECT stream (END_STREAM) now that the WS Close is
    // done.
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
#if WS_HAVE_DEFLATE
  if (w->deflate_init) deflateEnd(&w->deflate_zs);
  if (w->inflate_init) inflateEnd(&w->inflate_zs);
#endif
  arena_release(w->arena);
}

WsTransport ws_conn_transport(WsConn *w) { return w->transport; }
const char *ws_conn_error(WsConn *w) { return w->err; }
