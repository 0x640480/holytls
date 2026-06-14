#include "support/loopback_server.h"

#include <nghttp2/nghttp2.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

//- shared low-level helpers -------------------------------------------------

typedef struct LbWrite {
  uv_write_t req;
  uv_buf_t buf;
} LbWrite;
static void lb_on_wr(uv_write_t *r, int st) {
  (void)st;
  free(r);
}
void lb_raw_write(uv_tcp_t *t, const U8 *d, U64 n) {
  if (n == 0 || uv_is_closing((uv_handle_t *)t)) return;
  LbWrite *w = (LbWrite *)malloc(sizeof(LbWrite) + n);
  U8 *p = (U8 *)(w + 1);
  MemoryCopy(p, d, n);
  w->buf = uv_buf_init((char *)p, (unsigned)n);
  uv_write(&w->req, (uv_stream_t *)t, &w->buf, 1, lb_on_wr);
}
void lb_alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *b) {
  (void)h;
  (void)suggested;
  static thread_local U8 storage[65536];
  b->base = (char *)storage;
  b->len = sizeof storage;
}
U16 lb_listen(EventLoop *loop, uv_tcp_t *srv, uv_connection_cb cb, void *data) {
  uv_tcp_init(loop_uv(loop), srv);
  srv->data = data;
  struct sockaddr_in a;
  uv_ip4_addr("127.0.0.1", 0, &a);
  uv_tcp_bind(srv, (const struct sockaddr *)&a, 0);
  uv_listen((uv_stream_t *)srv, 16, cb);
  struct sockaddr_storage ss;
  int sl = sizeof ss;
  uv_tcp_getsockname(srv, (struct sockaddr *)&ss, &sl);
  return ntohs(((struct sockaddr_in *)&ss)->sin_port);
}

static int lb_alpn_cb(SSL *ssl, const U8 **out, U8 *outlen, const U8 *in,
                      unsigned inlen, void *arg) {
  (void)ssl;
  LbAlpn mode = (LbAlpn)(uintptr_t)arg;
  static const U8 h2[] = {'h', '2'};
  static const U8 h1[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
  if (mode == LB_ALPN_H1) {
    *out = h1;
    *outlen = 8;
    return SSL_TLSEXT_ERR_OK;
  }
  if (mode == LB_ALPN_BOTH) {  // prefer h2 if the client offered it
    for (unsigned i = 0; i < inlen;) {
      unsigned l = in[i];
      if (i + 1 + l <= inlen && l == 2 && memcmp(in + i + 1, "h2", 2) == 0)
        break;  // found -> fall through to the h2 answer below
      i += 1 + l;
    }
  }
  *out = h2;
  *outlen = 2;
  return SSL_TLSEXT_ERR_OK;
}

SSL_CTX *lb_server_ctx(LbAlpn alpn) {
  EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0);
  EVP_PKEY *pk = 0;
  if (!pc || EVP_PKEY_keygen_init(pc) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pc, NID_X9_62_prime256v1) <= 0 ||
      EVP_PKEY_keygen(pc, &pk) <= 0) {
    if (pc) EVP_PKEY_CTX_free(pc);
    return 0;
  }
  EVP_PKEY_CTX_free(pc);
  X509 *x = X509_new();
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), 0);
  X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
  X509_set_pubkey(x, pk);
  X509_NAME *nm = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                             (const unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(x, nm);
  X509_sign(x, pk, EVP_sha256());
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_use_certificate(ctx, x);
  SSL_CTX_use_PrivateKey(ctx, pk);
  SSL_CTX_set_alpn_select_cb(ctx, lb_alpn_cb, (void *)(uintptr_t)alpn);
  X509_free(x);
  EVP_PKEY_free(pk);
  return ctx;
}

//- server / connection / stream state ---------------------------------------

typedef struct LbStream {
  S32 stream_id;
  char method[16];
  U64 method_len;
  char path[512];
  U64 path_len;
  char authority[256];
  U64 authority_len;
  U8 *body;
  U64 body_len, body_cap;
  U8 *resp_body;  // copied at submit time; drained by the data provider
  U64 resp_len, resp_off;
  B32 stall;  // send the body but never EOF (hold the stream open) — for
              // exercising a client that aborts mid-stream
  // RFC 8441 Extended CONNECT (WS echo mode):
  char protocol[32];   // ":protocol" (e.g. "websocket")
  U64 protocol_len;
  B32 is_ws;           // a CONNECT + :protocol stream
  B32 ws_responded;    // 200 sent, deferred echo provider installed
  U8 *win;             // inbound client (masked) frame accumulator
  U64 win_len, win_cap;
  U8 *wout;            // re-framed server (unmasked) bytes; the provider drains
  U64 wout_len, wout_off, wout_cap;
  struct LbStream *next;  // per-connection list (freed on close incl. withheld)
} LbStream;

typedef struct LbConn LbConn;
struct LbConn {
  uv_tcp_t tcp;
  SSL *ssl;
  BIO *rb, *wb;
  nghttp2_session *h2;
  B32 is_h2, inited, closing;
  LbServer *server;
  LbStream
      *streams;  // live request streams (so withheld ones are freed on close)
  U8 *h1buf;     // HTTP/1.1 request accumulator
  U64 h1len, h1cap;
  uv_shutdown_t
      hsr;  // H1: flush queued writes before closing (Connection: close)
  LbConn *next;
};

struct LbServer {
  uv_tcp_t listener;
  SSL_CTX *ctx;
  LbAlpn alpn;
  LbHandler handler;
  void *user;
  B32 ws_echo;  // RFC 8441 Extended CONNECT echo origin (lb_ws_echo_start)
  LbConn *conns;
};

//- connection lifecycle -----------------------------------------------------

static void lb_conn_on_closed(uv_handle_t *h) {
  LbConn *c = (LbConn *)h->data;
  while (c->streams) {  // any stream still open (e.g. a withheld request)
    LbStream *st = c->streams;
    c->streams = st->next;
    free(st->body);
    free(st->resp_body);
    free(st->win);
    free(st->wout);
    free(st);
  }
  if (c->h2) nghttp2_session_del(c->h2);
  if (c->ssl) SSL_free(c->ssl);  // frees the attached BIOs
  free(c->h1buf);
  free(c);
}
static void lb_conn_close(LbConn *c) {
  if (c->closing) return;
  c->closing = 1;
  for (LbConn **pp = &c->server->conns; *pp; pp = &(*pp)->next)
    if (*pp == c) {
      *pp = c->next;
      break;
    }
  uv_close((uv_handle_t *)&c->tcp, lb_conn_on_closed);
}
static void lb_conn_flush(LbConn *c) {
  U8 b[16384];
  int n;
  while ((n = BIO_read(c->wb, b, (int)sizeof b)) > 0)
    lb_raw_write(&c->tcp, b, (U64)n);
}

//- HTTP/2 server ------------------------------------------------------------

static nghttp2_ssize lb_h2_send(nghttp2_session *s, const U8 *data, size_t len,
                                int flags, void *user) {
  (void)s;
  (void)flags;
  LbConn *c = (LbConn *)user;
  SSL_write(c->ssl, data, len);
  return (nghttp2_ssize)len;
}
static void lb_copy(char *dst, U64 cap, const U8 *src, size_t n) {
  U64 k = n < cap - 1 ? n : cap - 1;
  MemoryCopy(dst, src, k);
  dst[k] = 0;
}
static int lb_h2_begin_headers(nghttp2_session *s, const nghttp2_frame *frame,
                               void *user) {
  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    return 0;
  LbConn *c = (LbConn *)user;
  LbStream *st = (LbStream *)calloc(1, sizeof(LbStream));
  st->stream_id = frame->hd.stream_id;
  st->next = c->streams;
  c->streams = st;
  nghttp2_session_set_stream_user_data(s, frame->hd.stream_id, st);
  return 0;
}
static int lb_h2_header(nghttp2_session *s, const nghttp2_frame *frame,
                        const U8 *name, size_t namelen, const U8 *value,
                        size_t valuelen, U8 flags, void *user) {
  (void)flags;
  (void)user;
  LbStream *st =
      (LbStream *)nghttp2_session_get_stream_user_data(s, frame->hd.stream_id);
  if (!st) return 0;
  String8 n = str8((U8 *)name, namelen);
  if (str8_match(n, str8_lit(":method"))) {
    lb_copy(st->method, sizeof st->method, value, valuelen);
    st->method_len = strlen(st->method);
  } else if (str8_match(n, str8_lit(":path"))) {
    lb_copy(st->path, sizeof st->path, value, valuelen);
    st->path_len = strlen(st->path);
  } else if (str8_match(n, str8_lit(":authority"))) {
    lb_copy(st->authority, sizeof st->authority, value, valuelen);
    st->authority_len = strlen(st->authority);
  } else if (str8_match(n, str8_lit(":protocol"))) {
    lb_copy(st->protocol, sizeof st->protocol, value, valuelen);
    st->protocol_len = strlen(st->protocol);
  }
  return 0;
}
// Deferred provider for a WS CONNECT stream: emit re-framed (unmasked) server
// frames from wout; no EOF so the stream stays open; defer when empty (resumed
// by lb_h2_data on the next DATA frame).
static nghttp2_ssize lb_ws_echo_read(nghttp2_session *s, S32 sid, U8 *buf,
                                     size_t length, U32 *data_flags,
                                     nghttp2_data_source *source, void *user) {
  (void)s;
  (void)sid;
  (void)data_flags;
  (void)user;
  LbStream *st = (LbStream *)source->ptr;
  U64 remain = st->wout_len - st->wout_off;
  if (remain == 0) return NGHTTP2_ERR_DEFERRED;  // nothing to echo yet
  U64 n = remain < length ? remain : length;
  MemoryCopy(buf, st->wout + st->wout_off, n);
  st->wout_off += n;
  if (st->wout_off == st->wout_len) st->wout_len = st->wout_off = 0;  // drained
  return (nghttp2_ssize)n;  // no EOF: the WS stream stays open
}
static void lb_wout_append(LbStream *st, const U8 *d, U64 n) {
  if (st->wout_off) {  // compact the already-sent prefix
    MemoryMove(st->wout, st->wout + st->wout_off, st->wout_len - st->wout_off);
    st->wout_len -= st->wout_off;
    st->wout_off = 0;
  }
  if (st->wout_len + n > st->wout_cap) {
    U64 ncap = st->wout_cap ? st->wout_cap : 65536;
    while (ncap < st->wout_len + n) ncap *= 2;
    st->wout = (U8 *)realloc(st->wout, ncap);
    st->wout_cap = ncap;
  }
  MemoryCopy(st->wout + st->wout_len, d, n);
  st->wout_len += n;
}
// Parse complete client (masked) frames out of win and re-emit each as an
// UNMASKED server frame into wout (a client MUST mask, a server MUST NOT — so a
// byte echo would bounce back masked frames the client rejects). A leftover
// partial frame stays buffered in win. The echoed frame keeps the opcode + FIN.
static void lb_ws_reframe(LbStream *st) {
  U64 i = 0;
  for (;;) {
    if (st->win_len - i < 2) break;
    U8 b0 = st->win[i], b1 = st->win[i + 1];
    B32 masked = (b1 & 0x80) != 0;
    U64 plen = b1 & 0x7f;
    U64 hdr = 2;
    if (plen == 126) {
      if (st->win_len - i < 4) break;
      plen = ((U64)st->win[i + 2] << 8) | st->win[i + 3];
      hdr = 4;
    } else if (plen == 127) {
      if (st->win_len - i < 10) break;
      plen = 0;
      for (int k = 0; k < 8; ++k) plen = (plen << 8) | st->win[i + 2 + k];
      hdr = 10;
    }
    U64 mklen = masked ? 4 : 0;
    if (st->win_len - i < hdr + mklen + plen) break;  // incomplete frame
    const U8 *mk = st->win + i + hdr;
    const U8 *pl = st->win + i + hdr + mklen;
    // Server frame header: same b0 (FIN+opcode), no MASK bit.
    U8 sh[10];
    U64 shl = 0;
    sh[shl++] = b0;
    if (plen < 126)
      sh[shl++] = (U8)plen;
    else if (plen <= 0xffff) {
      sh[shl++] = 126;
      sh[shl++] = (U8)(plen >> 8);
      sh[shl++] = (U8)plen;
    } else {
      sh[shl++] = 127;
      for (int k = 7; k >= 0; --k) sh[shl++] = (U8)(plen >> (k * 8));
    }
    lb_wout_append(st, sh, shl);
    // Unmask the payload into wout.
    for (U64 j = 0; j < plen; ++j) {
      U8 byte = masked ? (U8)(pl[j] ^ mk[j & 3]) : pl[j];
      lb_wout_append(st, &byte, 1);
    }
    i += hdr + mklen + plen;
  }
  if (i) {  // drop consumed bytes, keep the partial tail
    MemoryMove(st->win, st->win + i, st->win_len - i);
    st->win_len -= i;
  }
}
static int lb_h2_data(nghttp2_session *s, U8 flags, S32 sid, const U8 *data,
                      size_t len, void *user) {
  (void)flags;
  (void)user;
  LbStream *st = (LbStream *)nghttp2_session_get_stream_user_data(s, sid);
  if (!st || !len) return 0;
  if (st->is_ws) {  // accumulate client frames, re-frame them back unmasked
    if (st->win_len + len > st->win_cap) {
      U64 ncap = st->win_cap ? st->win_cap : 65536;
      while (ncap < st->win_len + len) ncap *= 2;
      st->win = (U8 *)realloc(st->win, ncap);
      st->win_cap = ncap;
    }
    MemoryCopy(st->win + st->win_len, data, len);
    st->win_len += len;
    lb_ws_reframe(st);
    nghttp2_session_resume_data(s, sid);  // un-defer the echo provider
    return 0;
  }
  if (st->body_len + len > st->body_cap) {
    U64 ncap = st->body_cap ? st->body_cap : 65536;
    while (ncap < st->body_len + len) ncap *= 2;
    st->body = (U8 *)realloc(st->body, ncap);
    st->body_cap = ncap;
  }
  MemoryCopy(st->body + st->body_len, data, len);
  st->body_len += len;
  return 0;
}
static nghttp2_ssize lb_h2_body_read(nghttp2_session *s, S32 sid, U8 *buf,
                                     size_t length, U32 *data_flags,
                                     nghttp2_data_source *source, void *user) {
  (void)s;
  (void)sid;
  (void)user;
  LbStream *st = (LbStream *)source->ptr;
  U64 remain = st->resp_len - st->resp_off;
  // Stall: once the whole body is sent, hold the stream open (never EOF) so the
  // client gets the full body but no fin — it must abort (timeout) to finish.
  if (remain == 0 && st->stall) return NGHTTP2_ERR_DEFERRED;
  U64 n = remain < length ? remain : length;
  if (n) MemoryCopy(buf, st->resp_body + st->resp_off, n);
  st->resp_off += n;
  if (st->resp_off >= st->resp_len && !st->stall)
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  return (nghttp2_ssize)n;
}
static int lb_h2_frame_recv(nghttp2_session *s, const nghttp2_frame *frame,
                            void *user) {
  LbConn *c = (LbConn *)user;
  LbStream *st =
      (LbStream *)nghttp2_session_get_stream_user_data(s, frame->hd.stream_id);

  // RFC 8441 Extended CONNECT: a `:method=CONNECT` + `:protocol` HEADERS opens a
  // bidirectional stream (no END_STREAM on the request). Reply 200 and install a
  // deferred echo provider; the stream then stays open for DATA both ways.
  if (c->server->ws_echo && st && !st->ws_responded &&
      frame->hd.type == NGHTTP2_HEADERS && st->protocol_len > 0 &&
      str8_match(str8((U8 *)st->method, st->method_len), str8_lit("CONNECT"))) {
    st->is_ws = 1;
    st->ws_responded = 1;
    nghttp2_nv nv[1] = {
        {(U8 *)":status", (U8 *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE}};
    nghttp2_data_provider2 prd;
    prd.source.ptr = st;
    prd.read_callback = lb_ws_echo_read;
    nghttp2_submit_response2(c->h2, st->stream_id, nv, 1, &prd);
    return 0;
  }

  if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) return 0;
  if (!st) return 0;
  if (!c->server->handler) return 0;  // WS-echo origin: no plain-request handler

  LbRequest req;
  MemoryZeroStruct(&req);
  req.method = str8((U8 *)st->method, st->method_len);
  req.path = str8((U8 *)st->path, st->path_len);
  req.authority = str8((U8 *)st->authority, st->authority_len);
  req.body = st->body;
  req.body_len = st->body_len;
  req.is_h2 = 1;
  LbResponse resp;
  MemoryZeroStruct(&resp);
  c->server->handler(&req, &resp, c->server->user);
  if (resp.withhold) return 0;  // send nothing; keep the stream + conn open
  if (resp.status == 0) resp.status = 200;

  char status_str[8];
  snprintf(status_str, sizeof status_str, "%d", resp.status);
  nghttp2_nv nv[1 + 8];
  size_t nvn = 0;
  nv[nvn++] = (nghttp2_nv){(U8 *)":status", (U8 *)status_str, 7,
                           strlen(status_str), NGHTTP2_NV_FLAG_NONE};
  for (U64 i = 0; i < resp.extra_count && i < 8; ++i)
    nv[nvn++] =
        (nghttp2_nv){(U8 *)resp.extra_names[i], (U8 *)resp.extra_values[i],
                     strlen(resp.extra_names[i]), strlen(resp.extra_values[i]),
                     NGHTTP2_NV_FLAG_NONE};

  B32 head = str8_match(req.method, str8_lit("HEAD"));
  if (resp.body_len && !head) {
    st->resp_body = (U8 *)malloc(resp.body_len);
    MemoryCopy(st->resp_body, resp.body, resp.body_len);
    st->resp_len = resp.body_len;
    st->resp_off = 0;
    st->stall = resp.stall;
    nghttp2_data_provider2 prd;
    prd.source.ptr = st;
    prd.read_callback = lb_h2_body_read;
    nghttp2_submit_response2(c->h2, st->stream_id, nv, nvn, &prd);
  } else {
    nghttp2_submit_response2(c->h2, st->stream_id, nv, nvn, 0);
  }
  return 0;
}
static int lb_h2_stream_close(nghttp2_session *s, S32 sid, U32 ec, void *user) {
  (void)ec;
  LbConn *c = (LbConn *)user;
  LbStream *st = (LbStream *)nghttp2_session_get_stream_user_data(s, sid);
  if (st) {
    for (LbStream **pp = &c->streams; *pp; pp = &(*pp)->next)
      if (*pp == st) {
        *pp = st->next;
        break;
      }
    free(st->body);
    free(st->resp_body);
    free(st->win);
    free(st->wout);
    free(st);
    nghttp2_session_set_stream_user_data(s, sid, 0);
  }
  return 0;
}
static void lb_h2_init(LbConn *c) {
  nghttp2_session_callbacks *cbs = 0;
  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_send_callback2(cbs, lb_h2_send);
  nghttp2_session_callbacks_set_on_begin_headers_callback(cbs,
                                                          lb_h2_begin_headers);
  nghttp2_session_callbacks_set_on_header_callback(cbs, lb_h2_header);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, lb_h2_data);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, lb_h2_frame_recv);
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs,
                                                         lb_h2_stream_close);
  nghttp2_session_server_new(&c->h2, cbs, c);
  nghttp2_session_callbacks_del(cbs);
  nghttp2_settings_entry iv[2] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  size_t niv = 1;
  if (c->server->ws_echo)  // RFC 8441: allow Extended CONNECT (:protocol)
    iv[niv++] = (nghttp2_settings_entry){
        NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1};
  nghttp2_submit_settings(c->h2, NGHTTP2_FLAG_NONE, iv, niv);
}

//- HTTP/1.1 server ----------------------------------------------------------

static U64 lb_h1_content_length(const U8 *hdr, U64 n) {
  // case-insensitive "content-length:" scan within the header block.
  for (U64 i = 0; i + 15 < n; ++i)
    if (strncasecmp((const char *)hdr + i, "content-length:", 15) == 0)
      return (U64)strtoull((const char *)hdr + i + 15, 0, 10);
  return 0;
}
static void lb_h1_on_shutdown(uv_shutdown_t *req, int status) {
  (void)status;  // queued writes are now flushed (or cancelled) -> close
  lb_conn_close((LbConn *)req->data);
}
static void lb_h1_feed(LbConn *c, const U8 *data, U64 len) {
  if (c->h1len + len > c->h1cap) {
    U64 ncap = c->h1cap ? c->h1cap : 8192;
    while (ncap < c->h1len + len) ncap *= 2;
    c->h1buf = (U8 *)realloc(c->h1buf, ncap);
    c->h1cap = ncap;
  }
  MemoryCopy(c->h1buf + c->h1len, data, len);
  c->h1len += len;

  String8 acc = str8(c->h1buf, c->h1len);
  S64 pos = str8_find(acc, str8_lit("\r\n\r\n"));
  if (pos < 0) return;  // headers incomplete
  U64 hdr_end = (U64)pos + 4;
  U64 clen = lb_h1_content_length(c->h1buf, hdr_end);
  if (c->h1len < hdr_end + clen) return;  // body incomplete

  // Parse the request line: "METHOD SP path SP HTTP/1.1".
  String8 line = str8(c->h1buf, (U64)pos);
  String8 rest = line;
  String8 method = str8_chop_by_delim(&rest, ' ');
  String8 path = str8_chop_by_delim(&rest, ' ');

  LbRequest req;
  MemoryZeroStruct(&req);
  req.method = method;
  req.path = path;
  req.body = c->h1buf + hdr_end;
  req.body_len = clen;
  req.is_h2 = 0;
  LbResponse resp;
  MemoryZeroStruct(&resp);
  c->server->handler(&req, &resp, c->server->user);
  if (resp.withhold) return;
  if (resp.status == 0) resp.status = 200;

  char head[1024];
  int hn = snprintf(head, sizeof head, "HTTP/1.1 %d OK\r\n", resp.status);
  for (U64 i = 0; i < resp.extra_count && i < 8; ++i)
    hn += snprintf(head + hn, sizeof head - (size_t)hn, "%s: %s\r\n",
                   resp.extra_names[i], resp.extra_values[i]);
  hn += snprintf(head + hn, sizeof head - (size_t)hn,
                 "Content-Length: %llu\r\nConnection: close\r\n\r\n",
                 (unsigned long long)resp.body_len);
  SSL_write(c->ssl, head, hn);
  if (resp.body_len) SSL_write(c->ssl, resp.body, (int)resp.body_len);
  lb_conn_flush(c);
  // Connection: close, but flush the (possibly multi-MB) queued writes first —
  // uv_close would cancel them. uv_shutdown drains then half-closes; we close
  // in its callback.
  c->hsr.data = c;
  if (uv_shutdown(&c->hsr, (uv_stream_t *)&c->tcp, lb_h1_on_shutdown) != 0)
    lb_conn_close(c);
}

//- drive loop + accept ------------------------------------------------------

static void lb_conn_drive(LbConn *c) {
  if (c->closing) return;
  if (!SSL_is_init_finished(c->ssl)) {
    int r = SSL_do_handshake(c->ssl);
    lb_conn_flush(c);
    if (r != 1) {
      int e = SSL_get_error(c->ssl, r);
      if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
        lb_conn_close(c);
      return;
    }
  }
  if (!c->inited) {
    const U8 *ap = 0;
    unsigned al = 0;
    SSL_get0_alpn_selected(c->ssl, &ap, &al);
    c->is_h2 = (al == 2 && memcmp(ap, "h2", 2) == 0);
    if (c->is_h2) lb_h2_init(c);
    c->inited = 1;
  }
  U8 b[16384];
  int n;
  while ((n = SSL_read(c->ssl, b, (int)sizeof b)) > 0) {
    if (c->is_h2) {
      if (nghttp2_session_mem_recv2(c->h2, b, (size_t)n) < 0) {
        lb_conn_close(c);
        return;
      }
    } else {
      lb_h1_feed(c, b, (U64)n);
      if (c->closing) return;
    }
  }
  if (c->is_h2 && c->h2) nghttp2_session_send(c->h2);
  lb_conn_flush(c);
}
static void lb_conn_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
  LbConn *c = (LbConn *)s->data;
  if (c->closing) return;
  if (nread < 0) {
    lb_conn_close(c);
    return;
  }
  if (nread > 0) BIO_write(c->rb, buf->base, (int)nread);
  lb_conn_drive(c);
}
static void lb_on_conn(uv_stream_t *srv, int status) {
  if (status < 0) return;
  LbServer *server = (LbServer *)srv->data;
  LbConn *c = (LbConn *)calloc(1, sizeof(LbConn));
  c->server = server;
  uv_tcp_init(srv->loop, &c->tcp);
  c->tcp.data = c;
  if (uv_accept(srv, (uv_stream_t *)&c->tcp) != 0) {
    lb_conn_close(c);
    return;
  }
  c->ssl = SSL_new(server->ctx);
  c->rb = BIO_new(BIO_s_mem());
  c->wb = BIO_new(BIO_s_mem());
  SSL_set_bio(c->ssl, c->rb, c->wb);
  SSL_set_accept_state(c->ssl);
  c->next = server->conns;
  server->conns = c;
  uv_read_start((uv_stream_t *)&c->tcp, lb_alloc_cb, lb_conn_read);
}

//- public lifecycle ---------------------------------------------------------

LbServer *lb_server_start(EventLoop *loop, LbAlpn alpn, LbHandler handler,
                          void *user, U16 *out_port) {
  LbServer *s = (LbServer *)calloc(1, sizeof(LbServer));
  s->ctx = lb_server_ctx(alpn);
  s->alpn = alpn;
  s->handler = handler;
  s->user = user;
  U16 port = lb_listen(loop, &s->listener, lb_on_conn, s);
  if (out_port) *out_port = port;
  return s;
}
LbServer *lb_ws_echo_start(EventLoop *loop, U16 *out_port) {
  LbServer *s = (LbServer *)calloc(1, sizeof(LbServer));
  s->ctx = lb_server_ctx(LB_ALPN_H2);
  s->alpn = LB_ALPN_H2;
  s->ws_echo = 1;  // handler stays 0: this origin only serves WS Extended CONNECT
  U16 port = lb_listen(loop, &s->listener, lb_on_conn, s);
  if (out_port) *out_port = port;
  return s;
}
static void lb_on_listener_closed(uv_handle_t *h) {
  LbServer *s = (LbServer *)h->data;
  if (s->ctx) SSL_CTX_free(s->ctx);  // refcounted; survives any still-live SSLs
  free(s);
}
void lb_server_stop(LbServer *s) {
  if (!s) return;
  while (s->conns)
    lb_conn_close(s->conns);  // each unlinks itself from the list
  uv_close((uv_handle_t *)&s->listener, lb_on_listener_closed);
}
