#include "h1/h1.h"

#include <picohttpparser.h>

#include "base/u8buf.h"

#define H1_MAX_HEADERS 128
#define H1_MAX_HEADER_REGION KB(64)

typedef enum H1State {
  H1State_Headers,      // accumulating + parsing until \r\n\r\n
  H1State_BodyLength,   // Content-Length: N
  H1State_BodyChunked,  // Transfer-Encoding: chunked
  H1State_BodyClose,    // read until EOF
  H1State_Done,         // response delivered
  H1State_Error,
} H1State;

struct H1Session {
  Arena *arena;
  H1SendFn send_fn;
  void *send_user;

  H1RespFn cb;
  void *user;
  B32 is_head;

  H1State state;
  U8Buf in;        // raw received bytes; the header region is parsed from here
  U64 parsed_off;  // picohttpparser last_len (\r\n\r\n scan optimization)
  U64 header_end;  // byte offset just past the end-of-headers in `in`

  int status;
  U32 http_minor;  // status-line HTTP minor version (1 => keep-alive default)
  HeaderList headers;  // arena-owned copies (stable across buffer growth)
  U64 content_length;

  U8Buf body;  // assembled body (raw for length/close; decoded for chunked)
  struct phr_chunked_decoder chunk_dec;

  B32 delivered;
};

//- lifetime

H1Session *h1_session_alloc(H1SendFn send_fn, void *send_user) {
  Arena *arena = arena_alloc();
  H1Session *s = push_struct(arena, H1Session);
  s->arena = arena;
  s->send_fn = send_fn;
  s->send_user = send_user;
  s->state = H1State_Headers;
  header_list_init(&s->headers, arena);
  u8buf_init(&s->in, arena, KB(16));
  u8buf_init(&s->body, arena, 0);
  return s;
}

void h1_session_release(H1Session *s) {
  if (s) arena_release(s->arena);
}

//- request serialization

internal void h1_put(U8Buf *b, String8 s) { u8buf_append(b, s.str, s.size); }
#define H1_LIT(b, lit) u8buf_append((b), (const U8 *)(lit), sizeof(lit) - 1)

S32 h1_session_submit_request(H1Session *s, String8 method, String8 authority,
                              String8 path, const Header *headers,
                              U64 header_count, const U8 *body, U64 body_len,
                              B32 is_head, H1RespFn cb, void *user) {
  s->cb = cb;
  s->user = user;
  s->is_head = is_head;

  Temp scr = scratch_begin(&s->arena, 1);
  U8Buf out;
  u8buf_init(&out, scr.arena, 512 + body_len);
  // Request line.
  h1_put(&out, method);
  u8buf_push(&out, ' ');
  h1_put(&out, path);
  H1_LIT(&out, " HTTP/1.1\r\n");
  // Host first.
  H1_LIT(&out, "Host: ");
  h1_put(&out, authority);
  H1_LIT(&out, "\r\n");
  // Headers verbatim (wire-cased + ordered by the caller). Drop any caller-
  // supplied Host (we inject it above) or Connection (omitted = HTTP/1.1
  // keep-alive default, matching Chrome) so neither is duplicated/contradicted.
  for (U64 i = 0; i < header_count; ++i) {
    if (str8_match_ci(headers[i].name, str8_lit("host")) ||
        str8_match_ci(headers[i].name, str8_lit("connection")))
      continue;
    h1_put(&out, headers[i].name);
    H1_LIT(&out, ": ");
    h1_put(&out, headers[i].value);
    H1_LIT(&out, "\r\n");
  }
  H1_LIT(&out, "\r\n");
  if (body_len) u8buf_append(&out, body, body_len);

  s->send_fn(s->send_user, out.v, out.len);
  scratch_end(scr);
  return 0;
}

//- response parsing

// Can the connection be reused after this response? Computed from values we
// already parsed — call it BEFORE h1_deliver flips state to Done. A close-
// delimited body (read-until-EOF) is never reusable (EOF is its only
// terminator); otherwise HTTP/1.1 keeps alive unless `Connection: close`, and
// HTTP/1.0 only when it explicitly opts in with `Connection: keep-alive`.
internal B32 h1_compute_keep_alive(H1Session *s) {
  if (s->state == H1State_BodyClose) return 0;
  String8 *cn = header_list_get_ci(&s->headers, str8_lit("connection"));
  if (cn && str8_contains_ci(*cn, str8_lit("close"))) return 0;
  if (s->http_minor >= 1) return 1;  // HTTP/1.1 default
  return cn &&
         str8_contains_ci(*cn, str8_lit("keep-alive"));  // HTTP/1.0 opt-in
}

internal void h1_deliver(H1Session *s) {
  if (s->delivered) return;
  s->delivered = 1;
  B32 keep = h1_compute_keep_alive(s);  // read framing/state before -> Done
  s->state = H1State_Done;
  H1Response r;
  MemoryZeroStruct(&r);
  r.status = s->status;
  r.headers = &s->headers;
  r.body = s->body.v;
  r.body_len = s->body.len;
  r.ok = (s->status != 0);
  r.keep_alive = keep;
  if (s->cb) s->cb(s->user, &r);
}

// Decode chunked body bytes incrementally. The decoder rewrites in place and is
// stateful; we keep the decoded payload as the prefix of `body` and let it
// consume the encoded framing of the freshly-appended tail. Returns 0 / -1
// error.
internal S64 h1_feed_chunked(H1Session *s, const U8 *data, U64 n) {
  if (n == 0) return 0;
  U64 decoded_len = s->body.len;    // payload prefix so far
  u8buf_append(&s->body, data, n);  // append encoded after the payload
  size_t sz = n;
  ssize_t r =
      phr_decode_chunked(&s->chunk_dec, (char *)s->body.v + decoded_len, &sz);
  s->body.len = decoded_len + sz;  // truncate to payload (drop framing)
  if (r == -1) return -1;
  if (r >= 0) h1_deliver(s);  // complete (r = trailing bytes, ignore)
  return 0;
}

internal S64 h1_feed_body(H1Session *s, const U8 *data, U64 n) {
  switch (s->state) {
    case H1State_BodyLength: {
      U64 need = s->content_length - s->body.len;
      U64 take = n < need ? n : need;
      u8buf_append(&s->body, data, take);
      if (s->body.len >= s->content_length) h1_deliver(s);
    } break;
    case H1State_BodyChunked:
      if (h1_feed_chunked(s, data, n) < 0) {
        s->state = H1State_Error;
        return -1;
      }
      break;
    case H1State_BodyClose:
      u8buf_append(&s->body, data, n);
      break;
    default:
      break;
  }
  return 0;
}

// Decide body framing once the headers are parsed; may deliver immediately.
internal void h1_begin_body(H1Session *s) {
  if (s->is_head || s->status == 204 || s->status == 304 ||
      (s->status >= 100 && s->status < 200)) {
    h1_deliver(s);
    return;
  }
  String8 *te = header_list_get_ci(&s->headers, str8_lit("transfer-encoding"));
  if (te && str8_contains_ci(*te, str8_lit("chunked"))) {
    s->state = H1State_BodyChunked;
    s->chunk_dec.consume_trailer = 1;
    return;
  }
  String8 *cl = header_list_get_ci(&s->headers, str8_lit("content-length"));
  if (cl) {
    s->content_length = str8_to_u64(*cl);
    s->state = H1State_BodyLength;
    if (s->content_length == 0) h1_deliver(s);
    return;
  }
  s->state = H1State_BodyClose;
}

S64 h1_session_recv(H1Session *s, const U8 *data, U64 len) {
  if (s->state == H1State_Error) return -1;
  if (s->state == H1State_Done) return (S64)len;

  if (s->state == H1State_Headers) {
    u8buf_append(&s->in, data, len);
    if (s->in.len > H1_MAX_HEADER_REGION) {
      s->state = H1State_Error;
      return -1;
    }
    struct phr_header hdr[H1_MAX_HEADERS];
    size_t num = H1_MAX_HEADERS;
    int minor = 0, status = 0;
    const char *msg = 0;
    size_t msg_len = 0;
    int rc = phr_parse_response((char *)s->in.v, s->in.len, &minor, &status,
                                &msg, &msg_len, hdr, &num, s->parsed_off);
    if (rc == -2) {
      s->parsed_off = s->in.len;
      return (S64)len;
    }
    if (rc == -1) {
      s->state = H1State_Error;
      return -1;
    }
    // Headers complete: copy out NOW (hdr[] point into `in`, which may move on
    // a later append), then never call phr_parse_response again.
    s->status = status;
    s->http_minor = (U32)minor;  // for the keep-alive (reuse) decision
    s->header_end = (U64)rc;
    for (size_t i = 0; i < num; ++i) {
      if (hdr[i].name_len == 0) continue;  // obs-fold continuation; ignore
      String8 name = str8((U8 *)hdr[i].name, hdr[i].name_len);
      String8 val = str8((U8 *)hdr[i].value, hdr[i].value_len);
      header_list_push(&s->headers, push_str8_copy(s->arena, name),
                       push_str8_copy(s->arena, val), 0);
    }
    h1_begin_body(s);
    // Feed any post-header bytes already buffered in `in`.
    if (s->state != H1State_Done && s->state != H1State_Error) {
      U64 extra = s->in.len - s->header_end;
      if (extra && h1_feed_body(s, s->in.v + s->header_end, extra) < 0)
        return -1;
    }
    return (S64)len;
  }

  // Body states.
  if (h1_feed_body(s, data, len) < 0) return -1;
  return (S64)len;
}

void h1_session_eof(H1Session *s) {
  if (s->delivered) return;
  if (s->state == H1State_BodyClose) h1_deliver(s);  // EOF = complete body
  // Otherwise leave undelivered: the caller reports a connection-closed error.
}
