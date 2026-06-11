#include "h3/h3_session.h"

#include <nghttp3/nghttp3.h>
#include <string.h>

#include "h3/h3_control.h"

// Server-initiated uni streams (control + QPACK enc/dec): a tiny fixed set, kept
// in an inline array with linear scan rather than a tree.
typedef struct H3Uni H3Uni;
struct H3Uni {
  S64 id;
  B32 type_read;
  U64 type;
};

struct H3Session {
  QuicConnection *conn;
  const Http3Profile *prof;
  const nghttp3_mem *mem;
  nghttp3_qpack_encoder *qenc;
  nghttp3_qpack_decoder *qdec;
  Arena *arena;  // owns response header bytes + the receive buffer
  HeaderList resp_headers;

  S64 req_stream_id;
  U8Buf req_in;  // buffered response (request stream)
  B32 req_fin;
  B32 delivered;
  int status;
  H3RespFn on_response;
  void *user;

  H3Uni uni[8];
  int uni_count;
};

internal nghttp3_nv h3_make_nv(String8 n, String8 v) {
  nghttp3_nv nv;
  nv.name = n.str;
  nv.namelen = n.size;
  nv.value = v.str;
  nv.valuelen = v.size;
  nv.flags = NGHTTP3_NV_FLAG_NONE;
  return nv;
}

internal void h3_on_stream_data(void *user, S64 stream_id, const U8 *data,
                                U64 len, B32 fin);
internal void h3_on_stream_close(void *user, S64 stream_id);
internal void h3_finish_response(H3Session *s);
internal void h3_decode_headers(H3Session *s, const U8 *block, U64 len);

H3Session *h3_session_alloc(QuicConnection *conn, const Http3Profile *prof) {
  Arena *arena = arena_alloc();
  H3Session *s = push_array(arena, H3Session, 1);
  s->conn = conn;
  s->prof = prof;
  s->mem = nghttp3_mem_default();
  s->arena = arena;
  s->req_stream_id = -1;
  header_list_init(&s->resp_headers, arena);
  u8buf_init(&s->req_in, arena, 0);

  if (nghttp3_qpack_encoder_new(&s->qenc, 0, s->mem) != 0 ||  // static only
      nghttp3_qpack_decoder_new(&s->qdec, 65536, 100, s->mem) != 0) {
    if (s->qenc) nghttp3_qpack_encoder_del(s->qenc);
    arena_release(arena);
    return 0;
  }
  quic_on_stream_data(conn, h3_on_stream_data, s);
  quic_on_stream_close(conn, h3_on_stream_close, s);
  return s;
}

void h3_session_release(H3Session *s) {
  if (!s) return;
  if (s->qenc) nghttp3_qpack_encoder_del(s->qenc);
  if (s->qdec) nghttp3_qpack_decoder_del(s->qdec);
  arena_release(s->arena);  // frees the H3Session itself too
}

B32 h3_session_request(H3Session *s, String8 method, String8 scheme,
                       String8 authority, String8 path, const Header *headers,
                       U64 header_count, const U8 *body, U64 body_len,
                       H3RespFn cb, void *user) {
  s->on_response = cb;
  s->user = user;

  // Request bidi stream first (its id goes into the control PRIORITY_UPDATE).
  if (quic_open_bidi_stream(s->conn, &s->req_stream_id) != 0) return 0;

  // Control + QPACK uni streams (Chrome order: control, encoder, decoder).
  S64 ctrl_id = -1, qenc_id = -1, qdec_id = -1;
  if (quic_open_uni_stream(s->conn, &ctrl_id) != 0) return 0;
  String8 control = build_h3_control_stream(s->arena, s->prof, s->req_stream_id);
  quic_stream_send(s->conn, ctrl_id, control.str, control.size, 0);

  if (quic_open_uni_stream(s->conn, &qenc_id) != 0) return 0;
  U8 enc_type = 0x02;
  quic_stream_send(s->conn, qenc_id, &enc_type, 1, 0);
  if (quic_open_uni_stream(s->conn, &qdec_id) != 0) return 0;
  U8 dec_type = 0x03;
  quic_stream_send(s->conn, qdec_id, &dec_type, 1, 0);

  // Build the header list: pseudo-headers in the profile's order, then the
  // caller's regular headers (nghttp3_nv just needs ptr+len — no copies).
  Temp scratch = scratch_begin(&s->arena, 1);
  // A Cookie header splits into one field per crumb (Chrome's H3 framing), so
  // size for the post-split field count.
  U64 field_count = 0;
  for (U64 i = 0; i < header_count; ++i)
    field_count += str8_match_ci(headers[i].name, str8_lit("cookie"))
                       ? cookie_crumbs(headers[i].value, 0, 0)
                       : 1;
  U64 nva_cap = s->prof->pseudo_count + field_count;
  nghttp3_nv *nva = push_array_no_zero(scratch.arena, nghttp3_nv, nva_cap);
  U64 nvlen = 0;
  for (U8 i = 0; i < s->prof->pseudo_count; ++i) {
    switch (s->prof->pseudo_order[i]) {
      case Pseudo_Method:
        nva[nvlen++] = h3_make_nv(str8_lit(":method"), method);
        break;
      case Pseudo_Authority:
        nva[nvlen++] = h3_make_nv(str8_lit(":authority"), authority);
        break;
      case Pseudo_Scheme:
        nva[nvlen++] = h3_make_nv(str8_lit(":scheme"), scheme);
        break;
      case Pseudo_Path:
        nva[nvlen++] = h3_make_nv(str8_lit(":path"), path);
        break;
    }
  }
  for (U64 i = 0; i < header_count; ++i) {
    if (str8_match_ci(headers[i].name, str8_lit("cookie"))) {
      U64 cc = cookie_crumbs(headers[i].value, 0, 0);
      String8 *crumbs = push_array_no_zero(scratch.arena, String8, cc ? cc : 1);
      cookie_crumbs(headers[i].value, crumbs, cc);
      for (U64 k = 0; k < cc; ++k)
        nva[nvlen++] = h3_make_nv(headers[i].name, crumbs[k]);
    } else {
      nva[nvlen++] = h3_make_nv(headers[i].name, headers[i].value);
    }
  }

  // QPACK-encode (static): prefix -> pbuf, field section -> rbuf.
  nghttp3_buf pbuf, rbuf, ebuf;
  U8 raw_pbuf[16];
  pbuf.begin = pbuf.pos = pbuf.last = raw_pbuf;
  pbuf.end = raw_pbuf + sizeof raw_pbuf;
  nghttp3_buf_init(&rbuf);
  nghttp3_buf_init(&ebuf);
  int rv = nghttp3_qpack_encoder_encode(s->qenc, &pbuf, &rbuf, &ebuf,
                                        s->req_stream_id, nva, nvlen);
  if (rv != 0) {
    nghttp3_buf_free(&rbuf, s->mem);
    nghttp3_buf_free(&ebuf, s->mem);
    scratch_end(scratch);
    return 0;
  }
  U64 pl = nghttp3_buf_len(&pbuf), rl = nghttp3_buf_len(&rbuf);

  U8Buf frame;
  u8buf_init(&frame, scratch.arena, pl + rl + 16);
  quic_varint_put(&frame, 0x01);  // HEADERS frame
  quic_varint_put(&frame, pl + rl);
  u8buf_append(&frame, pbuf.pos, pl);
  u8buf_append(&frame, rbuf.pos, rl);
  nghttp3_buf_free(&rbuf, s->mem);
  nghttp3_buf_free(&ebuf, s->mem);

  // HEADERS carries the fin only when there's no body; otherwise a DATA frame
  // follows and carries it.
  B32 has_body = body_len != 0;
  quic_stream_send(s->conn, s->req_stream_id, frame.v, frame.len, !has_body);
  if (has_body) {
    U8Buf dframe;
    u8buf_init(&dframe, scratch.arena, body_len + 16);
    quic_varint_put(&dframe, 0x00);  // DATA frame
    quic_varint_put(&dframe, body_len);
    u8buf_append(&dframe, body, body_len);
    quic_stream_send(s->conn, s->req_stream_id, dframe.v, dframe.len, 1);
  }
  scratch_end(scratch);
  return 1;
}

internal H3Uni *h3_find_or_add_uni(H3Session *s, S64 id) {
  for (int i = 0; i < s->uni_count; ++i)
    if (s->uni[i].id == id) return &s->uni[i];
  if (s->uni_count >= (int)ArrayCount(s->uni)) return 0;
  H3Uni *u = &s->uni[s->uni_count++];
  u->id = id;
  u->type_read = 0;
  u->type = 0;
  return u;
}

internal void h3_on_stream_data(void *user, S64 stream_id, const U8 *data,
                                U64 len, B32 fin) {
  H3Session *s = (H3Session *)user;
  if (stream_id == s->req_stream_id) {
    u8buf_append(&s->req_in, data, len);
    if (fin) {
      s->req_fin = 1;
      h3_finish_response(s);
    }
    return;
  }
  // Server-initiated uni stream: first varint is the stream type.
  H3Uni *u = h3_find_or_add_uni(s, stream_id);
  if (!u) return;  // more uni streams than the tiny fixed set expects
  const U8 *p = data;
  U64 rem = len;
  if (!u->type_read) {
    if (rem == 0) return;
    U64 n = 0;
    u->type = quic_varint_get(p, rem, &n);
    if (n == 0) return;
    p += n;
    rem -= n;
    u->type_read = 1;
  }
  // Server QPACK encoder stream (0x02) -> feed the decoder. control (0x00) +
  // qpack decoder (0x03) streams: ignored.
  if (u->type == 0x02 && rem) nghttp3_qpack_decoder_read_encoder(s->qdec, p, rem);
}

internal void h3_on_stream_close(void *user, S64 stream_id) {
  H3Session *s = (H3Session *)user;
  if (stream_id == s->req_stream_id && !s->req_fin) {
    s->req_fin = 1;
    h3_finish_response(s);
  }
}

internal void h3_finish_response(H3Session *s) {
  if (s->delivered) return;
  s->delivered = 1;

  // Parse frames; DATA payloads are compacted to the front of req_in in place so
  // the body is a single contiguous span with no extra heap buffer. The
  // compacted region always stays behind the parse cursor, so it never clobbers
  // not-yet-parsed bytes.
  U8 *base = s->req_in.v;
  U64 body_len = 0;
  const U8 *p = s->req_in.v;
  U64 rem = s->req_in.len;
  while (rem > 0) {
    U64 n = 0;
    U64 type = quic_varint_get(p, rem, &n);
    if (n == 0) break;
    p += n;
    rem -= n;
    U64 flen = quic_varint_get(p, rem, &n);
    if (n == 0) break;
    p += n;
    rem -= n;
    U64 plen = flen <= rem ? flen : rem;
    const U8 *payload = p;
    p += plen;
    rem -= plen;

    if (type == 0x01) {  // HEADERS
      h3_decode_headers(s, payload, plen);
    } else if (type == 0x00) {  // DATA
      if (base + body_len != payload) MemoryMove(base + body_len, payload, plen);
      body_len += plen;
    }
    // other (GREASE/PUSH_PROMISE...): ignored
  }

  H3Response resp;
  MemoryZeroStruct(&resp);
  resp.status = s->status;
  resp.headers = s->resp_headers.v;
  resp.header_count = s->resp_headers.count;
  resp.body = s->req_in.v;
  resp.body_len = body_len;
  resp.ok = s->status != 0;
  if (!resp.ok) resp.error = "no response headers";
  if (s->on_response) s->on_response(s->user, &resp);
}

internal void h3_decode_headers(H3Session *s, const U8 *block, U64 len) {
  nghttp3_qpack_stream_context *sctx = 0;
  nghttp3_qpack_stream_context_new(&sctx, s->req_stream_id, s->mem);
  const U8 *p = block;
  U64 rem = len;
  for (;;) {
    nghttp3_qpack_nv nv;
    uint8_t flags = 0;
    nghttp3_ssize n = nghttp3_qpack_decoder_read_request(s->qdec, sctx, &nv,
                                                         &flags, p, rem, 1);
    if (n < 0) break;
    p += n;
    rem -= (U64)n;
    if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
      nghttp3_vec nb = nghttp3_rcbuf_get_buf(nv.name);
      nghttp3_vec vb = nghttp3_rcbuf_get_buf(nv.value);
      String8 name = str8(nb.base, nb.len);
      String8 val = str8(vb.base, vb.len);
      if (str8_match(name, str8_lit(":status"))) {
        s->status = (int)str8_to_u64(val);
      } else {
        // Copy into the session arena so the views outlive nghttp3's rcbufs.
        header_list_push(&s->resp_headers, push_str8_copy(s->arena, name),
                         push_str8_copy(s->arena, val), 0);
      }
      nghttp3_rcbuf_decref(nv.name);
      nghttp3_rcbuf_decref(nv.value);
    }
    if (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) break;
    if (n == 0) break;
  }
  nghttp3_qpack_stream_context_del(sctx);
}
