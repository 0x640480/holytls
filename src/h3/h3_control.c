#include "h3/h3_control.h"

// HTTP/3 frame + reserved-id constants.
enum {
  H3_FRAME_DATA = 0x00,
  H3_FRAME_HEADERS = 0x01,
  H3_FRAME_SETTINGS = 0x04,
  H3_FRAME_PRIORITY_UPDATE = 0xf0700,  // 984832, request PRIORITY_UPDATE
};
// A reserved (GREASE) value of the form 0x1f*N+0x21.
#define H3_GREASE_SETTING (0x1f * 7 + 0x21)
#define H3_GREASE_FRAME (0x1f * 11 + 0x21)

internal B32 h3_is_reserved(U64 v) {
  return v >= 0x21 && (v - 0x21) % 0x1f == 0;
}

internal char pseudo_char(PseudoId id) {
  switch (id) {
    case Pseudo_Method:
      return 'm';
    case Pseudo_Authority:
      return 'a';
    case Pseudo_Scheme:
      return 's';
    case Pseudo_Path:
      return 'p';
  }
  return '?';
}

//- varints

void quic_varint_put(U8Buf *b, U64 v) {
  if (v < 0x40) {
    u8buf_push(b, (U8)v);
  } else if (v < 0x4000) {
    u8buf_push(b, (U8)(0x40 | (v >> 8)));
    u8buf_push(b, (U8)v);
  } else if (v < 0x40000000) {
    u8buf_push(b, (U8)(0x80 | (v >> 24)));
    u8buf_push(b, (U8)(v >> 16));
    u8buf_push(b, (U8)(v >> 8));
    u8buf_push(b, (U8)v);
  } else {
    u8buf_push(b, (U8)(0xc0 | (v >> 56)));
    u8buf_push(b, (U8)(v >> 48));
    u8buf_push(b, (U8)(v >> 40));
    u8buf_push(b, (U8)(v >> 32));
    u8buf_push(b, (U8)(v >> 24));
    u8buf_push(b, (U8)(v >> 16));
    u8buf_push(b, (U8)(v >> 8));
    u8buf_push(b, (U8)v);
  }
}

U64 quic_varint_get(const U8 *p, U64 len, U64 *consumed) {
  if (len == 0) {
    *consumed = 0;
    return 0;
  }
  U64 n = (U64)1 << (p[0] >> 6);  // 1, 2, 4 or 8 bytes
  if (len < n) {
    *consumed = 0;
    return 0;
  }
  U64 v = p[0] & 0x3f;
  for (U64 i = 1; i < n; ++i) v = (v << 8) | p[i];
  *consumed = n;
  return v;
}

//- control stream

// A single request PRIORITY_UPDATE frame (type + len + varint(stream_id) + the
// priority field value "u=1, i"). Sent inside the control stream for the first
// request on a connection and standalone on the open control stream for each
// later (pooled-reuse) request — so every request carries its own
// PRIORITY_UPDATE.
String8 build_h3_priority_update(Arena *arena, S64 prioritized_stream_id) {
  U8Buf out;
  u8buf_init(&out, arena, 16);
  U8Buf pu;
  u8buf_init(&pu, arena, 16);
  quic_varint_put(&pu, (U64)prioritized_stream_id);
  u8buf_append(&pu, (const U8 *)"u=1, i", 6);
  quic_varint_put(&out, H3_FRAME_PRIORITY_UPDATE);
  quic_varint_put(&out, pu.len);
  u8buf_append(&out, pu.v, pu.len);
  return u8buf_str8(&out);
}

String8 build_h3_control_stream(Arena *arena, const Http3Profile *p,
                                S64 prioritized_stream_id) {
  U8Buf out;
  u8buf_init(&out, arena, 64);
  quic_varint_put(&out, 0x00);  // control stream type

  // SETTINGS frame.
  U8Buf body;
  u8buf_init(&body, arena, 32);
  for (U8 i = 0; i < p->settings_count; ++i) {
    quic_varint_put(&body, p->settings[i].id);
    quic_varint_put(&body, p->settings[i].value);
  }
  if (p->settings_grease) {
    quic_varint_put(&body, H3_GREASE_SETTING);
    quic_varint_put(&body, 0x00);  // grease value (opaque)
  }
  quic_varint_put(&out, H3_FRAME_SETTINGS);
  quic_varint_put(&out, body.len);
  u8buf_append(&out, body.v, body.len);

  // GREASE frame (empty payload).
  if (p->send_grease_frame) {
    quic_varint_put(&out, H3_GREASE_FRAME);
    quic_varint_put(&out, 0x00);
  }

  // PRIORITY_UPDATE for the request stream, priority field value "u=1, i".
  if (p->send_priority_update) {
    String8 pu = build_h3_priority_update(arena, prioritized_stream_id);
    u8buf_append(&out, pu.str, pu.size);
  }

  return u8buf_str8(&out);
}

//- fingerprint text

String8 h3_text(Arena *arena, String8 control, const Http3Profile *p) {
  Temp scratch = scratch_begin(&arena, 1);
  const U8 *d = control.str;
  U64 len = control.size, off = 0, n = 0;

  quic_varint_get(d + off, len - off, &n);  // skip the stream type
  off += n;

  String8List frames = {0};
  while (off < len) {
    U64 type = quic_varint_get(d + off, len - off, &n);
    if (n == 0) break;
    off += n;
    U64 flen = quic_varint_get(d + off, len - off, &n);
    if (n == 0) break;
    off += n;
    const U8 *payload = d + off;
    U64 plen = (off + flen <= len) ? flen : (len - off);
    off += flen;

    if (type == H3_FRAME_SETTINGS) {
      String8List settings = {0};
      U64 so = 0;
      while (so < plen) {
        U64 id = quic_varint_get(payload + so, plen - so, &n);
        if (n == 0) break;
        so += n;
        U64 val = quic_varint_get(payload + so, plen - so, &n);
        if (n == 0) break;
        so += n;
        if (h3_is_reserved(id))
          str8_list_push(scratch.arena, &settings, str8_lit("GREASE"));
        else
          str8_list_pushf(scratch.arena, &settings, "%llu:%llu",
                          (unsigned long long)id, (unsigned long long)val);
      }
      str8_list_push(scratch.arena, &frames,
                     str8_list_join(scratch.arena, &settings, str8_lit(";")));
    } else if (h3_is_reserved(type)) {
      str8_list_push(scratch.arena, &frames, str8_lit("GREASE"));
    } else {
      str8_list_pushf(scratch.arena, &frames, "%llu", (unsigned long long)type);
    }
  }
  String8 frames_text = str8_list_join(scratch.arena, &frames, str8_lit("|"));

  String8List pseudo = {0};
  for (U8 i = 0; i < p->pseudo_count; ++i)
    str8_list_pushf(scratch.arena, &pseudo, "%c",
                    pseudo_char(p->pseudo_order[i]));
  String8 pseudo_text = str8_list_join(scratch.arena, &pseudo, str8_lit(","));

  String8 result =
      push_str8f(arena, "%.*s|%.*s", (int)frames_text.size, frames_text.str,
                 (int)pseudo_text.size, pseudo_text.str);
  scratch_end(scratch);
  return result;
}
