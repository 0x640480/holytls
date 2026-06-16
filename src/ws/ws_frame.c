#include "ws/ws_frame.h"

#include <stdlib.h>  // realloc/free for the reused reassembly buffer

// Non-null sentinel so an empty (zero-length) message/control still hands the
// callback a valid pointer — a consumer that memcpy/ffi.buffers (data, 0) must
// not see NULL.
global const U8 g_ws_empty[1] = {0};

// --- build (client frames are always masked) --------------------------------

void ws_frame_build(U8Buf *out, WsOpcode op, B32 fin, B32 rsv1,
                    const U8 *payload, U64 len, const U8 mask_key[4]) {
  u8buf_push(out, (U8)((fin ? 0x80 : 0) | (rsv1 ? 0x40 : 0) | ((U8)op & 0x0f)));
  if (len < 126) {
    u8buf_push(out, (U8)(0x80 | len));
  } else if (len <= 0xffff) {
    u8buf_push(out, 0x80 | 126);
    u8buf_push(out, (U8)(len >> 8));
    u8buf_push(out, (U8)len);
  } else {
    u8buf_push(out, 0x80 | 127);
    for (int i = 7; i >= 0; --i) u8buf_push(out, (U8)(len >> (i * 8)));
  }
  u8buf_append(out, mask_key, 4);
  U64 off = out->len;
  if (len) u8buf_append(out, payload, len);  // copied in, then masked in place
  for (U64 i = 0; i < len; ++i) out->v[off + i] ^= mask_key[i & 3];
}

// --- incremental parse ------------------------------------------------------

void ws_parser_init(WsParser *p, U64 max_message) {
  MemoryZeroStruct(p);
  p->max_message = max_message ? max_message : (64ull << 20);
}

void ws_parser_free(WsParser *p) {
  if (p->msg) {
    free(p->msg);
    p->msg = 0;
  }
}

internal S64 ws_fail(WsParser *p) {
  p->dead = 1;
  return -1;
}

// Append received message-payload bytes to the reassembly buffer (reused across
// messages; grows by doubling). Returns 0 on the bomb cap or OOM.
internal B32 ws_msg_append(WsParser *p, const U8 *d, U64 n) {
  if (n == 0) return 1;
  if (p->msg_len + n > p->max_message) return 0;
  if (p->msg_len + n > p->msg_cap) {
    U64 cap = p->msg_cap ? p->msg_cap : 4096;
    while (cap < p->msg_len + n) cap *= 2;
    U8 *nb = (U8 *)realloc(p->msg, cap);
    if (!nb) return 0;
    p->msg = nb;
    p->msg_cap = cap;
  }
  MemoryCopy(p->msg + p->msg_len, d, n);
  p->msg_len += n;
  return 1;
}

// A complete frame header has arrived (p->hdr[0..hdr_need)); validate it and
// set up payload accumulation. Returns 0 on a protocol violation.
internal B32 ws_begin_frame(WsParser *p) {
  p->cur_fin = (p->hdr[0] & 0x80) != 0;
  p->cur_op = (WsOpcode)(p->hdr[0] & 0x0f);
  B32 rsv1 = (p->hdr[0] & 0x40) != 0;
  U8 l7 = p->hdr[1] & 0x7f;
  U64 plen;
  if (l7 < 126)
    plen = l7;
  else if (l7 == 126)
    plen = ((U64)p->hdr[2] << 8) | p->hdr[3];
  else {
    plen = 0;
    for (int k = 0; k < 8; ++k) plen = (plen << 8) | p->hdr[2 + k];
  }
  p->payload_remaining = plen;

  if (rsv1 && !p->allow_rsv1) return 0;  // RSV1 without negotiated extension

  if (p->cur_op & 0x8) {  // control frame
    if (!p->cur_fin || plen > 125)
      return 0;          // control: never fragmented, <=125
    if (rsv1) return 0;  // RFC 7692: control frames are never compressed
    if (p->cur_op != WsOp_Close && p->cur_op != WsOp_Ping &&
        p->cur_op != WsOp_Pong)
      return 0;  // reserved control opcode
    p->cur_control = 1;
    p->ctrl_len = 0;
  } else {  // data frame: text / binary / continuation
    if (p->cur_op != WsOp_Text && p->cur_op != WsOp_Binary &&
        p->cur_op != WsOp_Continuation)
      return 0;  // reserved data opcode
    p->cur_control = 0;
    if (p->cur_op == WsOp_Continuation) {
      if (!p->in_message) return 0;  // continuation with no message started
      if (rsv1) return 0;            // RSV1 only on a message's FIRST frame
    } else {  // first frame of a new message (Text/Binary)
      if (p->in_message) return 0;  // new message while one is in progress
      p->in_message = 1;
      p->msg_op = p->cur_op;
      p->msg_rsv1 = rsv1;  // RSV1 here marks the whole reassembled message
      p->msg_len = 0;      // fresh message (reuse the buffer's capacity)
    }
  }
  return 1;
}

// The current frame's payload is fully received; emit any resulting event.
internal B32 ws_frame_done(WsParser *p, WsEventFn cb, void *user) {
  if (p->cur_control) {
    WsEvent ev;
    MemoryZeroStruct(&ev);
    ev.op = p->cur_op;
    if (p->cur_op == WsOp_Ping) {
      ev.kind = WsEvent_Ping;
      ev.data = p->ctrl;
      ev.len = p->ctrl_len;
    } else if (p->cur_op == WsOp_Pong) {
      ev.kind = WsEvent_Pong;
      ev.data = p->ctrl;
      ev.len = p->ctrl_len;
    } else {  // close: optional 2-byte big-endian code + reason
      ev.kind = WsEvent_Close;
      if (p->ctrl_len >= 2) {
        ev.close_code = ((U16)p->ctrl[0] << 8) | p->ctrl[1];
        ev.data = p->ctrl + 2;
        ev.len = p->ctrl_len - 2;
      } else {
        ev.data = p->ctrl;
        ev.len = 0;
      }
    }
    cb(user, &ev);
    p->cur_control = 0;
    return 1;
  }
  // data frame: deliver the whole message on FIN
  if (p->cur_fin) {
    WsEvent ev;
    MemoryZeroStruct(&ev);
    ev.kind = WsEvent_Message;
    ev.op = p->msg_op;
    ev.data =
        p->msg ? p->msg : g_ws_empty;  // non-null even for an empty message
    ev.len = p->msg_len;
    ev.compressed = p->msg_rsv1;  // RFC 7692: payload is still deflated
    cb(user, &ev);
    p->in_message = 0;
    p->msg_len = 0;  // keep capacity for the next message
  }
  return 1;
}

S64 ws_parser_feed(WsParser *p, const U8 *data, U64 len, WsEventFn cb,
                   void *user) {
  if (p->dead) return -1;
  U64 i = 0;
  while (i < len) {
    if (!p->in_payload) {
      p->hdr[p->hdr_have++] = data[i++];
      if (p->hdr_have == 2) {
        if (p->hdr[1] & 0x80) return ws_fail(p);  // server frames are unmasked
        if (p->hdr[0] & 0x30) return ws_fail(p);  // RSV2/RSV3 always illegal
        // RSV1 (0x40) is validated per-opcode in ws_begin_frame (only a
        // permessage-deflate compressed data-message first frame may set it).
        U8 l7 = p->hdr[1] & 0x7f;
        p->hdr_need = l7 == 126 ? 4 : l7 == 127 ? 10 : 2;
      }
      if (p->hdr_have >= 2 && p->hdr_have == p->hdr_need) {
        if (!ws_begin_frame(p)) return ws_fail(p);
        p->hdr_have = 0;
        p->in_payload = 1;
        if (p->payload_remaining == 0) {  // zero-length frame completes at once
          if (!ws_frame_done(p, cb, user)) return ws_fail(p);
          p->in_payload = 0;
        }
      }
      continue;
    }
    U64 avail = len - i;
    U64 take = avail < p->payload_remaining ? avail : p->payload_remaining;
    if (p->cur_control)
      MemoryCopy(p->ctrl + p->ctrl_len, data + i, take);  // bounded <= 125
    else if (!ws_msg_append(p, data + i, take))
      return ws_fail(p);
    if (p->cur_control) p->ctrl_len += take;
    i += take;
    p->payload_remaining -= take;
    if (p->payload_remaining == 0) {
      if (!ws_frame_done(p, cb, user)) return ws_fail(p);
      p->in_payload = 0;
    }
  }
  return (S64)len;
}
