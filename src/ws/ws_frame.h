// RFC 6455 WebSocket frame codec — transport-agnostic. Build client frames
// (always masked) into a U8Buf; feed received bytes (from an HTTP/1.1 plaintext
// stream OR concatenated HTTP/2 DATA) into an incremental parser that yields
// whole application messages + control frames. No Connection / nghttp2 / TLS
// dependency: this is pure framing, so it can be unit-tested offline.
#ifndef HOLYTLS_WS_FRAME_H
#define HOLYTLS_WS_FRAME_H

#include "base/base.h"
#include "base/string8.h"
#include "base/u8buf.h"

typedef enum WsOpcode {
  WsOp_Continuation = 0x0,
  WsOp_Text = 0x1,
  WsOp_Binary = 0x2,
  WsOp_Close = 0x8,
  WsOp_Ping = 0x9,
  WsOp_Pong = 0xA,
} WsOpcode;

// Build one CLIENT frame into `out` (arena-backed). Per RFC 6455 a client MUST
// mask every frame: `mask_key` is 4 random bytes (the caller supplies them, e.g.
// from RAND_bytes) XORed over the payload. `fin` ends a message; for a single
// (unfragmented) message pass fin=1 with the text/binary opcode.
void ws_frame_build(U8Buf *out, WsOpcode op, B32 fin, const U8 *payload, U64 len,
                    const U8 mask_key[4]);

// --- incremental receive parser --------------------------------------------

typedef enum WsEventKind {
  WsEvent_Message,  // a complete application message (text/binary, reassembled)
  WsEvent_Ping,     // control: caller should reply with a Pong (echo data)
  WsEvent_Pong,
  WsEvent_Close,    // control: the peer is closing (close_code + optional reason)
} WsEventKind;

typedef struct WsEvent WsEvent;
struct WsEvent {
  WsEventKind kind;
  WsOpcode op;     // WsOp_Text / WsOp_Binary for a message; the control opcode else
  const U8 *data;  // message / control payload — valid only during the callback
  U64 len;
  U16 close_code;  // for WsEvent_Close (0 if the peer sent no code)
};

typedef void (*WsEventFn)(void *user, const WsEvent *ev);

typedef struct WsParser WsParser;
struct WsParser {
  // Frame-header accumulation (server->client frames are never masked, so the
  // header is 2 + 0/2/8 length bytes — no 4-byte mask key).
  U8 hdr[10];
  int hdr_have;  // header bytes accumulated
  int hdr_need;  // total header bytes needed (known after byte 2)
  B32 in_payload;

  // Current frame.
  B32 cur_fin;
  WsOpcode cur_op;
  B32 cur_control;  // current frame is a control frame (buffer to ctrl)
  U64 payload_remaining;

  // Reassembled application message (reused across messages — malloc'd, grows;
  // len reset to 0 after each complete message, capacity kept).
  U8 *msg;
  U64 msg_len, msg_cap;
  WsOpcode msg_op;   // opcode of the in-progress message (its first fragment)
  B32 in_message;    // a fragmented message is in progress
  U64 max_message;   // reassembly ceiling (decompression-bomb-style guard)

  // Control-frame payload (RFC 6455: control payloads are <= 125 bytes).
  U8 ctrl[125];
  U64 ctrl_len;

  B32 dead;  // a protocol error occurred; further feeds return -1
};

// Initialize a parser. `max_message` caps a reassembled message (0 => a 64 MB
// default). Pair with ws_parser_free.
void ws_parser_init(WsParser *p, U64 max_message);
void ws_parser_free(WsParser *p);

// Feed received bytes; each complete event is delivered to `cb(user, ...)` (one
// feed may yield several). Returns bytes consumed (== len) or <0 on a protocol
// error (the parser is dead afterwards).
S64 ws_parser_feed(WsParser *p, const U8 *data, U64 len, WsEventFn cb,
                   void *user);

#endif  // HOLYTLS_WS_FRAME_H
