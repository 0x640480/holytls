// HTTP/3 control-stream construction — the fingerprint surface measured by the
// browserleaks "h3_hash". HTTP/3 control frames are simple QUIC-varint frames
// (type, length, payload), so we hand-roll them for full control over SETTINGS
// order, GREASE (a setting + a frame) and PRIORITY_UPDATE — things nghttp3 does
// not emit. (nghttp3 is used only for QPACK request-header encoding.)
#ifndef HOLYTLS_H3_CONTROL_H
#define HOLYTLS_H3_CONTROL_H

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "base/u8buf.h"
#include "profile/profile.h"

// QUIC varint codec (RFC 9000 §16). quic_varint_get sets *consumed to the byte
// count, or 0 on a short/empty buffer.
void quic_varint_put(U8Buf *b, U64 v);
U64 quic_varint_get(const U8 *p, U64 len, U64 *consumed);

// Build the client control-stream bytes: stream type 0x00 + SETTINGS (profile
// order, + a GREASE setting) + a GREASE frame + a PRIORITY_UPDATE for the given
// request stream. Returned bytes live in `arena`.
String8 build_h3_control_stream(Arena *arena, const Http3Profile *p,
                                S64 prioritized_stream_id);

// One request PRIORITY_UPDATE frame (sent standalone on the open control stream
// for each pooled-reuse request). Returned bytes live in `arena`.
String8 build_h3_priority_update(Arena *arena, S64 prioritized_stream_id);

// browserleaks-style h3 fingerprint text for a control stream + request pseudo
// order, e.g. "1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p".
String8 h3_text(Arena *arena, String8 control, const Http3Profile *p);

#endif  // HOLYTLS_H3_CONTROL_H
