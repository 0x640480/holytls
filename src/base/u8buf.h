// U8Buf — a growable byte buffer backed by an arena. The assembly surface for
// wire bytes (QUIC/H3 frames, decompressed bodies). Growth allocates a fresh,
// larger run in the arena and copies; the old run is abandoned in the arena and
// reclaimed in bulk on release. Not a general container — append-only.
#ifndef HOLYTLS_U8BUF_H
#define HOLYTLS_U8BUF_H

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

typedef struct U8Buf U8Buf;
struct U8Buf {
  U8 *v;
  U64 len;
  U64 cap;
  Arena *arena;
};

void u8buf_init(U8Buf *b, Arena *arena, U64 cap);
void u8buf_push(U8Buf *b, U8 x);
void u8buf_append(U8Buf *b, const U8 *p, U64 n);
internal inline String8 u8buf_str8(U8Buf *b) { return str8(b->v, b->len); }

#endif  // HOLYTLS_U8BUF_H
