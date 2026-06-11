#include "base/u8buf.h"

void u8buf_init(U8Buf *b, Arena *arena, U64 cap) {
  b->arena = arena;
  b->len = 0;
  b->cap = cap;
  b->v = cap ? push_array_no_zero(arena, U8, cap) : 0;
}

internal void u8buf_reserve(U8Buf *b, U64 need) {
  if (b->len + need <= b->cap) return;
  U64 ncap = b->cap ? b->cap : 64;
  while (ncap < b->len + need) ncap *= 2;
  U8 *nv = push_array_no_zero(b->arena, U8, ncap);
  if (b->len) MemoryCopy(nv, b->v, b->len);
  b->v = nv;
  b->cap = ncap;
}

void u8buf_push(U8Buf *b, U8 x) {
  u8buf_reserve(b, 1);
  b->v[b->len++] = x;
}

void u8buf_append(U8Buf *b, const U8 *p, U64 n) {
  if (!n) return;
  u8buf_reserve(b, n);
  MemoryCopy(b->v + b->len, p, n);
  b->len += n;
}
