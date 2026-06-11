#include "base/base64.h"

global const char k_b64_enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

String8 base64_encode(Arena *arena, String8 in) {
  if (in.size == 0) return str8_zero();
  U64 out_len = ((in.size + 2) / 3) * 4;
  U8 *out = push_array_no_zero(arena, U8, out_len);
  U64 o = 0, i = 0;
  while (i + 3 <= in.size) {
    U32 n = (U32)in.str[i] << 16 | (U32)in.str[i + 1] << 8 | (U32)in.str[i + 2];
    out[o++] = (U8)k_b64_enc[(n >> 18) & 63];
    out[o++] = (U8)k_b64_enc[(n >> 12) & 63];
    out[o++] = (U8)k_b64_enc[(n >> 6) & 63];
    out[o++] = (U8)k_b64_enc[n & 63];
    i += 3;
  }
  U64 rem = in.size - i;
  if (rem == 1) {
    U32 n = (U32)in.str[i] << 16;
    out[o++] = (U8)k_b64_enc[(n >> 18) & 63];
    out[o++] = (U8)k_b64_enc[(n >> 12) & 63];
    out[o++] = '=';
    out[o++] = '=';
  } else if (rem == 2) {
    U32 n = (U32)in.str[i] << 16 | (U32)in.str[i + 1] << 8;
    out[o++] = (U8)k_b64_enc[(n >> 18) & 63];
    out[o++] = (U8)k_b64_enc[(n >> 12) & 63];
    out[o++] = (U8)k_b64_enc[(n >> 6) & 63];
    out[o++] = '=';
  }
  return str8(out, o);
}

// Reverse-map a base64 char: 0..63 data, 0xfe = '=' padding, 0xff = invalid.
internal U8 b64_rev(U8 ch) {
  if (ch >= 'A' && ch <= 'Z') return (U8)(ch - 'A');
  if (ch >= 'a' && ch <= 'z') return (U8)(ch - 'a' + 26);
  if (ch >= '0' && ch <= '9') return (U8)(ch - '0' + 52);
  if (ch == '+') return 62;
  if (ch == '/') return 63;
  if (ch == '=') return 0xfe;
  return 0xff;
}

String8 base64_decode(Arena *arena, String8 in) {
  if (in.size == 0 || (in.size % 4) != 0) return str8_zero();
  U8 *out = push_array_no_zero(arena, U8, (in.size / 4) * 3);
  U64 o = 0;
  for (U64 i = 0; i < in.size; i += 4) {
    U8 a = b64_rev(in.str[i]), b = b64_rev(in.str[i + 1]);
    U8 c = b64_rev(in.str[i + 2]), d = b64_rev(in.str[i + 3]);
    if (a >= 64 || b >= 64) return str8_zero();      // data required; no pad here
    if (c == 0xff || d == 0xff) return str8_zero();  // invalid byte
    B32 c_pad = (c == 0xfe), d_pad = (d == 0xfe);
    if (c_pad && !d_pad) return str8_zero();          // "xx=y" is malformed
    if ((c_pad || d_pad) && i + 4 != in.size)
      return str8_zero();                             // padding only in last quad
    U32 n = (U32)a << 18 | (U32)b << 12;
    out[o++] = (U8)((n >> 16) & 0xff);
    if (!c_pad) {
      n |= (U32)c << 6;
      out[o++] = (U8)((n >> 8) & 0xff);
      if (!d_pad) {
        n |= (U32)d;
        out[o++] = (U8)(n & 0xff);
      }
    }
  }
  return str8(out, o);
}
