#include "tls/ja4.h"

#include <openssl/md5.h>
#include <openssl/sha.h>

//- bounds-checked cursor ----------------------------------------------------

typedef struct Cursor Cursor;
struct Cursor {
  const U8 *p;
  const U8 *end;
  B32 ok;
};
internal U64 cur_remaining(Cursor *c) {
  return c->ok ? (U64)(c->end - c->p) : 0;
}
internal U8 cur_u8(Cursor *c) {
  if (cur_remaining(c) < 1) {
    c->ok = 0;
    return 0;
  }
  return *c->p++;
}
internal U16 cur_u16(Cursor *c) {
  if (cur_remaining(c) < 2) {
    c->ok = 0;
    return 0;
  }
  U16 v = (U16)((c->p[0] << 8) | c->p[1]);
  c->p += 2;
  return v;
}
internal U32 cur_u24(Cursor *c) {
  if (cur_remaining(c) < 3) {
    c->ok = 0;
    return 0;
  }
  U32 v = ((U32)c->p[0] << 16) | ((U32)c->p[1] << 8) | c->p[2];
  c->p += 3;
  return v;
}
internal void cur_skip(Cursor *c, U64 n) {
  if (cur_remaining(c) < n) {
    c->ok = 0;
    c->p = c->end;
    return;
  }
  c->p += n;
}

//- hashes -------------------------------------------------------------------

B32 ja4_is_grease(U16 v) {
  return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

String8 ja4_sha256_hex(Arena *arena, String8 s, U64 hex_chars) {
  U8 d[SHA256_DIGEST_LENGTH];
  SHA256(s.str, s.size, d);
  U64 maxh = 2 * SHA256_DIGEST_LENGTH;
  U64 n = hex_chars < maxh ? hex_chars : maxh;
  U8 *out = push_array_no_zero(arena, U8, n);
  for (U64 i = 0; i < n; ++i) {
    U8 b = d[i >> 1];
    out[i] = (U8)hex_digit_lower((i & 1) ? (b & 0xf) : (b >> 4));
  }
  return str8(out, n);
}

internal String8 md5_hex(Arena *arena, String8 s) {
  U8 d[MD5_DIGEST_LENGTH];
  MD5(s.str, s.size, d);
  U8 *out = push_array_no_zero(arena, U8, 2 * MD5_DIGEST_LENGTH);
  hex_encode(out, d, MD5_DIGEST_LENGTH);
  return str8(out, 2 * MD5_DIGEST_LENGTH);
}

//- parse --------------------------------------------------------------------

internal void parse_ch_body(Cursor *ch, ClientHelloInfo *info) {
  info->legacy_version = cur_u16(ch);
  cur_skip(ch, 32);          // random
  cur_skip(ch, cur_u8(ch));  // session id

  U16 cs_len = cur_u16(ch);
  for (U16 i = 0; i + 1 < cs_len; i += 2) {
    U16 v = cur_u16(ch);
    if (info->cipher_count < JA4_MAX_CIPHERS)
      info->cipher_suites[info->cipher_count++] = v;
  }

  cur_skip(ch, cur_u8(ch));  // compression methods

  if (cur_remaining(ch) >= 2) {
    U16 ext_total = cur_u16(ch);
    U64 cap = ext_total < cur_remaining(ch) ? ext_total : cur_remaining(ch);
    Cursor exts = {ch->p, ch->p + cap, 1};
    while (cur_remaining(&exts) >= 4) {
      U16 type = cur_u16(&exts);
      U16 elen = cur_u16(&exts);
      U64 ecap = elen < cur_remaining(&exts) ? elen : cur_remaining(&exts);
      Cursor ed = {exts.p, exts.p + ecap, 1};
      cur_skip(&exts, elen);
      if (info->ext_count < JA4_MAX_EXTS)
        info->extensions[info->ext_count++] = type;

      switch (type) {
        case 0x0000:  // server_name
          info->has_sni = 1;
          break;
        case 0x000a: {  // supported_groups
          U16 l = cur_u16(&ed);
          for (U16 j = 0; j + 1 < l; j += 2) {
            U16 v = cur_u16(&ed);
            if (info->group_count < JA4_MAX_GROUPS)
              info->supported_groups[info->group_count++] = v;
          }
          break;
        }
        case 0x000b: {  // ec_point_formats
          U8 l = cur_u8(&ed);
          for (U8 j = 0; j < l; ++j) {
            U8 v = cur_u8(&ed);
            if (info->ecpf_count < JA4_MAX_ECPF)
              info->ec_point_formats[info->ecpf_count++] = v;
          }
          break;
        }
        case 0x000d: {  // signature_algorithms
          U16 l = cur_u16(&ed);
          for (U16 j = 0; j + 1 < l; j += 2) {
            U16 v = cur_u16(&ed);
            if (info->sig_count < JA4_MAX_SIGALGS)
              info->sig_algs[info->sig_count++] = v;
          }
          break;
        }
        case 0x0010: {            // ALPN
          cur_u16(&ed);           // protocol list length
          U8 plen = cur_u8(&ed);  // first protocol length
          for (U8 j = 0; j < plen && ed.ok; ++j) {
            U8 v = cur_u8(&ed);
            if (info->alpn_len < JA4_MAX_ALPN)
              info->alpn_first[info->alpn_len++] = (char)v;
          }
          break;
        }
        case 0x002b: {  // supported_versions
          U8 l = cur_u8(&ed);
          for (U8 j = 0; j + 1 < l; j += 2) {
            U16 v = cur_u16(&ed);
            if (info->sv_count < JA4_MAX_SV)
              info->supported_versions[info->sv_count++] = v;
          }
          break;
        }
        default:
          break;
      }
    }
  }
  info->ok = ch->ok;
}

ClientHelloInfo ja4_parse_record(const U8 *rec, U64 len) {
  ClientHelloInfo info;
  MemoryZeroStruct(&info);
  info.transport = 't';
  Cursor c = {rec, rec + len, 1};
  if (cur_u8(&c) != 0x16) return info;  // not a handshake record
  cur_u16(&c);                          // record version
  U16 rec_len = cur_u16(&c);
  U64 cap = rec_len < cur_remaining(&c) ? rec_len : cur_remaining(&c);
  Cursor hs = {c.p, c.p + cap, 1};
  if (cur_u8(&hs) != 0x01) return info;  // not a ClientHello
  U32 ch_len = cur_u24(&hs);
  U64 ccap = ch_len < cur_remaining(&hs) ? ch_len : cur_remaining(&hs);
  Cursor ch = {hs.p, hs.p + ccap, 1};
  parse_ch_body(&ch, &info);
  return info;
}

ClientHelloInfo ja4_parse_handshake(const U8 *hs_msg, U64 len) {
  ClientHelloInfo info;
  MemoryZeroStruct(&info);
  info.transport = 'q';
  Cursor hs = {hs_msg, hs_msg + len, 1};
  if (cur_u8(&hs) != 0x01) return info;  // not a ClientHello
  U32 ch_len = cur_u24(&hs);
  U64 ccap = ch_len < cur_remaining(&hs) ? ch_len : cur_remaining(&hs);
  Cursor ch = {hs.p, hs.p + ccap, 1};
  parse_ch_body(&ch, &info);
  return info;
}

//- compute ------------------------------------------------------------------

internal int cmp_u16(const void *a, const void *b) {
  U16 x = *(const U16 *)a, y = *(const U16 *)b;
  return (x > y) - (x < y);
}

// Join U16 values as 4-hex-digit fields separated by ','.
internal String8 join_hex(Arena *arena, const U16 *v, U64 n) {
  if (n == 0) return str8((U8 *)"", 0);
  U8 *out = push_array_no_zero(arena, U8, n * 4 + n);  // 4 + comma per
  U64 off = 0;
  for (U64 i = 0; i < n; ++i) {
    if (i) out[off++] = ',';
    U16 x = v[i];
    out[off++] = (U8)hex_digit_lower((U8)(x >> 12));
    out[off++] = (U8)hex_digit_lower((U8)(x >> 8));
    out[off++] = (U8)hex_digit_lower((U8)(x >> 4));
    out[off++] = (U8)hex_digit_lower((U8)x);
  }
  return str8(out, off);
}

internal String8 join_dec_u16(Arena *arena, const U16 *v, U64 n) {
  String8List sl = {0};
  for (U64 i = 0; i < n; ++i) str8_list_pushf(arena, &sl, "%u", v[i]);
  return str8_list_join(arena, &sl, str8_lit("-"));
}
internal String8 join_dec_u8(Arena *arena, const U8 *v, U64 n) {
  String8List sl = {0};
  for (U64 i = 0; i < n; ++i) str8_list_pushf(arena, &sl, "%u", v[i]);
  return str8_list_join(arena, &sl, str8_lit("-"));
}

internal U64 filter_grease_u16(const U16 *in, U64 n, U16 *out) {
  U64 m = 0;
  for (U64 i = 0; i < n; ++i)
    if (!ja4_is_grease(in[i])) out[m++] = in[i];
  return m;
}

Fingerprints ja4_compute(Arena *arena, const ClientHelloInfo *in) {
  Fingerprints fp;
  MemoryZeroStruct(&fp);
  Temp scratch = scratch_begin(&arena, 1);
  Arena *sc = scratch.arena;

  // Filter GREASE from the lists.
  U16 ciphers[JA4_MAX_CIPHERS], exts_all[JA4_MAX_EXTS], sigs[JA4_MAX_SIGALGS],
      groups[JA4_MAX_GROUPS];
  U64 nc = filter_grease_u16(in->cipher_suites, in->cipher_count, ciphers);
  U64 ne = filter_grease_u16(in->extensions, in->ext_count, exts_all);
  U64 ns = filter_grease_u16(in->sig_algs, in->sig_count, sigs);
  U64 ng = filter_grease_u16(in->supported_groups, in->group_count, groups);

  // Version: max non-GREASE supported_version, else legacy.
  U16 ver = in->legacy_version;
  for (U64 i = 0; i < in->sv_count; ++i) {
    U16 v = in->supported_versions[i];
    if (!ja4_is_grease(v) && v > ver) ver = v;
  }
  const char *vs = "00";
  switch (ver) {
    case 0x0304:
      vs = "13";
      break;
    case 0x0303:
      vs = "12";
      break;
    case 0x0302:
      vs = "11";
      break;
    case 0x0301:
      vs = "10";
      break;
    case 0x0300:
      vs = "s3";
      break;
    default:
      vs = "00";
      break;
  }

  char counts[8];
  // %llu (not %zu) so MinGW's gcc -Wformat is happy too; values are <= 99 so
  // the 2-digit output (the JA4_a cipher/extension counts) is byte-identical.
  snprintf(counts, sizeof counts, "%02llu%02llu",
           (unsigned long long)(nc < 99 ? nc : 99),
           (unsigned long long)(ne < 99 ? ne : 99));

  char alpn2[3] = "00";
  if (in->alpn_len > 0) {
    alpn2[0] = in->alpn_first[0];
    alpn2[1] = in->alpn_first[in->alpn_len - 1];
  }

  String8 ja4_a = push_str8f(arena, "%c%s%c%s%s", in->transport, vs,
                             in->has_sni ? 'd' : 'i', counts, alpn2);

  // ja4_b: sorted ciphers -> sha256/12 (or 12 zeros when empty).
  U16 cs[JA4_MAX_CIPHERS];
  if (nc) MemoryCopy(cs, ciphers, nc * sizeof(U16));
  qsort(cs, nc, sizeof(U16), cmp_u16);
  String8 b_raw = join_hex(sc, cs, nc);
  String8 ja4_b = nc == 0 ? push_str8_copy(arena, str8_lit("000000000000"))
                          : ja4_sha256_hex(arena, b_raw, 12);

  // ja4_c: sorted exts (excl SNI 0x0000, ALPN 0x0010) + "_" + sigalgs in order.
  U16 exts_c[JA4_MAX_EXTS];
  U64 nec = 0;
  for (U64 i = 0; i < ne; ++i)
    if (exts_all[i] != 0x0000 && exts_all[i] != 0x0010)
      exts_c[nec++] = exts_all[i];
  qsort(exts_c, nec, sizeof(U16), cmp_u16);
  String8 exts_c_hex = join_hex(sc, exts_c, nec);
  String8 sigs_hex = join_hex(sc, sigs, ns);
  String8 c_raw = push_str8f(sc, "%.*s_%.*s", (int)exts_c_hex.size,
                             exts_c_hex.str, (int)sigs_hex.size, sigs_hex.str);
  String8 ja4_c = ja4_sha256_hex(arena, c_raw, 12);

  fp.ja4 = push_str8f(arena, "%.*s_%.*s_%.*s", (int)ja4_a.size, ja4_a.str,
                      (int)ja4_b.size, ja4_b.str, (int)ja4_c.size, ja4_c.str);
  fp.ja4_r = push_str8f(arena, "%.*s_%.*s_%.*s", (int)ja4_a.size, ja4_a.str,
                        (int)b_raw.size, b_raw.str, (int)c_raw.size, c_raw.str);

  // JA3: legacy_version, ciphers, exts, groups, ec_point_formats (decimal).
  String8 d_ciph = join_dec_u16(sc, ciphers, nc);
  String8 d_exts = join_dec_u16(sc, exts_all, ne);
  String8 d_grp = join_dec_u16(sc, groups, ng);
  String8 d_ecpf = join_dec_u8(sc, in->ec_point_formats, in->ecpf_count);
  fp.ja3_str =
      push_str8f(arena, "%u,%.*s,%.*s,%.*s,%.*s", in->legacy_version,
                 (int)d_ciph.size, d_ciph.str, (int)d_exts.size, d_exts.str,
                 (int)d_grp.size, d_grp.str, (int)d_ecpf.size, d_ecpf.str);
  fp.ja3 = md5_hex(arena, fp.ja3_str);

  scratch_end(scratch);
  return fp;
}
