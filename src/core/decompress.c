#include "core/decompress.h"

#include "base/u8buf.h"

#ifdef HOLYTLS_HAVE_ZLIB
#include <zlib.h>
#endif

// brotli / zstd dev headers may be absent; declare the streaming decode APIs.
#ifdef HOLYTLS_HAVE_BROTLI
typedef enum {
  BROTLI_DECODER_RESULT_ERROR = 0,
  BROTLI_DECODER_RESULT_SUCCESS = 1,
  BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT = 2,
  BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT = 3,
} BrotliDecoderResult;
typedef struct BrotliDecoderStateStruct BrotliDecoderState;
extern BrotliDecoderState *BrotliDecoderCreateInstance(void *, void *, void *);
extern void BrotliDecoderDestroyInstance(BrotliDecoderState *);
extern BrotliDecoderResult BrotliDecoderDecompressStream(
    BrotliDecoderState *, size_t *avail_in, const uint8_t **next_in,
    size_t *avail_out, uint8_t **next_out, size_t *total_out);
#endif
#ifdef HOLYTLS_HAVE_ZSTD
typedef struct ZSTD_DCtx_s ZSTD_DCtx;
extern ZSTD_DCtx *ZSTD_createDCtx(void);
extern size_t ZSTD_freeDCtx(ZSTD_DCtx *);
typedef struct {
  const void *src;
  size_t size;
  size_t pos;
} ZSTD_inBuffer;
typedef struct {
  void *dst;
  size_t size;
  size_t pos;
} ZSTD_outBuffer;
extern size_t ZSTD_decompressStream(ZSTD_DCtx *, ZSTD_outBuffer *,
                                    ZSTD_inBuffer *);
extern unsigned ZSTD_isError(size_t);
#endif

internal B32 eqi(String8 a, const char *b) {
  return str8_match_ci(a, str8_cstring(b));
}

// Decompression-bomb guard: hard cap on the decoded size. A handful of
// compressed KBs can expand to GBs (gzip ~1000:1); without a ceiling a
// malicious response exhausts memory. 256 MB is far above any legitimate
// in-memory response body. On breach the decoder fails and the body is
// delivered as received (still compressed), like any other decode failure.
// Note: this bounds the decoded LENGTH; peak arena usage during a max-size
// decode is a small multiple of it (U8Buf doubling abandons old runs in the
// arena until release) — bounded, just not equal to the cap.
#define DECODE_MAX_OUT (256ull << 20)

#ifdef HOLYTLS_HAVE_ZLIB
internal B32 zlib_inflate(const U8 *data, U64 len, int window_bits,
                          U8Buf *out) {
  z_stream zs;
  MemoryZeroStruct(&zs);
  if (inflateInit2(&zs, window_bits) != Z_OK) return 0;
  zs.next_in = (Bytef *)data;
  zs.avail_in = (uInt)len;
  U8 buf[16384];
  int rv;
  do {
    zs.next_out = buf;
    zs.avail_out = sizeof buf;
    rv = inflate(&zs, Z_NO_FLUSH);
    if (rv != Z_OK && rv != Z_STREAM_END && rv != Z_BUF_ERROR) {
      inflateEnd(&zs);
      return 0;
    }
    u8buf_append(out, buf, sizeof buf - zs.avail_out);
    if (out->len > DECODE_MAX_OUT) {  // decompression bomb
      inflateEnd(&zs);
      return 0;
    }
    if (rv == Z_BUF_ERROR) break;  // no progress possible (truncated/done)
  } while (rv != Z_STREAM_END);
  inflateEnd(&zs);
  return 1;
}
#endif

#ifdef HOLYTLS_HAVE_BROTLI
internal B32 brotli_decode(const U8 *data, U64 len, U8Buf *out) {
  BrotliDecoderState *s = BrotliDecoderCreateInstance(0, 0, 0);
  if (!s) return 0;
  size_t avail_in = len;
  const U8 *next_in = data;
  U8 buf[16384];
  BrotliDecoderResult r;
  do {
    size_t avail_out = sizeof buf;
    U8 *next_out = buf;
    r = BrotliDecoderDecompressStream(s, &avail_in, &next_in, &avail_out,
                                      &next_out, 0);
    u8buf_append(out, buf, sizeof buf - avail_out);
    if (r == BROTLI_DECODER_RESULT_ERROR || out->len > DECODE_MAX_OUT) {
      BrotliDecoderDestroyInstance(s);
      return 0;
    }
  } while (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);
  BrotliDecoderDestroyInstance(s);
  return r == BROTLI_DECODER_RESULT_SUCCESS;
}
#endif

#ifdef HOLYTLS_HAVE_ZSTD
internal B32 zstd_decode(const U8 *data, U64 len, U8Buf *out) {
  ZSTD_DCtx *d = ZSTD_createDCtx();
  if (!d) return 0;
  ZSTD_inBuffer in = {data, len, 0};
  U8 buf[16384];
  while (in.pos < in.size) {
    ZSTD_outBuffer ob = {buf, sizeof buf, 0};
    size_t r = ZSTD_decompressStream(d, &ob, &in);
    if (ZSTD_isError(r)) {
      ZSTD_freeDCtx(d);
      return 0;
    }
    u8buf_append(out, buf, ob.pos);
    if (out->len > DECODE_MAX_OUT) {  // decompression bomb
      ZSTD_freeDCtx(d);
      return 0;
    }
    if (ob.pos == 0 && r == 0) break;
  }
  ZSTD_freeDCtx(d);
  return 1;
}
#endif

// --- streaming decode -------------------------------------------------------

typedef enum DecKind {
  Dec_Identity,
  Dec_Gzip,  // zlib auto-detect (gzip + zlib-wrapped)
  Dec_Brotli,
  Dec_Zstd,
} DecKind;

struct StreamDecoder {
  DecKind kind;
  U64 total_out;  // cumulative decoded bytes (bomb cap)
  B32 dead;       // a prior push failed; further pushes are no-ops returning 0
#ifdef HOLYTLS_HAVE_ZLIB
  z_stream zs;
  B32 zs_init;
#endif
#ifdef HOLYTLS_HAVE_BROTLI
  BrotliDecoderState *br;
#endif
#ifdef HOLYTLS_HAVE_ZSTD
  ZSTD_DCtx *zd;
#endif
};

StreamDecoder *stream_decoder_create(String8 encoding) {
  StreamDecoder *d = (StreamDecoder *)calloc(1, sizeof *d);
  if (!d) return 0;
  String8 s = encoding;  // last comma token, trimmed (mirrors decode_content)
  U64 comma;
  if (str8_rindex_of(s, ',', &comma)) s = str8_skip(s, comma + 1);
  s = str8_trim(s);
  d->kind = Dec_Identity;
#ifdef HOLYTLS_HAVE_ZSTD
  if (eqi(s, "zstd")) {
    d->kind = Dec_Zstd;
    d->zd = ZSTD_createDCtx();
    if (!d->zd) d->kind = Dec_Identity;  // degrade to passthrough on OOM
  } else
#endif
#ifdef HOLYTLS_HAVE_BROTLI
      if (eqi(s, "br")) {
    d->kind = Dec_Brotli;
    d->br = BrotliDecoderCreateInstance(0, 0, 0);
    if (!d->br) d->kind = Dec_Identity;
  } else
#endif
#ifdef HOLYTLS_HAVE_ZLIB
      if (eqi(s, "gzip") || eqi(s, "x-gzip") || eqi(s, "deflate")) {
    // 15+32 auto-detects gzip and zlib-wrapped deflate (the common cases); raw
    // headerless deflate is not handled here (rare; would surface as an error).
    if (inflateInit2(&d->zs, 15 + 32) == Z_OK) {
      d->kind = Dec_Gzip;
      d->zs_init = 1;
    }
  }
#endif
  (void)s;
  return d;
}

// Emit a decoded run, enforcing the bomb cap. Returns 0 on breach.
internal B32 dec_emit(StreamDecoder *d, const U8 *p, U64 n, DecodeChunkFn cb,
                      void *user) {
  if (n == 0) return 1;
  d->total_out += n;
  if (d->total_out > DECODE_MAX_OUT) return 0;
  cb(user, p, n);
  return 1;
}

B32 stream_decoder_push(StreamDecoder *d, const U8 *in, U64 len,
                        DecodeChunkFn cb, void *user) {
  if (!d || d->dead) return 0;
  if (d->kind == Dec_Identity)
    return (d->dead = !dec_emit(d, in, len, cb, user)) ? 0 : 1;
  U8 buf[16384];
#ifdef HOLYTLS_HAVE_ZLIB
  if (d->kind == Dec_Gzip) {
    d->zs.next_in = (Bytef *)in;
    d->zs.avail_in = (uInt)len;
    int rv;
    do {
      d->zs.next_out = buf;
      d->zs.avail_out = sizeof buf;
      rv = inflate(&d->zs, Z_NO_FLUSH);
      if (rv != Z_OK && rv != Z_STREAM_END && rv != Z_BUF_ERROR) goto fail;
      if (!dec_emit(d, buf, sizeof buf - d->zs.avail_out, cb, user)) goto fail;
      if (rv == Z_BUF_ERROR) break;  // needs more input (or done)
    } while (d->zs.avail_in > 0 || d->zs.avail_out == 0);
    if (rv == Z_STREAM_END) { /* done; further input ignored */
    }
    return 1;
  }
#endif
#ifdef HOLYTLS_HAVE_BROTLI
  if (d->kind == Dec_Brotli) {
    size_t avail_in = len;
    const U8 *next_in = in;
    BrotliDecoderResult r;
    do {
      size_t avail_out = sizeof buf;
      U8 *next_out = buf;
      r = BrotliDecoderDecompressStream(d->br, &avail_in, &next_in, &avail_out,
                                        &next_out, 0);
      if (r == BROTLI_DECODER_RESULT_ERROR) goto fail;
      if (!dec_emit(d, buf, sizeof buf - avail_out, cb, user)) goto fail;
    } while (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);
    return 1;
  }
#endif
#ifdef HOLYTLS_HAVE_ZSTD
  if (d->kind == Dec_Zstd) {
    ZSTD_inBuffer ib = {in, len, 0};
    while (ib.pos < ib.size) {
      ZSTD_outBuffer ob = {buf, sizeof buf, 0};
      size_t r = ZSTD_decompressStream(d->zd, &ob, &ib);
      if (ZSTD_isError(r)) goto fail;
      if (!dec_emit(d, buf, ob.pos, cb, user)) goto fail;
      if (ob.pos == 0 && r == 0) break;
    }
    return 1;
  }
#endif
  return 1;
fail:
  d->dead = 1;
  return 0;
}

void stream_decoder_free(StreamDecoder *d) {
  if (!d) return;
#ifdef HOLYTLS_HAVE_ZLIB
  if (d->zs_init) inflateEnd(&d->zs);
#endif
#ifdef HOLYTLS_HAVE_BROTLI
  if (d->br) BrotliDecoderDestroyInstance(d->br);
#endif
#ifdef HOLYTLS_HAVE_ZSTD
  if (d->zd) ZSTD_freeDCtx(d->zd);
#endif
  free(d);
}

B32 decode_content(Arena *arena, String8 encoding, const U8 *data, U64 len,
                   String8 *out) {
  // Use the last token of a comma-listed encoding, trimmed.
  String8 s = encoding;
  U64 comma;
  if (str8_rindex_of(s, ',', &comma)) s = str8_skip(s, comma + 1);
  s = str8_trim(s);

  U8Buf buf;
  u8buf_init(&buf, arena, len ? len * 2 : 64);
  B32 ok = 0;
  if (s.size == 0 || eqi(s, "identity")) {
    u8buf_append(&buf, data, len);
    ok = 1;
  }
#ifdef HOLYTLS_HAVE_ZSTD
  else if (eqi(s, "zstd"))
    ok = zstd_decode(data, len, &buf);
#endif
#ifdef HOLYTLS_HAVE_BROTLI
  else if (eqi(s, "br"))
    ok = brotli_decode(data, len, &buf);
#endif
#ifdef HOLYTLS_HAVE_ZLIB
  else if (eqi(s, "gzip") || eqi(s, "x-gzip"))
    ok = zlib_inflate(data, len, 15 + 32, &buf);
  else if (eqi(s, "deflate")) {
    ok = zlib_inflate(data, len, 15 + 32, &buf);  // zlib-wrapped
    if (!ok) {
      u8buf_init(&buf, arena, len ? len * 2 : 64);  // reset, try raw deflate
      ok = zlib_inflate(data, len, -15, &buf);
    }
  }
#endif
  if (ok) *out = u8buf_str8(&buf);
  return ok;
}
