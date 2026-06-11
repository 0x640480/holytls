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
internal B32 zlib_inflate(const U8 *data, U64 len, int window_bits, U8Buf *out) {
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
