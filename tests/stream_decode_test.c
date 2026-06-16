// Streaming Content-Encoding decoder: feed compressed input in small pieces and
// confirm the decoded chunks reassemble the original (the property
// response-body streaming relies on). Exercises the gzip (streaming inflate)
// and identity (passthrough) paths; gzip data is produced here with zlib's
// deflate.
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/decompress.h"

global int g_failures = 0;
#define CHECK(cond, msg)                                  \
  do {                                                    \
    if (!(cond)) {                                        \
      fprintf(stderr, "[stream_decode] FAIL: %s\n", msg); \
      g_failures++;                                       \
    }                                                     \
  } while (0)

// Sink: accumulate every decoded chunk into a fixed buffer.
typedef struct Sink Sink;
struct Sink {
  U8 *buf;
  U64 len;
  U64 cap;
};
internal void sink_cb(void *user, const U8 *data, U64 len) {
  Sink *s = (Sink *)user;
  if (s->len + len <= s->cap) MemoryCopy(s->buf + s->len, data, len);
  s->len += len;  // keep counting past cap so an overrun is detectable
}

// gzip-compress src into dst (zlib deflate, windowBits 15+16 = gzip wrapper).
internal U64 gzip_compress(const U8 *src, U64 n, U8 *dst, U64 dcap) {
  z_stream zs;
  MemoryZeroStruct(&zs);
  deflateInit2(&zs, Z_BEST_SPEED, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
  zs.next_in = (Bytef *)src;
  zs.avail_in = (uInt)n;
  zs.next_out = dst;
  zs.avail_out = (uInt)dcap;
  deflate(&zs, Z_FINISH);
  U64 out = dcap - zs.avail_out;
  deflateEnd(&zs);
  return out;
}

// Push `comp` through a streaming decoder in `step`-byte pieces; verify the
// reassembled output equals `orig`.
internal void run_case(const char *enc, const U8 *comp, U64 clen,
                       const U8 *orig, U64 olen, U64 step, const char *label) {
  U8 *out = (U8 *)malloc(olen + 64);
  Sink sink = {out, 0, olen + 64};
  StreamDecoder *d = stream_decoder_create(str8_cstring(enc));
  CHECK(d != 0, "decoder create");
  B32 ok = 1;
  for (U64 off = 0; off < clen && ok; off += step) {
    U64 n = off + step <= clen ? step : clen - off;
    ok = stream_decoder_push(d, comp + off, n, sink_cb, &sink);
  }
  stream_decoder_free(d);
  CHECK(ok, label);
  CHECK(sink.len == olen, label);
  CHECK(sink.len == olen && memcmp(out, orig, olen) == 0, label);
  free(out);
}

int main(void) {
  // A ~256 KB buffer with structure (so it actually compresses).
  U64 n = 256 * 1024;
  U8 *orig = (U8 *)malloc(n);
  for (U64 i = 0; i < n; i++) orig[i] = (U8)((i * 31 + (i >> 8)) & 0xff);

  U8 *comp = (U8 *)malloc(n + 1024);
  U64 clen = gzip_compress(orig, n, comp, n + 1024);
  CHECK(clen > 0 && clen < n, "gzip produced smaller output");

  // Stream gzip in awkward small pieces (boundaries fall mid-codec-block).
  run_case("gzip", comp, clen, orig, n, 7, "gzip step=7");
  run_case("gzip", comp, clen, orig, n, 1, "gzip step=1");
  run_case("gzip", comp, clen, orig, n, 65536, "gzip step=64k");
  // A comma-listed encoding uses the last token.
  run_case("identity, gzip", comp, clen, orig, n, 13, "gzip via comma-list");

  // Identity passthrough (the body IS the input).
  run_case("identity", orig, n, orig, n, 9, "identity passthrough");
  run_case("", orig, n, orig, n, 9, "empty-encoding passthrough");

  free(orig);
  free(comp);
  fprintf(stderr, "[stream_decode] %s (%d failures)\n",
          g_failures ? "FAILED" : "ok", g_failures);
  return g_failures ? 1 : 0;
}
