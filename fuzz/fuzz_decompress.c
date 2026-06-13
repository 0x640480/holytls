// Fuzz Content-Encoding decoding: the first input byte selects the codec
// (gzip/deflate/br/zstd), the rest is the compressed payload fed to
// decode_content. Exercises the zlib/brotli/zstd glue on malformed streams.
#include "core/decompress.h"
#include "fuzz/fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) return 0;
  static const char *enc[] = {"gzip", "deflate", "br", "zstd"};
  String8 encoding = str8_cstring(enc[data[0] & 3]);

  Arena *a = fuzz_arena();
  Temp t = temp_begin(a);
  String8 out;
  decode_content(a, encoding, data + 1, (U64)(size - 1), &out);
  temp_end(t);
  return 0;
}
