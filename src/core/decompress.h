// Transparent Content-Encoding decoding (gzip / deflate / br / zstd). Decodes
// the last token of a possibly comma-listed encoding into an arena-backed
// String8. Returns false (and leaves *out untouched) on an unknown/failed
// codec.
#ifndef HOLYTLS_DECOMPRESS_H
#define HOLYTLS_DECOMPRESS_H

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

B32 decode_content(Arena *arena, String8 encoding, const U8 *data, U64 len,
                   String8 *out);

#endif  // HOLYTLS_DECOMPRESS_H
