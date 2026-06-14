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

// --- streaming decode (for response-body streaming) -------------------------
// A stateful decoder fed input incrementally, emitting decoded output in chunks
// via a callback — so a large body never has to be fully buffered. Decodes the
// last token of a comma-listed Content-Encoding (gzip/deflate/br/zstd; an
// empty/identity/unknown encoding is passthrough). Heap-allocated (holds codec
// state needing explicit teardown), independent of any arena.
typedef void (*DecodeChunkFn)(void *user, const U8 *data, U64 len);

typedef struct StreamDecoder StreamDecoder;

// Create a decoder for `encoding`. Never returns 0: an unrecognized encoding
// yields a passthrough decoder (input forwarded verbatim), matching the
// buffered path's "deliver as received on unknown codec" behavior. Free with
// stream_decoder_free.
StreamDecoder *stream_decoder_create(String8 encoding);

// Feed `len` input bytes; decoded output is delivered to `cb(user, ...)` in one
// or more chunks (cb may fire zero times if the codec needs more input).
// Returns 0 on a decode error or decompression-bomb breach (the same
// DECODE_MAX_OUT ceiling as the buffered path); the decoder is dead afterwards.
B32 stream_decoder_push(StreamDecoder *d, const U8 *in, U64 len,
                        DecodeChunkFn cb, void *user);

void stream_decoder_free(StreamDecoder *d);

#endif  // HOLYTLS_DECOMPRESS_H
