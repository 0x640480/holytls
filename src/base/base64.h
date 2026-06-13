// base64 — RFC 4648 standard base64 (alphabet A-Za-z0-9+/, '=' padding). Pure
// and arena-backed, with no external dependencies, so it stays in the base
// layer alongside string8 / u8buf. Used for ECH config decoding, session
// serialization (TLS tickets + QUIC 0-RTT params), and anywhere raw bytes must
// ride inside JSON.
#ifndef HOLYTLS_BASE64_H
#define HOLYTLS_BASE64_H

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

// Encode `raw` to standard padded base64 in `arena`. {0,0} for empty input.
String8 base64_encode(Arena *arena, String8 raw);

// Decode standard base64 (`b64`) to raw bytes in `arena`. Strict: the input
// length must be a multiple of 4, with only the base64 alphabet and trailing
// '=' padding; any invalid byte, embedded whitespace, or misplaced padding
// yields {0,0}. {0,0} for empty input too.
String8 base64_decode(Arena *arena, String8 b64);

#endif  // HOLYTLS_BASE64_H
