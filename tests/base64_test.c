// Offline base64 tests: the RFC 4648 §10 test vectors, binary round-trips, and
// strict rejection of malformed input (bad length, invalid chars, stray
// padding).
#include "base/base64.h"

#include <stdio.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal B32 enc_is(Arena *a, const char *raw, const char *want) {
  return str8_match(base64_encode(a, str8_cstring(raw)), str8_cstring(want));
}
internal B32 dec_is(Arena *a, const char *b64, const char *want) {
  return str8_match(base64_decode(a, str8_cstring(b64)), str8_cstring(want));
}

internal void test_rfc4648(Arena *a) {
  // The canonical vectors (RFC 4648 §10), both directions.
  CHECK(enc_is(a, "", ""));
  CHECK(enc_is(a, "f", "Zg=="));
  CHECK(enc_is(a, "fo", "Zm8="));
  CHECK(enc_is(a, "foo", "Zm9v"));
  CHECK(enc_is(a, "foob", "Zm9vYg=="));
  CHECK(enc_is(a, "fooba", "Zm9vYmE="));
  CHECK(enc_is(a, "foobar", "Zm9vYmFy"));

  CHECK(dec_is(a, "", ""));
  CHECK(dec_is(a, "Zg==", "f"));
  CHECK(dec_is(a, "Zm8=", "fo"));
  CHECK(dec_is(a, "Zm9v", "foo"));
  CHECK(dec_is(a, "Zm9vYg==", "foob"));
  CHECK(dec_is(a, "Zm9vYmE=", "fooba"));
  CHECK(dec_is(a, "Zm9vYmFy", "foobar"));
}

internal void test_round_trip(Arena *a) {
  // Every byte value, and lengths hitting each padding case (0/1/2 remainder).
  for (U64 len = 0; len <= 256; ++len) {
    U8 *raw = push_array_no_zero(a, U8, len ? len : 1);
    for (U64 i = 0; i < len; ++i) raw[i] = (U8)((i * 37 + 11) & 0xff);
    String8 in = str8(raw, len);
    String8 enc = base64_encode(a, in);
    if (len) CHECK((enc.size % 4) == 0);  // always padded to a quad boundary
    CHECK(str8_match(base64_decode(a, enc), in));
  }
  // The full 64-symbol alphabet (incl. '+' and '/') round-trips.
  U8 all[48];
  for (int i = 0; i < 48; ++i) all[i] = (U8)((i * 5 + 1) & 0xff);
  String8 in = str8(all, sizeof all);
  CHECK(str8_match(base64_decode(a, base64_encode(a, in)), in));
}

internal void test_reject(Arena *a) {
  CHECK(base64_decode(a, str8_lit("Zg=")).size ==
        0);  // length not a multiple of 4
  CHECK(base64_decode(a, str8_lit("Zg")).size ==
        0);  // length not a multiple of 4
  CHECK(base64_decode(a, str8_lit("Z!==")).size == 0);  // invalid char '!'
  CHECK(base64_decode(a, str8_lit("Z g=")).size == 0);  // embedded space
  CHECK(base64_decode(a, str8_lit("Zm9=Zm9v")).size ==
        0);  // padding mid-stream
  CHECK(base64_decode(a, str8_lit("Z=g=")).size ==
        0);  // '=' in a data position
  CHECK(base64_decode(a, str8_lit("====")).size == 0);  // all padding
}

int main(void) {
  Arena *a = arena_alloc();
  test_rfc4648(a);
  test_round_trip(a);
  test_reject(a);
  arena_release(a);
  fprintf(stderr, "[base64_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
