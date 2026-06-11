// H3 control-stream golden: build the Chrome-148 HTTP/3 control stream (SETTINGS
// + GREASE setting + GREASE frame + PRIORITY_UPDATE) from the profile, decode it
// into the browserleaks "h3_text", and assert the text + its MD5 (h3_hash) are
// byte-exact against the golden.
#include <openssl/md5.h>
#include <stdio.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "h3/h3_control.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal String8 md5_hex(Arena *a, String8 s) {
  U8 d[MD5_DIGEST_LENGTH];
  MD5(s.str, s.size, d);
  U8 *out = push_array_no_zero(a, U8, 2 * MD5_DIGEST_LENGTH);
  const char *hex = "0123456789abcdef";
  for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
    out[2 * i] = (U8)hex[d[i] >> 4];
    out[2 * i + 1] = (U8)hex[d[i] & 0xf];
  }
  return str8(out, 2 * MD5_DIGEST_LENGTH);
}

int main(void) {
  Arena *a = arena_alloc();
  const Http3Profile *h3 = &profile_chrome148_h3()->h3;

  // browserleaks observes PRIORITY_UPDATE prioritizing request stream 0.
  String8 cs = build_h3_control_stream(a, h3, /*prioritized_stream_id=*/0);
  String8 text = h3_text(a, cs, h3);
  String8 hash = md5_hex(a, text);

  String8 golden_text =
      str8_lit("1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p");
  String8 golden_hash = str8_lit("ba909fc3dc419ea5c5b26c6323ac1879");

  fprintf(stderr, "  h3_text = %.*s\n", (int)text.size, text.str);
  fprintf(stderr, "  h3_hash = %.*s  golden = %.*s\n", (int)hash.size, hash.str,
          (int)golden_hash.size, golden_hash.str);
  CHECK(str8_match(text, golden_text));
  CHECK(str8_match(hash, golden_hash));

  arena_release(a);
  fprintf(stderr, "[h3_control_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
