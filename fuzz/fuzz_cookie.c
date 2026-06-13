// Fuzz the Set-Cookie parser: arbitrary bytes as one Set-Cookie value stored
// against a fixed request URL, then the Cookie-header emit path. Exercises the
// RFC 6265 attribute parser, domain/path matching, and the jar growth — the
// code that consumes attacker-controlled response headers.
#include "core/cookie.h"
#include "core/url.h"
#include "fuzz/fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Arena *a = fuzz_arena();
  Temp t = temp_begin(a);

  CookieJar jar;
  cookie_jar_init(&jar, a);
  ParsedUrl url = url_parse(str8_lit("https://www.example.com/dir/page"));
  cookie_jar_store(&jar, url, fuzz_str8(data, size), 1700000000ULL);
  String8 hdr = cookie_jar_cookie_header(&jar, a, url, 1700000000ULL);
  (void)hdr;

  temp_end(t);
  return 0;
}
