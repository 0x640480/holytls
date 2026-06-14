// Offline unit tests for the core helpers: url_parse, alt_svc_parse,
// build_ordered_headers, and decode_content (gzip/deflate/zstd round-trip + the
// identity / comma-list / unknown cases).
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/alt_svc.h"
#include "core/client.h"
#include "core/client_internal.h"
#include "core/decompress.h"
#include "core/header.h"
#include "core/header_order.h"
#include "core/url.h"

extern size_t ZSTD_compress(void *, size_t, const void *, size_t, int);
extern size_t ZSTD_compressBound(size_t);

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

//- url
internal void test_url(void) {
  ParsedUrl u = url_parse(str8_lit("https://tls.browserleaks.com/json"));
  CHECK(u.ok && u.https && u.port == 443);
  CHECK(str8_match(u.host, str8_lit("tls.browserleaks.com")));
  CHECK(str8_match(u.authority, str8_lit("tls.browserleaks.com")));
  CHECK(str8_match(u.path, str8_lit("/json")));

  u = url_parse(str8_lit("https://example.com:8443/a?b=c"));
  CHECK(u.ok && u.port == 8443);
  CHECK(str8_match(u.host, str8_lit("example.com")));
  CHECK(str8_match(u.authority, str8_lit("example.com:8443")));
  CHECK(str8_match(u.path, str8_lit("/a?b=c")));

  u = url_parse(str8_lit("http://x.com"));
  CHECK(u.ok && !u.https && u.port == 80);
  CHECK(str8_match(u.path, str8_lit("/")));

  u = url_parse(str8_lit("https://[::1]:9000/p"));
  CHECK(u.ok && u.port == 9000);
  CHECK(str8_match(u.host, str8_lit("::1")));

  CHECK(!url_parse(str8_lit("ftp://x.com/")).ok);
  CHECK(!url_parse(str8_lit("not a url")).ok);
}

//- url_resolve (Location against a base URL)
internal void test_url_resolve(Arena *a) {
  String8 base = str8_lit("https://example.com/a/b/c?q=1");
  CHECK(str8_match(url_resolve(a, base, str8_lit("https://other.com/x")),
                   str8_lit("https://other.com/x")));  // absolute
  CHECK(str8_match(url_resolve(a, base, str8_lit("//cdn.com/y")),
                   str8_lit("https://cdn.com/y")));  // protocol-rel
  CHECK(str8_match(url_resolve(a, base, str8_lit("/newpath")),
                   str8_lit("https://example.com/newpath")));  // absolute-path
  CHECK(str8_match(url_resolve(a, base, str8_lit("d")),
                   str8_lit("https://example.com/a/b/d")));  // relative
  CHECK(str8_match(url_resolve(a, str8_lit("https://x.com/"), str8_lit("y")),
                   str8_lit("https://x.com/y")));  // root base
}

//- redirect method/body decision (browser-faithful)
internal void test_redirect_method(void) {
  B32 drop;
  CHECK(redirect_next_method(Method_POST, 301, &drop) == Method_GET && drop);
  CHECK(redirect_next_method(Method_POST, 302, &drop) == Method_GET && drop);
  CHECK(redirect_next_method(Method_POST, 303, &drop) == Method_GET && drop);
  CHECK(redirect_next_method(Method_GET, 303, &drop) == Method_GET && drop);
  CHECK(redirect_next_method(Method_POST, 307, &drop) == Method_POST && !drop);
  CHECK(redirect_next_method(Method_POST, 308, &drop) == Method_POST && !drop);
  CHECK(redirect_next_method(Method_GET, 301, &drop) == Method_GET && !drop);
  CHECK(redirect_next_method(Method_PUT, 302, &drop) == Method_PUT && !drop);
}

//- alt-svc
internal void test_alt_svc(void) {
  AltSvcInfo a = alt_svc_parse(str8_lit("h3=\":443\"; ma=2592000"));
  CHECK(a.h3 && a.ma_seconds == 2592000);
  a = alt_svc_parse(str8_lit("h3-29=\":443\""));
  CHECK(a.h3 && a.ma_seconds == 86400);  // default
  a = alt_svc_parse(str8_lit("h2=\":443\""));
  CHECK(!a.h3);
  a = alt_svc_parse(str8_lit("h3=\":443\"; clear"));
  CHECK(!a.h3);
}

//- header order
internal void test_header_order(Arena *a) {
  DefaultHeader defaults[] = {
      {"user-agent", "UA", 0}, {"accept", "*/*", 0}, {"cookie", "", 0}};
  Header caller[] = {
      {str8_lit("accept"), str8_lit("text/html"), 0},
      {str8_lit("x-custom"), str8_lit("1"), 0},
  };
  HeaderList out;
  header_list_init(&out, a);
  build_ordered_headers(a, defaults, 3, caller, 2, &out);
  // user-agent=UA, accept=text/html (overridden), x-custom=1; cookie dropped.
  CHECK(out.count == 3);
  CHECK(str8_match(out.v[0].name, str8_lit("user-agent")) &&
        str8_match(out.v[0].value, str8_lit("UA")));
  CHECK(str8_match(out.v[1].name, str8_lit("accept")) &&
        str8_match(out.v[1].value, str8_lit("text/html")));
  CHECK(str8_match(out.v[2].name, str8_lit("x-custom")));

  // A caller header with empty value suppresses a default.
  Header suppress[] = {{str8_lit("accept"), str8_zero(), 0}};
  HeaderList out2;
  header_list_init(&out2, a);
  build_ordered_headers(a, defaults, 3, suppress, 1, &out2);
  CHECK(out2.count == 1);  // only user-agent (accept suppressed, cookie empty)
  CHECK(str8_match(out2.v[0].name, str8_lit("user-agent")));
}

//- decompress
internal String8 gzip_compress(Arena *a, String8 s) {
  z_stream zs;
  MemoryZeroStruct(&zs);
  deflateInit2(&zs, Z_BEST_SPEED, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
  zs.next_in = (Bytef *)s.str;
  zs.avail_in = (uInt)s.size;
  U8 *out = push_array_no_zero(a, U8, s.size + 256);
  zs.next_out = out;
  zs.avail_out = (uInt)(s.size + 256);
  deflate(&zs, Z_FINISH);
  U64 n = (s.size + 256) - zs.avail_out;
  deflateEnd(&zs);
  return str8(out, n);
}

internal String8 zlib_compress(Arena *a, String8 s) {
  uLongf bound = compressBound((uLong)s.size);
  U8 *out = push_array_no_zero(a, U8, bound);
  compress2(out, &bound, (const Bytef *)s.str, (uLong)s.size, Z_BEST_SPEED);
  return str8(out, bound);
}

internal String8 zstd_compress(Arena *a, String8 s) {
  size_t bound = ZSTD_compressBound(s.size);
  U8 *out = push_array_no_zero(a, U8, bound);
  size_t n = ZSTD_compress(out, bound, s.str, s.size, 3);
  return str8(out, n);
}

internal B32 roundtrip(Arena *a, const char *enc, String8 comp, String8 orig) {
  String8 out;
  if (!decode_content(a, str8_cstring(enc), comp.str, comp.size, &out))
    return 0;
  return str8_match(out, orig);
}

internal void test_decompress(Arena *a) {
  String8List sl = {0};
  for (int i = 0; i < 400; ++i)
    str8_list_push(a, &sl,
                   str8_lit("the quick brown fox jumps over the lazy dog\n"));
  String8 data = str8_list_join(a, &sl, str8_zero());

  CHECK(roundtrip(a, "gzip", gzip_compress(a, data), data));
  CHECK(roundtrip(a, "deflate", zlib_compress(a, data), data));
  CHECK(roundtrip(a, "zstd", zstd_compress(a, data), data));
  CHECK(roundtrip(a, "identity", data, data));
  CHECK(roundtrip(a, "", data, data));
  // comma-list: the outermost (last) token wins.
  CHECK(roundtrip(a, "gzip, deflate", zlib_compress(a, data), data));
  // unknown -> false.
  String8 out;
  CHECK(!decode_content(a, str8_lit("snappy"), data.str, data.size, &out));
}

int main(void) {
  Arena *a = arena_alloc();
  test_url();
  test_url_resolve(a);
  test_redirect_method();
  test_alt_svc();
  test_header_order(a);
  test_decompress(a);
  arena_release(a);
  fprintf(stderr, "[core_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
