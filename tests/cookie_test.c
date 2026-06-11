// Offline RFC 6265 cookie-jar tests: the HTTP-date parser, host-only vs Domain
// scope, path-match boundaries, secure-only, Max-Age vs Expires + deletion,
// longest-path-first ordering, and replacement.
#include <stdio.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/cookie.h"
#include "core/url.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal ParsedUrl U(const char *s) { return url_parse(str8_cstring(s)); }
internal B32 has(String8 hdr, const char *sub) {
  return str8_contains(hdr, str8_cstring(sub));
}

internal void test_http_date(void) {
  CHECK(http_date_parse(str8_lit("Thu, 01 Jan 1970 00:00:01 GMT")) == 1);
  CHECK(http_date_parse(str8_lit("Wed, 09 Jun 2021 10:18:14 GMT")) ==
        1623233894);
  CHECK(http_date_parse(str8_lit("Sat, 29 Feb 2020 00:00:00 GMT")) ==
        1582934400);                                           // leap day
  CHECK(http_date_parse(str8_lit("not a date")) == 0);          // malformed
  CHECK(http_date_parse(str8_lit("")) == 0);
  // RFC 850 (dash) form parses too.
  CHECK(http_date_parse(str8_lit("Wednesday, 09-Jun-2021 10:18:14 GMT")) ==
        1623233894);
}

internal void test_scope(Arena *a) {
  CookieJar jar;
  cookie_jar_init(&jar, a);
  // host-only (no Domain): set on a.example.com.
  cookie_jar_store(&jar, U("https://a.example.com/"), str8_lit("sid=1"), 1000);
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://a.example.com/"), 1000),
            "sid=1"));
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://b.example.com/"), 1000),
             "sid=1"));  // host-only -> not other host

  // Domain cookie: covers subdomains.
  cookie_jar_store(&jar, U("https://a.example.com/"),
                   str8_lit("did=2; Domain=example.com"), 1000);
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://a.example.com/"), 1000),
            "did=2"));
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://b.example.com/"), 1000),
            "did=2"));  // domain-match

  // Domain mismatch + bare TLD are rejected.
  cookie_jar_store(&jar, U("https://a.example.com/"),
                   str8_lit("bad=3; Domain=other.com"), 1000);
  cookie_jar_store(&jar, U("https://a.example.com/"),
                   str8_lit("tld=4; Domain=com"), 1000);
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://other.com/"), 1000),
             "bad=3"));
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://a.example.com/"), 1000),
             "tld=4"));
}

internal void test_path(Arena *a) {
  CookieJar jar;
  cookie_jar_init(&jar, a);
  cookie_jar_store(&jar, U("https://h.com/api"),
                   str8_lit("p=1; Path=/api"), 1000);
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://h.com/api"), 1000),
            "p=1"));
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://h.com/api/x"), 1000),
            "p=1"));
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://h.com/apidocs"), 1000),
             "p=1"));  // prefix but not a path boundary
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://h.com/"), 1000),
             "p=1"));
}

internal void test_secure(Arena *a) {
  CookieJar jar;
  cookie_jar_init(&jar, a);
  cookie_jar_store(&jar, U("https://h.com/"), str8_lit("s=1; Secure"), 1000);
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://h.com/"), 1000), "s=1"));
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("http://h.com/"), 1000),
             "s=1"));  // not over http
}

internal void test_expiry(Arena *a) {
  CookieJar jar;
  cookie_jar_init(&jar, a);
  U64 now = 1000000000;
  cookie_jar_store(&jar, U("https://h.com/"), str8_lit("m=1; Max-Age=100"), now);
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://h.com/"), now), "m=1"));
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://h.com/"), now + 200),
             "m=1"));  // expired by now+200

  // Max-Age=0 deletes.
  cookie_jar_store(&jar, U("https://h.com/"), str8_lit("m=1; Max-Age=0"), now);
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://h.com/"), now), "m=1"));

  // A past Expires is not stored.
  cookie_jar_store(&jar, U("https://h.com/"),
                   str8_lit("e=1; Expires=Thu, 01 Jan 1970 00:00:01 GMT"), now);
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://h.com/"), now), "e=1"));

  // Max-Age overrides a past Expires (Max-Age wins) -> stored.
  cookie_jar_store(
      &jar, U("https://h.com/"),
      str8_lit("f=1; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=50"), now);
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://h.com/"), now), "f=1"));
}

internal void test_order_and_replace(Arena *a) {
  CookieJar jar;
  cookie_jar_init(&jar, a);
  cookie_jar_store(&jar, U("https://h.com/"), str8_lit("root=1; Path=/"), 1000);
  cookie_jar_store(&jar, U("https://h.com/a/b"),
                   str8_lit("deep=2; Path=/a/b"), 1000);
  String8 hdr = cookie_jar_cookie_header(&jar, a, U("https://h.com/a/b/c"), 1000);
  CHECK(has(hdr, "deep=2") && has(hdr, "root=1"));
  // Longest path first: deep (/a/b) before root (/).
  CHECK(str8_find(hdr, str8_lit("deep=2")) < str8_find(hdr, str8_lit("root=1")));

  // Replacement: same (name,domain,path) -> single cookie, new value.
  cookie_jar_store(&jar, U("https://h.com/"), str8_lit("r=1; Path=/"), 1000);
  cookie_jar_store(&jar, U("https://h.com/"), str8_lit("r=2; Path=/"), 1000);
  String8 h2 = cookie_jar_cookie_header(&jar, a, U("https://h.com/"), 1000);
  CHECK(has(h2, "r=2") && !has(h2, "r=1"));
}

// Public-suffix rejection: a Domain attribute naming a public suffix would
// blanket every site under it; only the suffix host itself may set it, and
// then it degrades to host-only (see cookie_jar_store + core/psl.h).
internal void test_public_suffix(Arena *a) {
  CookieJar jar;
  cookie_jar_init(&jar, a);

  // evil.co.uk cannot set Domain=co.uk (two-label public suffix)...
  cookie_jar_store(&jar, U("https://evil.co.uk/"),
                   str8_lit("evil=1; Domain=co.uk"), 1000);
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://victim.co.uk/"), 1000),
             "evil=1"));
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://evil.co.uk/"), 1000),
             "evil=1"));
  // ...and a PRIVATE-section suffix is rejected the same way.
  cookie_jar_store(&jar, U("https://evil.github.io/"),
                   str8_lit("gh=1; Domain=github.io"), 1000);
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://victim.github.io/"), 1000),
             "gh=1"));

  // The registrable domain itself is fine from a subdomain.
  cookie_jar_store(&jar, U("https://sub.example.co.uk/"),
                   str8_lit("ok=1; Domain=example.co.uk"), 1000);
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://other.example.co.uk/"), 1000),
            "ok=1"));

  // IP-address hosts domain-match only themselves (RFC 6265 5.1.3): a Domain
  // shaved to a host suffix must be rejected, the identical one degrades to
  // host-only.
  cookie_jar_store(&jar, U("https://127.0.0.1/"),
                   str8_lit("ip=1; Domain=0.0.1"), 1000);
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://127.0.0.1/"), 1000),
             "ip=1"));
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://10.0.0.1/"), 1000),
             "ip=1"));
  cookie_jar_store(&jar, U("https://127.0.0.1/"),
                   str8_lit("ipself=1; Domain=127.0.0.1"), 1000);
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://127.0.0.1/"), 1000),
            "ipself=1"));

  // A raw-IDN (non-ASCII) Domain attribute fails closed — the PSL table is
  // ASCII/punycode, so unconverted bytes could bypass the suffix guard.
  cookie_jar_store(&jar, U("https://evil.example/"),
                   str8_lit("idn=1; Domain=ÑÑ"), 1000);
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://evil.example/"), 1000),
             "idn=1"));

  // The suffix host itself may use Domain=<itself>, degraded to host-only.
  cookie_jar_store(&jar, U("https://github.io/"),
                   str8_lit("self=1; Domain=github.io"), 1000);
  CHECK(has(cookie_jar_cookie_header(&jar, a, U("https://github.io/"), 1000),
            "self=1"));
  CHECK(!has(cookie_jar_cookie_header(&jar, a, U("https://user.github.io/"), 1000),
             "self=1"));  // host-only: never sent to subdomains
}

int main(void) {
  Arena *a = arena_alloc();
  test_http_date();
  test_scope(a);
  test_public_suffix(a);
  test_path(a);
  test_secure(a);
  test_expiry(a);
  test_order_and_replace(a);
  arena_release(a);
  fprintf(stderr, "[cookie_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
