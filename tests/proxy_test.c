// Offline proxy tests: URL parsing (schemes, auth, IPv6, defaults) and the
// HTTP CONNECT + SOCKS5 wire framing against fixed byte vectors.
#include "net/proxy.h"

#include <stdio.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/base64.h"
#include "base/string8.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal B32 cfg_is(const char *url, ProxyType type, const char *host, U16 port,
                    const char *user, const char *pass) {
  ProxyConfig p;
  if (!proxy_parse(str8_cstring(url), &p)) return 0;
  return p.type == type && strcmp(p.host, host) == 0 && p.port == port &&
         strcmp(p.user, user) == 0 && strcmp(p.pass, pass) == 0;
}

internal void test_parse(void) {
  CHECK(cfg_is("http://proxy.example:8080", ProxyType_Http, "proxy.example",
               8080, "", ""));
  CHECK(cfg_is("https://proxy.example:3128", ProxyType_Https, "proxy.example",
               3128, "", ""));
  CHECK(cfg_is("socks5://proxy.example:1080", ProxyType_Socks5, "proxy.example",
               1080, "", ""));
  CHECK(cfg_is("socks5h://proxy.example", ProxyType_Socks5, "proxy.example",
               1080, "", ""));  // proxy-side DNS; default port

  // Default ports per scheme when omitted.
  CHECK(cfg_is("http://h", ProxyType_Http, "h", 80, "", ""));
  CHECK(cfg_is("https://h", ProxyType_Https, "h", 443, "", ""));

  // user:pass@ auth.
  CHECK(cfg_is("http://user:pass@h:8080", ProxyType_Http, "h", 8080, "user",
               "pass"));
  CHECK(cfg_is("socks5://bob:s3cret@h:1080", ProxyType_Socks5, "h", 1080, "bob",
               "s3cret"));
  CHECK(cfg_is("http://user@h:8080", ProxyType_Http, "h", 8080, "user", ""));
  // '@' inside the password (split on the LAST '@').
  CHECK(cfg_is("http://u:p@ss@h:1", ProxyType_Http, "h", 1, "u", "p@ss"));

  // IPv6 host, bracketed.
  CHECK(cfg_is("http://[::1]:8080", ProxyType_Http, "::1", 8080, "", ""));
  CHECK(cfg_is("socks5://[2001:db8::1]:1080", ProxyType_Socks5, "2001:db8::1",
               1080, "", ""));

  // A trailing path/slash is ignored (authority only).
  CHECK(cfg_is("http://h:8080/", ProxyType_Http, "h", 8080, "", ""));

  // Rejections.
  ProxyConfig p;
  CHECK(!proxy_parse(str8_cstring("ftp://h:21"), &p));  // unknown scheme
  CHECK(!proxy_parse(str8_cstring("h:8080"), &p));      // no scheme
  CHECK(!proxy_parse(str8_cstring("http://"), &p));     // empty host
  CHECK(!proxy_parse(str8_cstring("http://h:0"), &p));  // port 0
}

internal void test_http_connect(Arena *a) {
  ProxyConfig p;
  MemoryZeroStruct(&p);
  p.type = ProxyType_Http;

  String8 r = proxy_http_connect_request(a, &p, str8_lit("example.com"), 443);
  CHECK(str8_match(r, str8_lit("CONNECT example.com:443 HTTP/1.1\r\n"
                               "Host: example.com:443\r\n\r\n")));

  // IPv6 target is bracketed in the request-target.
  String8 r6 = proxy_http_connect_request(a, &p, str8_lit("::1"), 8443);
  CHECK(str8_match(r6, str8_lit("CONNECT [::1]:8443 HTTP/1.1\r\n"
                                "Host: [::1]:8443\r\n\r\n")));

  // With Basic auth.
  strcpy(p.user, "user");
  strcpy(p.pass, "pass");
  String8 ra = proxy_http_connect_request(a, &p, str8_lit("h"), 443);
  CHECK(str8_contains(ra,
                      str8_lit("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n")));
  CHECK(str8_ends_with(ra, str8_lit("\r\n\r\n")));
}

internal void resp_status(const char *s, B32 *complete, int *status, U64 *n) {
  *n = proxy_http_response_status((const U8 *)s, strlen(s), complete, status);
}
internal void test_http_response(void) {
  B32 complete;
  int status;
  U64 n;
  const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
  resp_status(ok, &complete, &status, &n);
  CHECK(complete && status == 200 && n == strlen(ok));

  resp_status("HTTP/1.0 407 Proxy Auth Required\r\n\r\n", &complete, &status,
              &n);
  CHECK(complete && status == 407);

  resp_status("HTTP/1.1 502 Bad Gateway\r\n\r\n", &complete, &status, &n);
  CHECK(complete && status == 502);

  // Incomplete (no terminator yet).
  resp_status("HTTP/1.1 200 OK\r\n", &complete, &status, &n);
  CHECK(!complete && status == 0);
}

internal B32 bytes_eq(const U8 *got, U64 gotlen, const U8 *exp, U64 explen) {
  if (gotlen != explen) return 0;
  return memcmp(got, exp, explen) == 0;
}

internal void test_socks5(void) {
  U8 buf[600];

  // Greeting: no creds -> offer no-auth only.
  ProxyConfig p;
  MemoryZeroStruct(&p);
  p.type = ProxyType_Socks5;
  U64 m = proxy_socks5_greeting(&p, buf, sizeof buf);
  CHECK(bytes_eq(buf, m, (const U8[]){0x05, 0x01, 0x00}, 3));

  // Greeting: with creds -> offer no-auth + user/pass.
  strcpy(p.user, "u");
  strcpy(p.pass, "pw");
  m = proxy_socks5_greeting(&p, buf, sizeof buf);
  CHECK(bytes_eq(buf, m, (const U8[]){0x05, 0x02, 0x00, 0x02}, 4));

  // Method selection parse.
  U8 method = 0;
  CHECK(proxy_socks5_parse_method((const U8[]){0x05, 0x02}, 2, &method) &&
        method == 0x02);
  CHECK(!proxy_socks5_parse_method((const U8[]){0x05}, 1, &method));  // short

  // Username/password sub-negotiation: 01 ulen user plen pass.
  m = proxy_socks5_userpass(&p, buf, sizeof buf);
  CHECK(bytes_eq(buf, m, (const U8[]){0x01, 0x01, 'u', 0x02, 'p', 'w'}, 6));
  B32 ok = 0;
  CHECK(proxy_socks5_parse_userpass_reply((const U8[]){0x01, 0x00}, 2, &ok) &&
        ok);
  CHECK(proxy_socks5_parse_userpass_reply((const U8[]){0x01, 0x01}, 2, &ok) &&
        !ok);

  // CONNECT request: 05 01 00 03 len host port_hi port_lo.
  m = proxy_socks5_connect_request(str8_lit("ex.com"), 443, buf, sizeof buf);
  CHECK(bytes_eq(buf, m,
                 (const U8[]){0x05, 0x01, 0x00, 0x03, 6, 'e', 'x', '.', 'c',
                              'o', 'm', 0x01, 0xBB},
                 13));

  // CONNECT reply (IPv4 bound addr) -> success, length 4+4+2 = 10.
  B32 complete = 0;
  m = proxy_socks5_parse_reply(
      (const U8[]){0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00}, 10,
      &complete, &ok, 0, 0, 0);
  CHECK(complete && ok && m == 10);

  // CONNECT reply (DOMAINNAME bound addr, len 3) -> 4+1+3+2 = 10.
  m = proxy_socks5_parse_reply(
      (const U8[]){0x05, 0x00, 0x00, 0x03, 3, 'a', 'b', 'c', 0x00, 0x00}, 10,
      &complete, &ok, 0, 0, 0);
  CHECK(complete && ok && m == 10);

  // Failure reply (REP != 0).
  m = proxy_socks5_parse_reply(
      (const U8[]){0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, 10, &complete,
      &ok, 0, 0, 0);
  CHECK(complete && !ok);

  // Partial reply -> not complete.
  proxy_socks5_parse_reply((const U8[]){0x05, 0x00, 0x00, 0x01, 0}, 5,
                           &complete, &ok, 0, 0, 0);
  CHECK(!complete);
}

internal void test_socks5_udp(void) {
  U8 buf[64];

  // UDP ASSOCIATE request: 05 03 00 01 0.0.0.0 :0.
  U64 m = proxy_socks5_udp_associate_request(buf, sizeof buf);
  CHECK(bytes_eq(buf, m, (const U8[]){0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0},
                 10));

  // ASSOCIATE reply surfaces the bound relay endpoint (IPv4 1.2.3.4:5000).
  B32 complete = 0, ok = 0;
  U8 atyp = 0;
  const U8 *addr = 0;
  U16 port = 0;
  const U8 reply[] = {0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x13, 0x88};  // :5000
  m = proxy_socks5_parse_reply(reply, sizeof reply, &complete, &ok, &atyp,
                               &addr, &port);
  CHECK(complete && ok && m == 10 && atyp == 0x01 && port == 5000);
  CHECK(addr && addr[0] == 1 && addr[1] == 2 && addr[2] == 3 && addr[3] == 4);

  // Per-datagram UDP request header (IPv4 9.8.7.6:443).
  const U8 ip[4] = {9, 8, 7, 6};
  m = proxy_socks5_udp_request_header(buf, sizeof buf, 0x01, ip, 4, 443);
  CHECK(bytes_eq(buf, m,
                 (const U8[]){0x00, 0x00, 0x00, 0x01, 9, 8, 7, 6, 0x01, 0xBB},
                 10));

  // Inbound header length parsing for each ATYP (incl. malformed/short).
  CHECK(proxy_socks5_udp_header_len(
            (const U8[]){0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0}, 10) == 10);
  const U8 v6[] = {0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0,    0, 0, 0, 0, 0, 0, 0};  // 4 + 16 + 2 = 22
  CHECK(proxy_socks5_udp_header_len(v6, sizeof v6) == 22);
  CHECK(proxy_socks5_udp_header_len(
            (const U8[]){0, 0, 0, 0x03, 3, 'a', 'b', 'c', 0, 0},
            10) == 10);  // domain len 3 -> 4+1+3+2
  CHECK(proxy_socks5_udp_header_len((const U8[]){0, 0, 0, 0x01, 0}, 5) ==
        0);  // short
}

internal B32 url_roundtrips(Arena *a, const char *url) {
  ProxyConfig p;
  if (!proxy_parse(str8_cstring(url), &p)) return 0;
  return str8_match(proxy_to_url(a, &p), str8_cstring(url));
}
internal void test_to_url(Arena *a) {
  // Canonical forms (explicit port) round-trip through parse -> to_url.
  CHECK(url_roundtrips(a, "http://h:8080"));
  CHECK(url_roundtrips(a, "https://h:3128"));
  CHECK(url_roundtrips(a, "socks5://h:1080"));
  CHECK(url_roundtrips(a, "http://user:pass@h:8080"));
  CHECK(url_roundtrips(a, "http://[::1]:8080"));  // IPv6 host re-bracketed
  ProxyConfig none;
  MemoryZeroStruct(&none);
  CHECK(proxy_to_url(a, &none).size == 0);  // direct -> empty
}

int main(void) {
  Arena *a = arena_alloc();
  test_parse();
  test_http_connect(a);
  test_http_response();
  test_socks5();
  test_socks5_udp();
  test_to_url(a);
  arena_release(a);
  fprintf(stderr, "[proxy_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
