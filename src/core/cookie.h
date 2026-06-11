// CookieJar — an in-memory RFC 6265 cookie store. Parses Set-Cookie response
// headers, keeps cookies with their domain/path/expiry/secure scope, and emits
// the matching Cookie request-header value for a URL (domain-match + path-match +
// secure + not-expired, longest-path-first). Arena-backed; the caller supplies
// "now" as epoch seconds (wall clock) so the jar has no time dependency itself.
#ifndef HOLYTLS_COOKIE_H
#define HOLYTLS_COOKIE_H

#include "base/arena.h"
#include "base/string8.h"
#include "core/url.h"  // ParsedUrl

typedef struct Cookie Cookie;
struct Cookie {
  String8 name;       // arena-owned copies (Set-Cookie views are transient)
  String8 value;
  String8 domain;     // no leading dot
  String8 path;
  U64 expires_epoch;  // 0 = session cookie (no expiry)
  B32 host_only;      // no Domain attribute -> exact-host match only
  B32 secure;         // send only over https
  B32 http_only;      // stored; informational at this (non-JS) layer
  U8 same_site;       // 0=unset 1=Lax 2=Strict 3=None (stored, not enforced)
};

typedef struct CookieJar CookieJar;
struct CookieJar {
  Cookie *v;        // growable array in `arena` (realloc-double like HeaderList)
  U64 count;
  U64 cap;
  U64 max_cookies;  // advisory total cap (RFC 6265 §6.1)
  Arena *arena;     // owns all cookie bytes
};

void cookie_jar_init(CookieJar *jar, Arena *arena);

// Parse ONE Set-Cookie header value for `request` and store/replace/delete.
// now_epoch = wall-clock seconds (time(NULL)). Silently ignores malformed input,
// a Domain that doesn't domain-match the request host, or a bare-TLD Domain.
void cookie_jar_store(CookieJar *jar, ParsedUrl request,
                      String8 set_cookie_value, U64 now_epoch);

// Insert (or replace, by name+domain+path) a fully-formed cookie. Strings are
// copied into the jar arena. Subject to max_cookies. Used by session restore to
// re-seed a jar from already-parsed cookies (and by cookie_jar_store internally).
void cookie_jar_put(CookieJar *jar, String8 name, String8 value, String8 domain,
                    String8 path, U64 expires_epoch, B32 host_only, B32 secure,
                    B32 http_only, U8 same_site);

// Build the "n1=v1; n2=v2" Cookie header value for `request` into `out` (longest
// path-match first). Returns str8_zero() when nothing matches.
String8 cookie_jar_cookie_header(CookieJar *jar, Arena *out, ParsedUrl request,
                                 U64 now_epoch);

// Drop expired cookies (expires_epoch != 0 && <= now). Called by store/header.
void cookie_jar_evict_expired(CookieJar *jar, U64 now_epoch);

// (exposed for cookie_test) Parse an HTTP-date (RFC 6265 §5.1.1 forms) into epoch
// seconds; 0 on failure. TZ-independent (no mktime/timegm).
U64 http_date_parse(String8 s);

#endif  // HOLYTLS_COOKIE_H
