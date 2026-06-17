#include "core/url.h"

// Parse a TCP port from the digits in [b, e). Returns 0..65535, -1 on a
// non-digit or on overflow (>65535), or `def` when the range is empty ("host:"
// -> the scheme default, as browsers treat a bare trailing colon).
internal S32 url_parse_port(const char *b, const char *e, U16 def) {
  if (b >= e) return (S32)def;
  U32 port = 0;
  for (const char *c = b; c < e; ++c) {
    if (*c < '0' || *c > '9') return -1;  // non-digit -> reject (don't skip)
    port = port * 10 + (U32)(*c - '0');
    if (port > 65535) return -1;  // overflow -> reject (don't wrap)
  }
  return (S32)port;
}

ParsedUrl url_parse(String8 u) {
  ParsedUrl r;
  MemoryZeroStruct(&r);
  const char *p = (const char *)u.str;
  const char *end = p + u.size;

  // scheme://
  const char *sep = 0;
  for (const char *c = p; c + 2 < end; ++c)
    if (c[0] == ':' && c[1] == '/' && c[2] == '/') {
      sep = c;
      break;
    }
  if (!sep) return r;
  r.scheme = str8((U8 *)p, (U64)(sep - p));
  if (str8_match_ci(r.scheme, str8_lit("https")))
    r.https = 1;
  else if (str8_match_ci(r.scheme, str8_lit("http")))
    r.https = 0;
  else
    return r;

  // A fragment is client-side only (a browser never sends it): truncate the
  // URL at the first '#' so it can't leak into the authority or request path.
  for (const char *c = sep + 3; c < end; ++c)
    if (*c == '#') {
      end = c;
      break;
    }

  const char *auth = sep + 3;
  const char *ae = auth;  // authority ends at '/', '?' or end
  while (ae < end && *ae != '/' && *ae != '?') ++ae;

  // Reject control chars / spaces in the authority and CR/LF/NUL in the path.
  // A host or request-target with these is malformed; rejecting fails closed
  // against Host-header / request-line injection via a crafted URL (e.g. a
  // redirect Location). Browsers strip CR/LF/TAB; failing the parse is safer.
  for (const char *c = auth; c < ae; ++c)
    if ((U8)*c <= 0x20 || (U8)*c == 0x7f) return r;
  for (const char *c = ae; c < end; ++c)
    if (*c == '\r' || *c == '\n' || *c == '\0') return r;

  String8 authority = str8((U8 *)auth, (U64)(ae - auth));

  // Strip userinfo at the LAST '@' — '@' is not valid unescaped in a host, so
  // the rightmost one delimits userinfo from the host (what browsers use; the
  // first '@' would mis-host `a@b@evil.com`).
  for (const char *c = ae; c-- > auth;)
    if (*c == '@') {
      authority = str8((U8 *)(c + 1), (U64)(ae - (c + 1)));
      break;
    }
  r.authority = authority;

  // split host:port (handle IPv6 [..]:port)
  String8 host = authority;
  S32 port = r.https ? 443 : 80;
  const char *abeg = (const char *)authority.str;
  const char *aend = abeg + authority.size;
  if (authority.size && abeg[0] == '[') {
    const char *rb = 0;
    for (const char *c = abeg; c < aend; ++c)
      if (*c == ']') {
        rb = c;
        break;
      }
    if (!rb) return r;  // unterminated IPv6 literal
    host = str8((U8 *)(abeg + 1), (U64)(rb - (abeg + 1)));
    if (rb + 1 < aend) {
      if (rb[1] != ':') return r;  // garbage between ']' and the port
      port = url_parse_port(rb + 2, aend, (U16)port);
    }
  } else {
    const char *colon = 0;
    for (const char *c = abeg; c < aend; ++c)
      if (*c == ':') colon = c;
    if (colon) {
      host = str8((U8 *)abeg, (U64)(colon - abeg));
      port = url_parse_port(colon + 1, aend, (U16)port);
    }
  }
  if (port < 0 || host.size == 0) return r;  // invalid port / empty host
  r.host = host;
  r.port = (U16)port;

  r.path = (ae < end) ? str8((U8 *)ae, (U64)(end - ae)) : str8_lit("/");
  if (r.path.size == 0) r.path = str8_lit("/");
  r.ok = 1;
  return r;
}

String8 url_resolve(Arena *arena, String8 base, String8 ref) {
  // Absolute reference (has its own scheme://) -> use as-is.
  if (url_parse(ref).ok) return push_str8_copy(arena, ref);
  ParsedUrl b = url_parse(base);
  if (!b.ok) return push_str8_copy(arena, ref);  // can't resolve; best effort

  // Protocol-relative: "//host/path" -> inherit the base scheme.
  if (str8_starts_with(ref, str8_lit("//")))
    return push_str8f(arena, STR8_Fmt ":" STR8_Fmt, STR8_Arg(b.scheme),
                      STR8_Arg(ref));
  // Absolute-path: "/path" -> base scheme://authority + ref.
  if (ref.size && ref.str[0] == '/')
    return push_str8f(arena, STR8_Fmt "://" STR8_Fmt STR8_Fmt,
                      STR8_Arg(b.scheme), STR8_Arg(b.authority), STR8_Arg(ref));

  // Relative: base scheme://authority + base-dir + ref, where base-dir is the
  // base path up to (and including) the last '/', with any query stripped.
  String8 basepath = b.path;
  U64 q;
  if (str8_index_of(basepath, '?', &q)) basepath = str8_prefix(basepath, q);
  String8 dir = str8_chop_last_slash(basepath);  // part before the last '/'
  return push_str8f(arena, STR8_Fmt "://" STR8_Fmt STR8_Fmt "/" STR8_Fmt,
                    STR8_Arg(b.scheme), STR8_Arg(b.authority), STR8_Arg(dir),
                    STR8_Arg(ref));
}

String8 url_encode_component(Arena *arena, String8 s) {
  // RFC 3986 percent-encoding: pass the unreserved set (ALPHA / DIGIT / -._~)
  // through, %XX-escape every other byte (upper-hex). Worst case 3x the input.
  static const char hex[] = "0123456789ABCDEF";
  U8 *out = push_array_no_zero(arena, U8, s.size * 3);
  U64 n = 0;
  for (U64 i = 0; i < s.size; ++i) {
    U8 c = s.str[i];
    if (char_is_alnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out[n++] = c;
    } else {
      out[n++] = '%';
      out[n++] = (U8)hex[c >> 4];
      out[n++] = (U8)hex[c & 0xf];
    }
  }
  return str8(out, n);
}
