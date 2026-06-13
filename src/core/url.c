#include "core/url.h"

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
  String8 authority = str8((U8 *)auth, (U64)(ae - auth));

  // strip userinfo
  for (const char *c = auth; c < ae; ++c)
    if (*c == '@') {
      authority = str8((U8 *)(c + 1), (U64)(ae - (c + 1)));
      break;
    }
  r.authority = authority;

  // split host:port (handle IPv6 [..]:port)
  String8 host = authority;
  U16 port = r.https ? 443 : 80;
  const char *abeg = (const char *)authority.str;
  const char *aend = abeg + authority.size;
  if (authority.size && abeg[0] == '[') {
    const char *rb = 0;
    for (const char *c = abeg; c < aend; ++c)
      if (*c == ']') {
        rb = c;
        break;
      }
    if (rb) {
      host = str8((U8 *)(abeg + 1), (U64)(rb - (abeg + 1)));
      if (rb + 1 < aend && rb[1] == ':') {
        port = 0;
        for (const char *c = rb + 2; c < aend; ++c)
          if (*c >= '0' && *c <= '9') port = (U16)(port * 10 + (*c - '0'));
      }
    }
  } else {
    const char *colon = 0;
    for (const char *c = abeg; c < aend; ++c)
      if (*c == ':') colon = c;
    if (colon) {
      host = str8((U8 *)abeg, (U64)(colon - abeg));
      port = 0;
      for (const char *c = colon + 1; c < aend; ++c)
        if (*c >= '0' && *c <= '9') port = (U16)(port * 10 + (*c - '0'));
    }
  }
  r.host = host;
  r.port = port;

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
