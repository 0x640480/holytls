// Minimal URL parser for http(s)://host[:port][/path][?query]. Returns String8
// views into the input, which must outlive the result.
#ifndef HOLYTLS_URL_H
#define HOLYTLS_URL_H

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

typedef struct ParsedUrl ParsedUrl;
struct ParsedUrl {
  B32 ok;
  B32 https;
  String8 scheme;
  String8 host;       // no brackets for IPv6
  String8 authority;  // host[:port] as it should appear in :authority
  String8 path;       // includes query; defaults to "/"
  U16 port;
};

ParsedUrl url_parse(String8 u);

// Resolve a (possibly relative) reference (e.g. a Location header) against a base
// URL into an absolute URL, arena-allocated. Handles absolute, protocol-relative
// (//host), absolute-path (/path), and simple relative refs (no ../ normalization).
String8 url_resolve(Arena *arena, String8 base, String8 ref);

#endif  // HOLYTLS_URL_H
