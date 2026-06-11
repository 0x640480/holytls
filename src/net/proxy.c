#include "net/proxy.h"

#include "base/base64.h"

// Copy a String8 into a fixed NUL-terminated char buffer, truncating silently at
// cap-1 (config fields have generous bounds; truncation only on absurd input).
internal void proxy_copy_field(char *dst, U64 cap, String8 s) {
  U64 n = s.size < cap - 1 ? s.size : cap - 1;
  MemoryCopy(dst, s.str, n);
  dst[n] = 0;
}

B32 proxy_parse(String8 url, ProxyConfig *out) {
  MemoryZeroStruct(out);
  S64 sep = str8_find(url, str8_lit("://"));
  if (sep < 0) return 0;
  String8 scheme = str8_prefix(url, (U64)sep);
  String8 rest = str8_skip(url, (U64)sep + 3);

  U16 default_port;
  if (str8_match(scheme, str8_lit("http"))) {
    out->type = ProxyType_Http;
    default_port = 80;
  } else if (str8_match(scheme, str8_lit("https"))) {
    out->type = ProxyType_Https;
    default_port = 443;
  } else if (str8_match(scheme, str8_lit("socks5")) ||
             str8_match(scheme, str8_lit("socks5h"))) {
    out->type = ProxyType_Socks5;
    default_port = 1080;
  } else {
    return 0;
  }

  // Strip any path/query — a proxy URL carries only an authority.
  U64 slash;
  if (str8_index_of(rest, '/', &slash)) rest = str8_prefix(rest, slash);

  // [user:pass@] — split on the LAST '@' so a '@' in the password is tolerated.
  U64 at;
  if (str8_rindex_of(rest, '@', &at)) {
    String8 userinfo = str8_prefix(rest, at);
    rest = str8_skip(rest, at + 1);
    U64 colon;
    if (str8_index_of(userinfo, ':', &colon)) {
      proxy_copy_field(out->user, sizeof out->user, str8_prefix(userinfo, colon));
      proxy_copy_field(out->pass, sizeof out->pass, str8_skip(userinfo, colon + 1));
    } else {
      proxy_copy_field(out->user, sizeof out->user, userinfo);
    }
  }

  // host[:port], with IPv6 literals bracketed as [::1].
  String8 host = rest;
  U16 port = default_port;
  if (rest.size && rest.str[0] == '[') {
    U64 rb;
    if (!str8_index_of(rest, ']', &rb)) return 0;
    host = str8_substr(rest, 1, rb);
    String8 after = str8_skip(rest, rb + 1);  // ":port" or empty
    if (after.size && after.str[0] == ':') port = (U16)str8_to_u64(str8_skip(after, 1));
  } else {
    U64 colon;
    if (str8_index_of(rest, ':', &colon)) {
      host = str8_prefix(rest, colon);
      port = (U16)str8_to_u64(str8_skip(rest, colon + 1));
    }
  }
  if (host.size == 0 || port == 0) return 0;
  proxy_copy_field(out->host, sizeof out->host, host);
  out->port = port;
  return 1;
}

String8 proxy_to_url(Arena *arena, const ProxyConfig *p) {
  const char *scheme = p->type == ProxyType_Http     ? "http"
                       : p->type == ProxyType_Https  ? "https"
                       : p->type == ProxyType_Socks5 ? "socks5"
                                                     : 0;
  if (!scheme) return str8_zero();  // ProxyType_None == direct
  B32 v6 = 0;                       // bracket an IPv6 literal host
  for (const char *h = p->host; *h; ++h)
    if (*h == ':') {
      v6 = 1;
      break;
    }
  const char *lb = v6 ? "[" : "", *rb = v6 ? "]" : "";
  if (p->user[0])
    return push_str8f(arena, "%s://%s:%s@%s%s%s:%u", scheme, p->user, p->pass,
                      lb, p->host, rb, (unsigned)p->port);
  return push_str8f(arena, "%s://%s%s%s:%u", scheme, lb, p->host, rb,
                    (unsigned)p->port);
}

// "host:port", bracketing an IPv6 literal target ("[::1]:443").
internal String8 proxy_hostport(Arena *arena, String8 host, U16 port) {
  U64 c;
  if (str8_index_of(host, ':', &c))
    return push_str8f(arena, "[" STR8_Fmt "]:%u", STR8_Arg(host), (unsigned)port);
  return push_str8f(arena, STR8_Fmt ":%u", STR8_Arg(host), (unsigned)port);
}

String8 proxy_http_connect_request(Arena *arena, const ProxyConfig *p,
                                   String8 target_host, U16 target_port) {
  String8 hp = proxy_hostport(arena, target_host, target_port);
  if (p->user[0]) {
    String8 cred = push_str8f(arena, "%s:%s", p->user, p->pass);
    String8 b64 = base64_encode(arena, cred);
    return push_str8f(arena,
                      "CONNECT " STR8_Fmt " HTTP/1.1\r\nHost: " STR8_Fmt
                      "\r\nProxy-Authorization: Basic " STR8_Fmt "\r\n\r\n",
                      STR8_Arg(hp), STR8_Arg(hp), STR8_Arg(b64));
  }
  return push_str8f(arena,
                    "CONNECT " STR8_Fmt " HTTP/1.1\r\nHost: " STR8_Fmt "\r\n\r\n",
                    STR8_Arg(hp), STR8_Arg(hp));
}

U64 proxy_http_response_status(const U8 *buf, U64 len, B32 *complete,
                               int *status) {
  *complete = 0;
  *status = 0;
  // Find the end of the status/headers block.
  U64 end = 0;
  for (U64 i = 0; i + 4 <= len; ++i)
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
        buf[i + 3] == '\n') {
      end = i + 4;
      break;
    }
  if (end == 0) return 0;
  *complete = 1;
  // Status line: "HTTP/1.x SP NNN SP reason". Parse the code after the 1st space.
  String8 line = str8((U8 *)buf, end);
  U64 sp;
  if (str8_index_of(line, ' ', &sp))
    *status = (int)str8_to_u64(str8_trim_left(str8_skip(line, sp + 1)));
  return end;
}

//- SOCKS5 -------------------------------------------------------------------

U64 proxy_socks5_greeting(const ProxyConfig *p, U8 *out, U64 cap) {
  B32 auth = p->user[0] != 0;
  U64 need = auth ? 4 : 3;
  if (cap < need) return 0;
  out[0] = 0x05;
  if (auth) {
    out[1] = 0x02;
    out[2] = 0x00;  // no-auth
    out[3] = 0x02;  // username/password
  } else {
    out[1] = 0x01;
    out[2] = 0x00;
  }
  return need;
}

B32 proxy_socks5_parse_method(const U8 *buf, U64 len, U8 *method) {
  if (len < 2) return 0;
  *method = buf[1];
  return 1;
}

U64 proxy_socks5_userpass(const ProxyConfig *p, U8 *out, U64 cap) {
  U64 ulen = 0, plen = 0;
  while (p->user[ulen]) ++ulen;
  while (p->pass[plen]) ++plen;
  if (ulen > 255 || plen > 255) return 0;
  U64 need = 3 + ulen + plen;
  if (cap < need) return 0;
  U64 o = 0;
  out[o++] = 0x01;  // sub-negotiation version
  out[o++] = (U8)ulen;
  MemoryCopy(out + o, p->user, ulen);
  o += ulen;
  out[o++] = (U8)plen;
  MemoryCopy(out + o, p->pass, plen);
  o += plen;
  return o;
}

B32 proxy_socks5_parse_userpass_reply(const U8 *buf, U64 len, B32 *ok) {
  if (len < 2) return 0;
  *ok = (buf[1] == 0x00);
  return 1;
}

U64 proxy_socks5_connect_request(String8 target_host, U16 target_port, U8 *out,
                                 U64 cap) {
  if (target_host.size > 255) return 0;
  U64 need = 4 + 1 + target_host.size + 2;
  if (cap < need) return 0;
  U64 o = 0;
  out[o++] = 0x05;  // VER
  out[o++] = 0x01;  // CMD = CONNECT
  out[o++] = 0x00;  // RSV
  out[o++] = 0x03;  // ATYP = DOMAINNAME (proxy resolves)
  out[o++] = (U8)target_host.size;
  MemoryCopy(out + o, target_host.str, target_host.size);
  o += target_host.size;
  out[o++] = (U8)(target_port >> 8);
  out[o++] = (U8)(target_port & 0xff);
  return o;
}

U64 proxy_socks5_parse_reply(const U8 *buf, U64 len, B32 *complete, B32 *ok,
                             U8 *bnd_atyp, const U8 **bnd_addr, U16 *bnd_port) {
  *complete = 0;
  *ok = 0;
  if (len < 4) return 0;  // VER REP RSV ATYP
  U64 addr_len;
  switch (buf[3]) {
    case 0x01: addr_len = 4; break;             // IPv4
    case 0x04: addr_len = 16; break;            // IPv6
    case 0x03:                                  // DOMAINNAME
      if (len < 5) return 0;
      addr_len = 1 + buf[4];
      break;
    default: return 0;  // malformed ATYP
  }
  U64 total = 4 + addr_len + 2;  // + BND.PORT
  if (len < total) return 0;
  *complete = 1;
  *ok = (buf[1] == 0x00);  // REP == succeeded
  if (bnd_atyp) *bnd_atyp = buf[3];
  if (bnd_addr) *bnd_addr = buf + 4;
  if (bnd_port) *bnd_port = (U16)((buf[total - 2] << 8) | buf[total - 1]);
  return total;
}

//- SOCKS5 UDP ASSOCIATE -----------------------------------------------------

U64 proxy_socks5_udp_associate_request(U8 *out, U64 cap) {
  if (cap < 10) return 0;
  out[0] = 0x05;  // VER
  out[1] = 0x03;  // CMD = UDP ASSOCIATE
  out[2] = 0x00;  // RSV
  out[3] = 0x01;  // ATYP = IPv4
  for (int i = 4; i < 10; ++i) out[i] = 0x00;  // DST.ADDR 0.0.0.0 + DST.PORT 0
  return 10;
}

U64 proxy_socks5_udp_request_header(U8 *out, U64 cap, U8 atyp, const U8 *addr,
                                    U64 addrlen, U16 port) {
  U64 need = 4 + addrlen + 2;
  if (cap < need || (atyp != 0x01 && atyp != 0x04)) return 0;
  out[0] = 0x00;  // RSV
  out[1] = 0x00;  // RSV
  out[2] = 0x00;  // FRAG (0 = standalone, no fragmentation)
  out[3] = atyp;
  MemoryCopy(out + 4, addr, addrlen);
  out[4 + addrlen] = (U8)(port >> 8);
  out[4 + addrlen + 1] = (U8)(port & 0xff);
  return need;
}

U64 proxy_socks5_udp_header_len(const U8 *buf, U64 len) {
  if (len < 4) return 0;  // RSV RSV FRAG ATYP
  U64 addr_len;
  switch (buf[3]) {
    case 0x01: addr_len = 4; break;   // IPv4
    case 0x04: addr_len = 16; break;  // IPv6
    case 0x03:                        // DOMAINNAME
      if (len < 5) return 0;
      addr_len = 1 + buf[4];
      break;
    default: return 0;
  }
  U64 total = 4 + addr_len + 2;  // + port
  return len < total ? 0 : total;
}
