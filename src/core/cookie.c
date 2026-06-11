#include "core/cookie.h"

#include "core/psl.h"

#include "base/base.h"
#include "base/u8buf.h"

//- HTTP-date (RFC 6265 §5.1.1: tokenize, then pick day/month/year/time heuristically)
internal const char *k_months[12] = {"jan", "feb", "mar", "apr", "may", "jun",
                                     "jul", "aug", "sep", "oct", "nov", "dec"};

internal int cookie_month_of(String8 t) {
  if (t.size < 3) return 0;
  for (int i = 0; i < 12; ++i)
    if (char_to_lower(t.str[0]) == k_months[i][0] &&
        char_to_lower(t.str[1]) == k_months[i][1] &&
        char_to_lower(t.str[2]) == k_months[i][2])
      return i + 1;
  return 0;
}

internal B32 cookie_all_digits(String8 t) {
  if (t.size == 0) return 0;
  for (U64 i = 0; i < t.size; ++i)
    if (!char_is_digit(t.str[i])) return 0;
  return 1;
}

// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
// days_from_civil — TZ-independent, no libc date functions).
internal S64 cookie_days_from_civil(S64 y, S64 m, S64 d) {
  y -= m <= 2;
  S64 era = (y >= 0 ? y : y - 399) / 400;
  S64 yoe = y - era * 400;
  S64 doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  S64 doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + doe - 719468;
}

U64 http_date_parse(String8 s) {
  B32 have_time = 0, have_day = 0, have_month = 0, have_year = 0;
  U64 hh = 0, mm = 0, ss = 0, day = 0, year = 0;
  int month = 0;
  U64 i = 0;
  while (i < s.size) {
    while (i < s.size && !(char_is_alnum(s.str[i]) || s.str[i] == ':')) i++;
    U64 start = i;
    while (i < s.size && (char_is_alnum(s.str[i]) || s.str[i] == ':')) i++;
    if (i == start) break;
    String8 tok = str8(s.str + start, i - start);

    if (!have_time) {
      int ncolon = 0;
      for (U64 k = 0; k < tok.size; ++k)
        if (tok.str[k] == ':') ncolon++;
      if (ncolon == 2) {
        String8 t = tok;
        String8 a = str8_chop_by_delim(&t, ':');
        String8 b = str8_chop_by_delim(&t, ':');
        if (cookie_all_digits(a) && cookie_all_digits(b) && cookie_all_digits(t)) {
          hh = str8_to_u64(a);
          mm = str8_to_u64(b);
          ss = str8_to_u64(t);
          have_time = 1;
          continue;
        }
      }
    }
    if (!have_day && tok.size <= 2 && cookie_all_digits(tok)) {
      day = str8_to_u64(tok);
      have_day = 1;
      continue;
    }
    if (!have_month) {
      int m = cookie_month_of(tok);
      if (m) {
        month = m;
        have_month = 1;
        continue;
      }
    }
    if (!have_year && tok.size >= 2 && tok.size <= 4 && cookie_all_digits(tok)) {
      year = str8_to_u64(tok);
      have_year = 1;
      continue;
    }
  }
  if (!(have_time && have_day && have_month && have_year)) return 0;
  if (year >= 70 && year <= 99)
    year += 1900;
  else if (year <= 69)
    year += 2000;
  if (day < 1 || day > 31 || month < 1 || month > 12 || hh > 23 || mm > 59 ||
      ss > 59 || year < 1601)
    return 0;
  S64 days = cookie_days_from_civil((S64)year, month, (S64)day);
  S64 epoch = days * 86400 + (S64)hh * 3600 + (S64)mm * 60 + (S64)ss;
  return epoch < 0 ? 0 : (U64)epoch;
}

//- matching (RFC 6265 §5.1.3 domain-match, §5.1.4 path-match)
// True for hosts that are IP literals (IPv4 dotted-quad or anything with a
// colon, i.e. IPv6). RFC 6265 5.1.3: an IP host domain-matches only itself.
internal B32 cookie_host_is_ip(String8 host) {
  B32 has_alpha = 0, has_colon = 0;
  for (U64 i = 0; i < host.size; ++i) {
    U8 ch = host.str[i];
    if (ch == ':') has_colon = 1;
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) has_alpha = 1;
  }
  if (has_colon) return 1;  // IPv6 literal (colons never appear in hostnames)
  if (has_alpha || host.size == 0) return 0;
  return 1;  // digits/dots only: dotted-quad
}

internal B32 cookie_domain_match(String8 host, String8 dom) {
  if (str8_match_ci(host, dom)) return 1;
  if (host.size <= dom.size) return 0;
  String8 tail = str8_skip(host, host.size - dom.size);
  if (!str8_match_ci(tail, dom)) return 0;
  return host.str[host.size - dom.size - 1] == '.';
}

internal String8 cookie_strip_query(String8 path) {
  U64 q;
  if (str8_index_of(path, '?', &q)) path = str8_prefix(path, q);
  return path;
}

internal B32 cookie_path_match(String8 req_path, String8 cp) {
  String8 req = cookie_strip_query(req_path);
  if (req.size == 0) req = str8_lit("/");
  if (str8_match(req, cp)) return 1;
  if (cp.size == 0 || req.size <= cp.size) return 0;
  if (!str8_starts_with(req, cp)) return 0;
  if (cp.str[cp.size - 1] == '/') return 1;
  return req.str[cp.size] == '/';
}

// Default-path (§5.1.4): request path up to (excluding) the last '/'; "/" if the
// only slash is the leading one.
internal String8 cookie_default_path(String8 path) {
  path = cookie_strip_query(path);
  if (path.size == 0 || path.str[0] != '/') return str8_lit("/");
  U64 last = 0;
  B32 found = 0;
  for (U64 i = 0; i < path.size; ++i)
    if (path.str[i] == '/') {
      last = i;
      found = 1;
    }
  if (!found || last == 0) return str8_lit("/");
  return str8_prefix(path, last);
}

//- jar storage
void cookie_jar_init(CookieJar *jar, Arena *arena) {
  MemoryZeroStruct(jar);
  jar->arena = arena;
  jar->max_cookies = 3000;
}

internal Cookie *cookie_jar_push(CookieJar *jar) {
  if (jar->count == jar->cap) {
    U64 ncap = jar->cap ? jar->cap * 2 : 16;
    Cookie *nv = push_array_no_zero(jar->arena, Cookie, ncap);
    if (jar->count) MemoryCopy(nv, jar->v, jar->count * sizeof(Cookie));
    jar->v = nv;
    jar->cap = ncap;
  }
  return &jar->v[jar->count++];
}

internal void cookie_jar_remove(CookieJar *jar, U64 i) {
  if (i + 1 < jar->count)
    MemoryMove(&jar->v[i], &jar->v[i + 1], (jar->count - i - 1) * sizeof(Cookie));
  jar->count--;
}

void cookie_jar_evict_expired(CookieJar *jar, U64 now) {
  for (U64 i = 0; i < jar->count;) {
    if (jar->v[i].expires_epoch != 0 && jar->v[i].expires_epoch <= now)
      cookie_jar_remove(jar, i);
    else
      ++i;
  }
}

internal S64 cookie_jar_find(CookieJar *jar, String8 name, String8 domain,
                             String8 path) {
  for (U64 i = 0; i < jar->count; ++i)
    if (str8_match(jar->v[i].name, name) &&
        str8_match_ci(jar->v[i].domain, domain) &&
        str8_match(jar->v[i].path, path))
      return (S64)i;
  return -1;
}

void cookie_jar_put(CookieJar *jar, String8 name, String8 value, String8 domain,
                    String8 path, U64 expires_epoch, B32 host_only, B32 secure,
                    B32 http_only, U8 same_site) {
  S64 existing = cookie_jar_find(jar, name, domain, path);
  Cookie *ck;
  if (existing >= 0) {
    ck = &jar->v[existing];
  } else {
    if (jar->count >= jar->max_cookies) return;  // cap: refuse new
    ck = cookie_jar_push(jar);
  }
  ck->name = push_str8_copy(jar->arena, name);
  ck->value = push_str8_copy(jar->arena, value);
  ck->domain = push_str8_copy(jar->arena, domain);
  ck->path = push_str8_copy(jar->arena, path);
  ck->expires_epoch = expires_epoch;
  ck->host_only = host_only;
  ck->secure = secure;
  ck->http_only = http_only;
  ck->same_site = same_site;
}

void cookie_jar_store(CookieJar *jar, ParsedUrl req, String8 sc, U64 now) {
  String8 av = sc;
  String8 nv = str8_trim(str8_chop_by_delim(&av, ';'));  // name=value pair
  U64 eq;
  if (!str8_index_of(nv, '=', &eq)) return;
  String8 name = str8_trim(str8_prefix(nv, eq));
  String8 value = str8_trim(str8_skip(nv, eq + 1));
  if (name.size == 0) return;

  String8 domain = req.host;
  B32 host_only = 1, secure = 0, http_only = 0, has_expiry = 0;
  B32 expired_now = 0, maxage_set = 0;
  U8 same_site = 0;
  U64 expires = 0;
  String8 path = cookie_default_path(req.path);

  while (av.size) {
    String8 attr = str8_trim(str8_chop_by_delim(&av, ';'));
    if (attr.size == 0) continue;
    String8 an = attr, val = str8_zero();
    U64 e2;
    if (str8_index_of(attr, '=', &e2)) {
      an = str8_trim(str8_prefix(attr, e2));
      val = str8_trim(str8_skip(attr, e2 + 1));
    }
    if (str8_match_ci(an, str8_lit("expires"))) {
      if (!maxage_set) {
        U64 ep = http_date_parse(val);
        if (ep) {
          expires = ep;
          has_expiry = 1;
          if (ep <= now) expired_now = 1;
        }
      }
    } else if (str8_match_ci(an, str8_lit("max-age"))) {
      maxage_set = 1;
      has_expiry = 1;
      B32 neg = val.size && val.str[0] == '-';
      U64 secs = str8_to_u64(neg ? str8_skip(val, 1) : val);
      if (neg || secs == 0) {
        expired_now = 1;
        expires = 1;
      } else {
        expires = now + secs;
        expired_now = 0;
      }
    } else if (str8_match_ci(an, str8_lit("domain"))) {
      String8 d = val;
      if (d.size && d.str[0] == '.') d = str8_skip(d, 1);
      if (d.size) {
        domain = d;
        host_only = 0;
      }
    } else if (str8_match_ci(an, str8_lit("path"))) {
      if (val.size && val.str[0] == '/') path = val;
    } else if (str8_match_ci(an, str8_lit("secure"))) {
      secure = 1;
    } else if (str8_match_ci(an, str8_lit("httponly"))) {
      http_only = 1;
    } else if (str8_match_ci(an, str8_lit("samesite"))) {
      same_site = str8_match_ci(val, str8_lit("strict"))  ? 2
                  : str8_match_ci(val, str8_lit("none"))  ? 3
                                                          : 1;
    }
  }

  if (!host_only) {  // a Domain attribute was given
    for (U64 i = 0; i < domain.size; ++i)
      if (domain.str[i] >= 0x80)
        return;  // raw-IDN bytes would bypass the ASCII/punycode PSL: fail closed
    if (cookie_host_is_ip(req.host)) {
      // An IP host domain-matches only itself (RFC 6265 5.1.3): accept the
      // identical Domain as a host-only cookie, reject anything else (e.g.
      // Domain=0.0.1 from 127.0.0.1 would leak to every *.0.0.1 host).
      if (!str8_match_ci(domain, req.host)) return;
      host_only = 1;
      domain = req.host;
    } else if (psl_is_public_suffix(domain)) {
      // A Domain equal to a public suffix (com, co.uk, github.io, ...) would
      // blanket every site registered under it. Accept it only from the
      // suffix host itself, degraded to a host-only cookie (RFC 6265bis
      // 5.5 step 6 / browser behavior); reject it from anyone else.
      if (!str8_match_ci(domain, req.host)) return;
      host_only = 1;
      domain = req.host;
    } else if (!cookie_domain_match(req.host, domain)) {
      return;  // Domain must cover the request host
    }
  }

  if (expired_now) {
    S64 existing = cookie_jar_find(jar, name, domain, path);
    if (existing >= 0) cookie_jar_remove(jar, (U64)existing);
    return;
  }
  cookie_jar_put(jar, name, value, domain, path, has_expiry ? expires : 0,
                 host_only, secure, http_only, same_site);
}

String8 cookie_jar_cookie_header(CookieJar *jar, Arena *out, ParsedUrl req,
                                 U64 now) {
  cookie_jar_evict_expired(jar, now);
  if (jar->count == 0) return str8_zero();

  Temp scr = scratch_begin(&out, 1);
  U64 *idx = push_array_no_zero(scr.arena, U64, jar->count);
  U64 n = 0;
  for (U64 i = 0; i < jar->count; ++i) {
    Cookie *c = &jar->v[i];
    B32 dm = c->host_only ? str8_match_ci(req.host, c->domain)
                          : cookie_domain_match(req.host, c->domain);
    if (!dm) continue;
    if (!cookie_path_match(req.path, c->path)) continue;
    if (c->secure && !req.https) continue;
    idx[n++] = i;
  }
  if (n == 0) {
    scratch_end(scr);
    return str8_zero();
  }
  // Longest path-match first (stable for equal lengths) — RFC 6265 §5.4.
  for (U64 a = 1; a < n; ++a) {
    U64 key = idx[a], b = a;
    while (b > 0 && jar->v[idx[b - 1]].path.size < jar->v[key].path.size) {
      idx[b] = idx[b - 1];
      --b;
    }
    idx[b] = key;
  }
  U8Buf buf;
  u8buf_init(&buf, out, 128);
  for (U64 k = 0; k < n; ++k) {
    Cookie *c = &jar->v[idx[k]];
    if (k) u8buf_append(&buf, (const U8 *)"; ", 2);
    u8buf_append(&buf, c->name.str, c->name.size);
    u8buf_push(&buf, '=');
    u8buf_append(&buf, c->value.str, c->value.size);
  }
  scratch_end(scr);
  return u8buf_str8(&buf);
}
