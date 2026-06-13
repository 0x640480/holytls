#include "core/sec_fetch.h"

#include "base/base.h"
#include "core/url.h"

// Registrable domain = the last two dot-labels (a.b.example.com ->
// example.com). Pragmatic eTLD+1 (no public-suffix list) — good enough for
// same-site coherence, imperfect for multi-label public suffixes like co.uk.
internal String8 sec_reg_domain(String8 host) {
  U64 dot2 = 0;
  int n = 0;
  for (U64 i = host.size; i > 0; --i)
    if (host.str[i - 1] == '.') {
      if (n == 0)
        n = 1;
      else {
        dot2 = i - 1;
        n = 2;
        break;
      }
    }
  if (n < 2) return host;  // 0 or 1 label boundary -> whole host
  return str8_skip(host, dot2 + 1);
}

// RFC 6454 / Fetch Metadata: the request initiator's relation to the target.
internal String8 sec_fetch_site(String8 url, String8 referer) {
  if (referer.size == 0) return str8_lit("none");
  ParsedUrl u = url_parse(url), r = url_parse(referer);
  if (!u.ok || !r.ok) return str8_lit("none");
  if (u.https == r.https && u.port == r.port && str8_match_ci(u.host, r.host))
    return str8_lit("same-origin");
  if (str8_match_ci(sec_reg_domain(u.host), sec_reg_domain(r.host)))
    return str8_lit("same-site");
  return str8_lit("cross-site");
}

void sec_fetch_append(HeaderList *out, FetchMode mode, String8 url,
                      String8 referer) {
  header_list_push(out, str8_lit("sec-fetch-site"),
                   sec_fetch_site(url, referer), 0);
  String8 m, dest, usr;
  switch (mode) {
    case FetchMode_Cors:
      m = str8_lit("cors"), dest = str8_lit("empty"), usr = str8_zero();
      break;
    case FetchMode_NoCors:
      m = str8_lit("no-cors"), dest = str8_lit("empty"), usr = str8_zero();
      break;
    case FetchMode_SameOrigin:
      m = str8_lit("same-origin"), dest = str8_lit("empty"), usr = str8_zero();
      break;
    case FetchMode_Navigate:
    default:
      m = str8_lit("navigate"), dest = str8_lit("document"),
      usr = str8_lit("?1");
      break;
  }
  header_list_push(out, str8_lit("sec-fetch-mode"), m, 0);
  header_list_push(out, str8_lit("sec-fetch-dest"), dest, 0);
  header_list_push(out, str8_lit("sec-fetch-user"), usr,
                   0);  // empty => omitted

  // Non-navigation requests (fetch/XHR) carry accept: */* and priority: u=1, i,
  // and omit Upgrade-Insecure-Requests — whereas the profile's static defaults
  // are navigation-shaped (accept: text/html..., priority: u=0, i, UIR: 1).
  // Emit these as overrides of the default slots (an empty value drops the
  // default in build_ordered_headers) unless the caller set them explicitly.
  if (mode != FetchMode_Navigate) {
    if (!header_list_has_ci(out, str8_lit("accept")))
      header_list_push(out, str8_lit("accept"), str8_lit("*/*"), 0);
    if (!header_list_has_ci(out, str8_lit("priority")))
      header_list_push(out, str8_lit("priority"), str8_lit("u=1, i"), 0);
    if (!header_list_has_ci(out, str8_lit("upgrade-insecure-requests")))
      header_list_push(out, str8_lit("upgrade-insecure-requests"), str8_zero(),
                       0);
  }
}

internal int sec_site_rank(String8 s) {
  if (str8_match(s, str8_lit("cross-site"))) return 3;
  if (str8_match(s, str8_lit("same-site"))) return 2;
  if (str8_match(s, str8_lit("same-origin"))) return 1;
  return 0;
}

String8 sec_fetch_site_for_redirect(const Header *headers, U64 header_count,
                                    String8 next_url) {
  String8 site = str8_zero(), referer = str8_zero();
  for (U64 i = 0; i < header_count; ++i) {
    if (str8_match_ci(headers[i].name, str8_lit("sec-fetch-site")))
      site = headers[i].value;
    else if (str8_match_ci(headers[i].name, str8_lit("referer")))
      referer = headers[i].value;
  }
  if (site.size == 0 || referer.size == 0) return str8_zero();  // nothing to do
  if (str8_match(site, str8_lit("none")) ||
      str8_match(site, str8_lit("cross-site")))
    return site;  // terminal: persists across the rest of the chain
  String8 rel = sec_fetch_site(next_url, referer);
  return sec_site_rank(rel) > sec_site_rank(site) ? rel : site;
}

void sec_fetch_merge(HeaderList *out, FetchMode mode, String8 url,
                     const Header *headers, U64 header_count) {
  String8 referer = str8_zero();
  for (U64 i = 0; i < header_count; ++i) {
    header_list_push(out, headers[i].name, headers[i].value, headers[i].flags);
    if (str8_match_ci(headers[i].name, str8_lit("referer")))
      referer = headers[i].value;
  }
  sec_fetch_append(out, mode, url, referer);
}
