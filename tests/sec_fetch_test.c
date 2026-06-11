// Offline Sec-Fetch coherence: Sec-Fetch-Site from the referer<->URL relationship
// (none / same-origin / same-site / cross-site) and the mode/dest/user mapping.
#include <stdio.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/header.h"
#include "core/sec_fetch.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal String8 hv(HeaderList *l, const char *name) {
  String8 *v = header_list_get_ci(l, str8_cstring(name));
  return v ? *v : str8_zero();
}
internal B32 eq(String8 a, const char *b) { return str8_match(a, str8_cstring(b)); }

// Build the Sec-Fetch headers for (mode, url, referer) into a fresh list.
internal void build(Arena *a, HeaderList *out, FetchMode mode, const char *url,
                    const char *referer) {
  header_list_init(out, a);
  sec_fetch_append(out, mode, str8_cstring(url), str8_cstring(referer));
}

int main(void) {
  Arena *a = arena_alloc();
  HeaderList h;

  // Navigate, no referer -> classic top-level navigation.
  build(a, &h, FetchMode_Navigate, "https://a.com/x", "");
  CHECK(eq(hv(&h, "sec-fetch-site"), "none"));
  CHECK(eq(hv(&h, "sec-fetch-mode"), "navigate"));
  CHECK(eq(hv(&h, "sec-fetch-dest"), "document"));
  CHECK(eq(hv(&h, "sec-fetch-user"), "?1"));

  // Cors fetch from the same origin -> the bot's common API-call case.
  build(a, &h, FetchMode_Cors, "https://a.com/api", "https://a.com/page");
  CHECK(eq(hv(&h, "sec-fetch-site"), "same-origin"));
  CHECK(eq(hv(&h, "sec-fetch-mode"), "cors"));
  CHECK(eq(hv(&h, "sec-fetch-dest"), "empty"));
  CHECK(hv(&h, "sec-fetch-user").size == 0);  // suppressed for fetches
  // Fetch/XHR also gets accept: */* and priority: u=1, i, and drops UIR (emitted
  // as an empty-value override so build_ordered_headers omits the default).
  CHECK(eq(hv(&h, "accept"), "*/*"));
  CHECK(eq(hv(&h, "priority"), "u=1, i"));
  CHECK(header_list_has_ci(&h, str8_lit("upgrade-insecure-requests")));
  CHECK(hv(&h, "upgrade-insecure-requests").size == 0);

  // A caller-supplied accept/priority is respected (not overridden).
  {
    HeaderList hc;
    header_list_init(&hc, a);
    header_list_push(&hc, str8_lit("accept"), str8_lit("application/json"), 0);
    header_list_push(&hc, str8_lit("priority"), str8_lit("u=4"), 0);
    sec_fetch_append(&hc, FetchMode_Cors, str8_lit("https://a.com/api"),
                     str8_lit("https://a.com/p"));
    CHECK(eq(hv(&hc, "accept"), "application/json"));
    CHECK(eq(hv(&hc, "priority"), "u=4"));
  }

  // Navigation leaves accept/priority/UIR to the profile defaults (not here).
  build(a, &h, FetchMode_Navigate, "https://a.com/x", "");
  CHECK(hv(&h, "accept").size == 0);
  CHECK(hv(&h, "priority").size == 0);
  CHECK(!header_list_has_ci(&h, str8_lit("upgrade-insecure-requests")));

  // Sec-Fetch-Site relationships.
  build(a, &h, FetchMode_Cors, "https://api.a.com/x", "https://www.a.com/y");
  CHECK(eq(hv(&h, "sec-fetch-site"), "same-site"));  // same registrable domain
  build(a, &h, FetchMode_Cors, "https://a.com/x", "https://b.com/y");
  CHECK(eq(hv(&h, "sec-fetch-site"), "cross-site"));
  build(a, &h, FetchMode_Cors, "https://a.com:443/x", "https://a.com:8443/y");
  CHECK(eq(hv(&h, "sec-fetch-site"), "same-site"));  // host matches, port differs

  // sec_fetch_merge keeps the caller's headers (incl. the referer it reads).
  Header caller[2] = {
      {str8_lit("referer"), str8_lit("https://a.com/page"), 0},
      {str8_lit("x-custom"), str8_lit("1"), 0},
  };
  HeaderList m;
  header_list_init(&m, a);
  sec_fetch_merge(&m, FetchMode_Cors, str8_lit("https://a.com/api"), caller, 2);
  CHECK(eq(hv(&m, "x-custom"), "1"));
  CHECK(eq(hv(&m, "referer"), "https://a.com/page"));
  CHECK(eq(hv(&m, "sec-fetch-site"), "same-origin"));  // from the caller's referer
  CHECK(eq(hv(&m, "sec-fetch-mode"), "cors"));

  //- redirect recomputation (monotonic; cross-site/none terminal)
  Header so[2] = {{str8_lit("referer"), str8_lit("https://a.com/"), 0},
                  {str8_lit("sec-fetch-site"), str8_lit("same-origin"), 0}};
  CHECK(eq(sec_fetch_site_for_redirect(so, 2, str8_lit("https://a.com/x")),
           "same-origin"));
  CHECK(eq(sec_fetch_site_for_redirect(so, 2, str8_lit("https://b.com/x")),
           "cross-site"));  // same-origin -> cross hop
  CHECK(eq(sec_fetch_site_for_redirect(so, 2, str8_lit("https://sub.a.com/x")),
           "same-site"));   // same-origin -> same-site hop

  // monotonic: was same-site, a later same-origin hop does NOT upgrade.
  Header ss[2] = {{str8_lit("referer"), str8_lit("https://a.com/"), 0},
                  {str8_lit("sec-fetch-site"), str8_lit("same-site"), 0}};
  CHECK(eq(sec_fetch_site_for_redirect(ss, 2, str8_lit("https://a.com/x")),
           "same-site"));
  // terminal: cross-site and none persist.
  Header cs[2] = {{str8_lit("referer"), str8_lit("https://a.com/"), 0},
                  {str8_lit("sec-fetch-site"), str8_lit("cross-site"), 0}};
  CHECK(eq(sec_fetch_site_for_redirect(cs, 2, str8_lit("https://a.com/x")),
           "cross-site"));
  Header nn[2] = {{str8_lit("referer"), str8_lit("https://a.com/"), 0},
                  {str8_lit("sec-fetch-site"), str8_lit("none"), 0}};
  CHECK(eq(sec_fetch_site_for_redirect(nn, 2, str8_lit("https://b.com/x")),
           "none"));
  // No Sec-Fetch-Site (a plain navigation) or no Referer -> leave as-is.
  Header plain[1] = {{str8_lit("referer"), str8_lit("https://a.com/"), 0}};
  CHECK(sec_fetch_site_for_redirect(plain, 1, str8_lit("https://a.com/x")).size ==
        0);
  Header noref[1] = {{str8_lit("sec-fetch-site"), str8_lit("same-origin"), 0}};
  CHECK(sec_fetch_site_for_redirect(noref, 1, str8_lit("https://a.com/x")).size ==
        0);

  arena_release(a);
  fprintf(stderr, "[sec_fetch_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
