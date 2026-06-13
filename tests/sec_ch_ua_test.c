// Verifies the Sec-CH-UA generator (profile/sec_ch_ua.c) reproduces Chromium's
// brand-list GREASE algorithm byte-for-byte. Three layers of evidence:
//   1. Chromium's own unit-test seeds (84/85/86) -> GREASE brand tokens.
//   2. Real captured Chrome outputs (148 powhttp, 149 browserleaks).
//   3. Drift guard: the generated string equals the static sec-ch-ua value
//   baked
//      into each profile's default headers, so a hand-typed profile string can
//      never silently diverge from the algorithm.
#include "profile/sec_ch_ua.h"

#include <stdio.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal B32 eq(String8 got, const char *want) {
  return str8_match(got, str8_cstring(want));
}

int main(void) {
  Arena *a = arena_alloc();

  // 1) Real captured Chrome outputs (ground truth). Short header form.
  String8 c148 = sec_ch_ua_brands(a, 148);
  String8 c149 = sec_ch_ua_brands(a, 149);
  fprintf(stderr, "  148: %.*s\n", (int)c148.size, c148.str);
  fprintf(stderr, "  149: %.*s\n", (int)c149.size, c149.str);
  CHECK(eq(c148,
           "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", "
           "\"Not/A)Brand\";v=\"99\""));
  CHECK(eq(c149,
           "\"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", "
           "\"Not)A;Brand\";v=\"24\""));

  // 2) Chromium unit-test seeds pin the GREASE brand token + version. The
  //    branded list adds "Google Chrome"; assert the full hand-derived strings.
  //    seed 84: sep[84%11=7]=";", sep[85%11=8]="=", ver[84%3=0]="8",
  //             order[84%6=0]={0,1,2} -> [GREASE, Chromium, Google Chrome]
  CHECK(eq(sec_ch_ua_brands(a, 84),
           "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"84\", "
           "\"Google Chrome\";v=\"84\""));
  //    seed 85: sep[85%11=8]="=", sep[86%11=9]="?", ver[85%3=1]="99",
  //             order[85%6=1]={0,2,1} -> [GREASE, Google Chrome, Chromium]
  CHECK(eq(sec_ch_ua_brands(a, 85),
           "\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"85\", "
           "\"Chromium\";v=\"85\""));
  //    seed 86: sep[86%11=9]="?", sep[87%11=10]="_", ver[86%3=2]="24",
  //             order[86%6=2]={1,0,2} -> [Chromium, GREASE, Google Chrome]
  CHECK(eq(sec_ch_ua_brands(a, 86),
           "\"Chromium\";v=\"86\", \"Not?A_Brand\";v=\"24\", "
           "\"Google Chrome\";v=\"86\""));

  // Full-version-list: real brands carry the SUPPLIED build (NOT frozen to
  // .0.0.0 — that's the high-entropy hint's whole point); GREASE keeps the same
  // token/order/permutation as the short form, with its greased digit +
  // ".0.0.0".
  CHECK(eq(sec_ch_ua_full_version_list(a, 149, str8_lit("149.0.7632.67")),
           "\"Google Chrome\";v=\"149.0.7632.67\", "
           "\"Chromium\";v=\"149.0.7632.67\", \"Not)A;Brand\";v=\"24.0.0.0\""));
  // str8_zero() falls back to the UA-frozen "<major>.0.0.0" for the real
  // brands.
  CHECK(eq(sec_ch_ua_full_version_list(a, 149, str8_zero()),
           "\"Google Chrome\";v=\"149.0.0.0\", \"Chromium\";v=\"149.0.0.0\", "
           "\"Not)A;Brand\";v=\"24.0.0.0\""));

  // 3) Drift guard: generated == the static string each profile ships, read via
  //    the first-class accessor.
  const Profile *p148 = profile_chrome148();
  const Profile *p149 = profile_chrome149();
  CHECK(str8_match(c148, profile_sec_ch_ua(p148)));
  CHECK(str8_match(c149, profile_sec_ch_ua(p149)));

  // 4) The first-class default-header accessors.
  CHECK(eq(profile_user_agent(p149),
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"));
  CHECK(eq(profile_sec_ch_ua_mobile(p149), "?0"));
  CHECK(eq(profile_sec_ch_ua_platform(p149), "\"Windows\""));
  CHECK(eq(profile_accept_language(p149), "en-US,en;q=0.9"));
  CHECK(eq(profile_accept_encoding(p149), "gzip, deflate, br, zstd"));
  // Generic by-name lookup (also the path for a QuicProfile table).
  CHECK(eq(
      profile_default_header(p149->default_headers, p149->default_header_count,
                             str8_lit("priority")),
      "u=0, i"));
  CHECK(eq(profile_default_header(profile_chrome149_h3()->default_headers,
                                  profile_chrome149_h3()->default_header_count,
                                  str8_lit("user-agent")),
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"));
  // Absent header -> empty.
  CHECK(profile_default_header(p149->default_headers,
                               p149->default_header_count,
                               str8_lit("x-not-present"))
            .size == 0);

  arena_release(a);
  fprintf(stderr, "[sec_ch_ua_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
