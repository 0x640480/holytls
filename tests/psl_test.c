// Public Suffix List lookup tests (core/psl.c over the generated
// core/psl_data.h): exact rules, wildcard rules (*.parent, one label only),
// exception rules (!host), the default '*' rule for unlisted single labels,
// PRIVATE-section suffixes, case/trailing-dot normalization, and the
// registrable-domain negatives the cookie jar depends on.
#include <stdio.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/psl.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal B32 P(const char *s) { return psl_is_public_suffix(str8_cstring(s)); }

int main(void) {
  // Exact rules (ICANN section).
  CHECK(P("com"));
  CHECK(P("uk"));
  CHECK(P("co.uk"));
  CHECK(P("ac.jp"));
  CHECK(P("com.au"));

  // PRIVATE-section suffixes (browsers reject cookie domains on these too).
  CHECK(P("github.io"));

  // Registrable domains are NOT suffixes.
  CHECK(!P("example.com"));
  CHECK(!P("example.co.uk"));
  CHECK(!P("foo.github.io"));
  CHECK(!P("sub.example.co.uk"));

  // Wildcard rule *.ck: every direct child of ck is a suffix...
  CHECK(P("ck"));        // single label (default '*' rule; ck isn't exact-listed)
  CHECK(P("foo.ck"));    // *.ck
  CHECK(!P("x.foo.ck")); // wildcard covers exactly one label
  // ...except the exception rule !www.ck.
  CHECK(!P("www.ck"));

  // *.kawasaki.jp + !city.kawasaki.jp, with no bare kawasaki.jp rule:
  CHECK(!P("kawasaki.jp"));       // registrable under 'jp', NOT a suffix
  CHECK(P("foo.kawasaki.jp"));    // *.kawasaki.jp
  CHECK(!P("city.kawasaki.jp"));  // exception
  CHECK(!P("a.city.kawasaki.jp"));

  // IP-address hosts must never read as suffixes (the jar's loopback tests).
  CHECK(!P("127.0.0.1"));

  // Default '*' rule: an unlisted single label is a public suffix.
  CHECK(P("zz--not-a-real-tld"));
  CHECK(P("localhost"));
  // But an unlisted multi-label name is not.
  CHECK(!P("foo.zz--not-a-real-tld"));

  // Normalization: case-insensitive, one trailing dot tolerated.
  CHECK(P("COM"));
  CHECK(P("Co.Uk"));
  CHECK(P("com."));
  CHECK(!P(""));
  CHECK(!P("."));

  // Punycode rules from the list are matched in ASCII form.
  CHECK(P("xn--p1ai"));  // .рф

  fprintf(stderr, "[psl_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
