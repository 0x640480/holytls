// Offline header-order tests: the reorder_headers primitive (listed-first, rest
// in original order, case-insensitive, no drop/dup) and the client
// get/set/reset API.
#include "core/header_order.h"

#include <stdio.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/client_internal.h"  // build_request_headers (white-box)
#include "core/header.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal void push(HeaderList *l, const char *n, const char *v) {
  header_list_push(l, str8_cstring(n), str8_cstring(v), 0);
}
// True if the list's names equal `names` (in order) AND each kept its own value
// (names[i] is "name=value").
internal B32 order_is(HeaderList *l, const char **pairs, U64 n) {
  if (l->count != n) return 0;
  for (U64 i = 0; i < n; ++i) {
    String8 want = str8_cstring(pairs[i]);
    String8 nm = want, val = str8_zero();
    U64 eq;
    if (str8_index_of(want, '=', &eq)) {
      nm = str8_prefix(want, eq);
      val = str8_skip(want, eq + 1);
    }
    if (!str8_match(l->v[i].name, nm)) return 0;
    if (val.size && !str8_match(l->v[i].value, val)) return 0;
  }
  return 1;
}
internal HeaderList abcd(Arena *a) {
  HeaderList l;
  header_list_init(&l, a);
  push(&l, "a", "1");
  push(&l, "b", "2");
  push(&l, "c", "3");
  push(&l, "d", "4");
  return l;
}

internal void test_reorder(Arena *a) {
  // Listed names first (in order), the rest in original order; values follow
  // names.
  HeaderList l = abcd(a);
  String8 o1[] = {str8_lit("c"), str8_lit("a")};
  reorder_headers(a, &l, o1, 2);
  CHECK(order_is(&l, (const char *[]){"c=3", "a=1", "b=2", "d=4"}, 4));

  // Case-insensitive match.
  l = abcd(a);
  String8 o2[] = {str8_lit("D"), str8_lit("B")};
  reorder_headers(a, &l, o2, 2);
  CHECK(order_is(&l, (const char *[]){"d", "b", "a", "c"}, 4));

  // A name with no matching header is skipped (no drop/dup of real headers).
  l = abcd(a);
  String8 o3[] = {str8_lit("x"), str8_lit("b")};
  reorder_headers(a, &l, o3, 2);
  CHECK(order_is(&l, (const char *[]){"b", "a", "c", "d"}, 4));

  // A duplicate order name claims only one header.
  l = abcd(a);
  String8 o4[] = {str8_lit("a"), str8_lit("a")};
  reorder_headers(a, &l, o4, 2);
  CHECK(order_is(&l, (const char *[]){"a", "b", "c", "d"}, 4));

  // Empty order is a no-op.
  l = abcd(a);
  reorder_headers(a, &l, 0, 0);
  CHECK(order_is(&l, (const char *[]){"a", "b", "c", "d"}, 4));

  // Full reverse.
  l = abcd(a);
  String8 o5[] = {str8_lit("d"), str8_lit("c"), str8_lit("b"), str8_lit("a")};
  reorder_headers(a, &l, o5, 4);
  CHECK(order_is(&l, (const char *[]){"d", "c", "b", "a"}, 4));
}

internal void test_override_defaults(Arena *a) {
  // The mechanism override-default-headers relies on: build_ordered_headers
  // with NO profile defaults emits exactly the caller's headers, in array
  // order, dropping empty-value entries.
  HeaderList out;
  header_list_init(&out, a);
  Header caller[] = {
      {str8_lit("user-agent"), str8_lit("ua"), 0},
      {str8_lit("accept"), str8_lit("*/*"), 0},
      {str8_lit("x-empty"), str8_zero(), 0},  // empty value -> dropped
      {str8_lit("x-custom"), str8_lit("v"), 0},
  };
  build_ordered_headers(a, 0, 0, caller, ArrayCount(caller), &out);
  CHECK(order_is(
      &out, (const char *[]){"user-agent=ua", "accept=*/*", "x-custom=v"}, 3));
}

// Named-slot template: an EMPTY content-length slot in the caller array is filled
// in place by build_request_headers (keeping its wire position) instead of being
// dropped + re-appended at the end. Byte-exact (append-at-end) when no slot.
internal void test_named_slot_content_length(Arena *a) {
  const U8 *body = (const U8 *)"hello";  // 5 bytes

  HeaderList out;
  header_list_init(&out, a);
  Header caller[] = {
      {str8_lit("x-first"), str8_lit("1"), 0},
      {str8_lit("content-length"), str8_zero(), 0},  // empty slot -> filled here
      {str8_lit("x-last"), str8_lit("2"), 0},
  };
  build_request_headers(a, 0, 0, caller, ArrayCount(caller), body, 5,
                        /*override=*/1, Method_POST, &out);
  CHECK(order_is(
      &out, (const char *[]){"x-first=1", "content-length=5", "x-last=2"}, 3));

  // No slot -> content-length appended at the END (today's behavior, unchanged).
  HeaderList out2;
  header_list_init(&out2, a);
  Header caller2[] = {
      {str8_lit("x-first"), str8_lit("1"), 0},
      {str8_lit("x-last"), str8_lit("2"), 0},
  };
  build_request_headers(a, 0, 0, caller2, ArrayCount(caller2), body, 5,
                        /*override=*/1, Method_POST, &out2);
  CHECK(order_is(
      &out2, (const char *[]){"x-first=1", "x-last=2", "content-length=5"}, 3));
}

// The session cookie-slot mechanism: a caller header whose empty value is FILLED
// before build_ordered_headers lands at its original position; an empty slot left
// UNFILLED is dropped (no empty "cookie:" leaks to the wire).
internal void test_named_slot_cookie_position(Arena *a) {
  HeaderList hop;
  header_list_init(&hop, a);
  push(&hop, "a", "1");
  header_list_push(&hop, str8_lit("cookie"), str8_zero(), 0);  // empty slot
  push(&hop, "b", "2");
  String8 *slot = header_list_get_ci(&hop, str8_lit("cookie"));
  CHECK(slot && slot->size == 0);
  *slot = str8_lit("sid=xyz");  // what session_dispatch_hop does with the jar
  HeaderList out;
  header_list_init(&out, a);
  build_ordered_headers(a, 0, 0, hop.v, hop.count, &out);  // override mode
  CHECK(order_is(&out, (const char *[]){"a=1", "cookie=sid=xyz", "b=2"}, 3));

  // Unfilled empty slot -> dropped.
  HeaderList hop2;
  header_list_init(&hop2, a);
  push(&hop2, "a", "1");
  header_list_push(&hop2, str8_lit("cookie"), str8_zero(), 0);
  push(&hop2, "b", "2");
  HeaderList out2;
  header_list_init(&out2, a);
  build_ordered_headers(a, 0, 0, hop2.v, hop2.count, &out2);
  CHECK(order_is(&out2, (const char *[]){"a=1", "b=2"}, 2));
}

internal void test_client_api(void) {
  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/0);

  String8 got[64];
  U64 def = client_get_header_order(&c, got, ArrayCount(got));
  CHECK(def > 0);  // the profile defines a default order

  String8 custom[] = {str8_lit("accept-language"), str8_lit("user-agent"),
                      str8_lit("accept")};
  CHECK(client_set_header_order(&c, custom, ArrayCount(custom)));
  U64 n = client_get_header_order(&c, got, ArrayCount(got));
  CHECK(n == 3 && str8_match(got[0], str8_lit("accept-language")) &&
        str8_match(got[1], str8_lit("user-agent")) &&
        str8_match(got[2], str8_lit("accept")));

  // A large order (>32, <= the 64 cap) now sets successfully — the raised cap
  // covers realistic header sets without the named-slot template.
  String8 many[40];
  char names40[40][8];
  for (U64 i = 0; i < 40; ++i) {
    int k = snprintf(names40[i], sizeof names40[i], "h%llu", (unsigned long long)i);
    many[i] = str8((U8 *)names40[i], (U64)k);
  }
  CHECK(client_set_header_order(&c, many, 40));
  CHECK(client_get_header_order(&c, got, ArrayCount(got)) == 40);

  // Over the cap -> rejected, state unchanged (40 names from above).
  String8 too_many[CLIENT_HEADER_ORDER_MAX + 1];
  for (U64 i = 0; i < ArrayCount(too_many); ++i) too_many[i] = str8_lit("x");
  CHECK(client_set_header_order(&c, too_many, ArrayCount(too_many)) == 0);
  CHECK(client_get_header_order(&c, got, ArrayCount(got)) == 40);

  // Reset (count 0) -> back to the profile order.
  CHECK(client_set_header_order(&c, 0, 0));
  CHECK(client_get_header_order(&c, got, ArrayCount(got)) == def);

  // String convenience: comma- and/or whitespace-separated == the array form.
  CHECK(client_set_header_order_str(&c, "accept, accept-language, user-agent"));
  n = client_get_header_order(&c, got, ArrayCount(got));
  CHECK(n == 3 && str8_match(got[0], str8_lit("accept")) &&
        str8_match(got[1], str8_lit("accept-language")) &&
        str8_match(got[2], str8_lit("user-agent")));
  CHECK(client_set_header_order_str(&c, "user-agent accept"));  // space-only
  CHECK(client_get_header_order(&c, got, ArrayCount(got)) == 2);
  CHECK(
      client_set_header_order_str(&c, ""));  // empty -> reset to profile order
  CHECK(client_get_header_order(&c, got, ArrayCount(got)) == def);

  // Override-default-headers flag: off by default, set/get, reset.
  CHECK(client_get_override_default_headers(&c) == 0);
  client_override_default_headers(&c, 1);
  CHECK(client_get_override_default_headers(&c) == 1);
  client_override_default_headers(&c, 0);
  CHECK(client_get_override_default_headers(&c) == 0);

  client_cleanup(&c);
  loop_shutdown(&loop);
}

// The profile's fetch_order reshapes a navigation-ordered XHR header set into
// Chrome's distinct fetch order (content-length first, client-hint block
// reordered, origin after accept, referer after sec-fetch-dest).
internal void test_fetch_order(Arena *a) {
  const Profile *p = profile_chrome149();
  CHECK(p->fetch_order_count > 0);  // Chrome profiles define a fetch order

  HeaderList l;
  header_list_init(&l, a);
  push(&l, "sec-ch-ua", "x");
  push(&l, "sec-ch-ua-mobile", "?0");
  push(&l, "sec-ch-ua-platform", "\"Windows\"");
  push(&l, "user-agent", "ua");
  push(&l, "accept", "*/*");
  push(&l, "sec-fetch-site", "same-origin");
  push(&l, "sec-fetch-mode", "cors");
  push(&l, "sec-fetch-dest", "empty");
  push(&l, "accept-encoding", "gzip");
  push(&l, "accept-language", "en");
  push(&l, "cookie", "a=1");
  push(&l, "priority", "u=1, i");
  push(&l, "origin", "https://a.com");
  push(&l, "referer", "https://a.com/p");
  push(&l, "content-length", "0");

  String8 order[32];
  for (U8 i = 0; i < p->fetch_order_count; ++i)
    order[i] = str8_cstring(p->fetch_order[i]);
  reorder_headers(a, &l, order, p->fetch_order_count);

  CHECK(order_is(
      &l,
      (const char *[]){"content-length", "sec-ch-ua-platform", "user-agent",
                       "sec-ch-ua", "sec-ch-ua-mobile", "accept", "origin",
                       "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
                       "referer", "accept-encoding", "accept-language",
                       "cookie", "priority"},
      15));
}

// HdrBuf: a fixed-storage Header[] builder. `hdrbuf_add` keeps an empty value
// (a named-slot placeholder); `hdrbuf_add_opt` skips it; adds past cap drop.
internal void test_hdr_buf(void) {
  Header st[3];
  HdrBuf b;
  hdrbuf_init(&b, st, ArrayCount(st));
  hdrbuf_lit(&b, "a", "1");
  hdrbuf_add(&b, str8_lit("cookie"), str8_zero());      // empty value KEPT
  hdrbuf_add_opt(&b, str8_lit("x-skip"), str8_zero());  // empty -> skipped
  hdrbuf_lit(&b, "b", "2");
  hdrbuf_lit(&b, "c", "3");  // past cap (3) -> dropped
  CHECK(b.count == 3);
  CHECK(str8_match(b.v[0].name, str8_lit("a")) &&
        str8_match(b.v[0].value, str8_lit("1")));
  CHECK(str8_match(b.v[1].name, str8_lit("cookie")) && b.v[1].value.size == 0);
  CHECK(str8_match(b.v[2].name, str8_lit("b")) &&
        str8_match(b.v[2].value, str8_lit("2")));
}

int main(void) {
  Arena *a = arena_alloc();
  test_reorder(a);
  test_override_defaults(a);
  test_named_slot_content_length(a);
  test_named_slot_cookie_position(a);
  test_hdr_buf();
  test_fetch_order(a);
  test_client_api();
  arena_release(a);
  fprintf(stderr, "[header_order_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
