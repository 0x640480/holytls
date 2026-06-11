// Offline request-hook tests: hook_request_set_header semantics (append, override
// in place, case-insensitive match, and refusal of fingerprint-controlled
// headers) and that the pre/post setters store the fn + user. Actual firing on a
// real request is covered by hook_live_test.
#include <stdio.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/header.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal B32 val_is(HeaderList *h, const char *name, const char *want) {
  String8 *v = header_list_get_ci(h, str8_cstring(name));
  return v && str8_match(*v, str8_cstring(want));
}

internal void test_set_header(Arena *a) {
  HeaderList h;
  header_list_init(&h, a);
  header_list_push(&h, str8_lit("user-agent"), str8_lit("orig-ua"), 0);
  header_list_push(&h, str8_lit("accept-language"), str8_lit("en"), 0);
  U64 base = h.count;  // 2

  HookRequest req = {Method_GET, str8_lit("https://h.com/"), &h};

  // Append a new (allowed) header.
  CHECK(hook_request_set_header(&req, str8_lit("x-custom"), str8_lit("1")));
  CHECK(h.count == base + 1);
  CHECK(val_is(&h, "x-custom", "1"));

  // Override an existing (allowed) header in place — no new entry.
  CHECK(hook_request_set_header(&req, str8_lit("Accept-Language"),
                                str8_lit("xx")));  // case-insensitive match
  CHECK(h.count == base + 1);                      // count unchanged
  CHECK(val_is(&h, "accept-language", "xx"));

  // Refuse fingerprint-controlled headers (return 0, no change).
  CHECK(!hook_request_set_header(&req, str8_lit("User-Agent"),
                                 str8_lit("evil")));
  CHECK(val_is(&h, "user-agent", "orig-ua"));      // unchanged
  CHECK(!hook_request_set_header(&req, str8_lit("accept-encoding"),
                                 str8_lit("identity")));
  CHECK(!hook_request_set_header(&req, str8_lit("sec-fetch-mode"),
                                 str8_lit("x")));
  CHECK(!hook_request_set_header(&req, str8_lit("SEC-FETCH-DEST"),
                                 str8_lit("x")));   // ci prefix
  CHECK(!hook_request_set_header(&req, str8_lit("sec-ch-ua-platform"),
                                 str8_lit("x")));
  CHECK(!hook_request_set_header(&req, str8_lit("Sec-Ch-Ua"), str8_lit("x")));
  CHECK(h.count == base + 1);  // none of the refused ones were appended
}

internal int my_pre(HookRequest *r, void *u) {
  (void)r;
  (void)u;
  return 0;
}
internal void my_post(Response *r, void *u) {
  (void)r;
  (void)u;
}

internal void test_setters(void) {
  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/0);
  CHECK(client_ok(&c));

  CHECK(c.pre_hook == 0 && c.post_hook == 0);  // off by default
  client_set_pre_hook(&c, my_pre, (void *)0x1234);
  client_set_post_hook(&c, my_post, (void *)0x5678);
  CHECK(c.pre_hook == my_pre && c.pre_hook_user == (void *)0x1234);
  CHECK(c.post_hook == my_post && c.post_hook_user == (void *)0x5678);
  client_set_pre_hook(&c, 0, 0);  // disable
  CHECK(c.pre_hook == 0);

  client_cleanup(&c);
  loop_shutdown(&loop);
}

int main(void) {
  Arena *a = arena_alloc();
  test_set_header(a);
  test_setters();
  arena_release(a);
  fprintf(stderr, "[hook_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
