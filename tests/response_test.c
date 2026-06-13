// Offline tests for the Response convenience accessors (response_text /
// get_header / is_success / is_redirect / json) and client_get_proxy. The
// Response helpers are pure over a hand-built Response; client_get_proxy is a
// set -> get round-trip on a Client.
#include <stdio.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/header.h"
#include "core/json.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal void test_response_helpers(Arena *a) {
  Header hdrs[] = {
      {str8_lit("content-type"), str8_lit("application/json"), 0},
      {str8_lit("x-foo"), str8_lit("bar"), 0},
  };
  Response r;
  MemoryZeroStruct(&r);
  r.ok = 1;
  r.status = 200;
  r.headers = hdrs;
  r.header_count = ArrayCount(hdrs);
  r.body = (const U8 *)"{\"a\":42}";
  r.body_len = 8;

  // text == raw body bytes.
  CHECK(str8_match(response_text(&r), str8_lit("{\"a\":42}")));

  // header lookup is case-insensitive; absent -> empty.
  CHECK(str8_match(response_get_header(&r, str8_lit("Content-Type")),
                   str8_lit("application/json")));
  CHECK(
      str8_match(response_get_header(&r, str8_lit("X-Foo")), str8_lit("bar")));
  CHECK(response_get_header(&r, str8_lit("missing")).size == 0);

  // is_success: transport ok AND 2xx.
  CHECK(response_is_success(&r));
  r.status = 404;
  CHECK(!response_is_success(&r));
  r.status = 301;
  CHECK(!response_is_success(&r) && response_is_redirect(&r));
  r.status = 200;
  CHECK(!response_is_redirect(&r));
  r.ok = 0;
  CHECK(!response_is_success(&r));  // transport failure is never success
  r.ok = 1;

  // json: parse the body + navigate.
  yyjson_doc *doc = response_json(&r, a);
  CHECK(doc != 0);
  if (doc) {
    yyjson_val *av = yyjson_obj_get(json_root(doc), "a");
    CHECK(av && yyjson_get_int(av) == 42);
  }

  // empty body -> empty text, null json.
  Response e;
  MemoryZeroStruct(&e);
  CHECK(response_text(&e).size == 0);
  CHECK(response_json(&e, a) == 0);
}

internal void test_get_proxy(Arena *a) {
  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/0);

  CHECK(client_get_proxy(&c, a).size == 0);  // direct by default

  CHECK(client_set_proxy(&c, str8_lit("socks5://h:1080"), 0));
  CHECK(str8_match(client_get_proxy(&c, a), str8_lit("socks5://h:1080")));

  CHECK(client_set_proxy(&c, str8_lit("http://user:pass@p.example:8080"), 0));
  CHECK(str8_match(client_get_proxy(&c, a),
                   str8_lit("http://user:pass@p.example:8080")));

  CHECK(client_set_proxy(&c, str8_lit(""), 0));  // back to direct
  CHECK(client_get_proxy(&c, a).size == 0);

  client_cleanup(&c);
  loop_shutdown(&loop);
}

int main(void) {
  Arena *a = arena_alloc();
  test_response_helpers(a);
  test_get_proxy(a);
  arena_release(a);
  fprintf(stderr, "[response_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
