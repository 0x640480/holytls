// Offline http-version tests: the setter stores the mode; forcing H1 builds an
// http/1.1-only ALPN profile (ALPS dropped) while keeping Chrome's TLS knobs; and
// forcing H3 on a non-dual client fails the request synchronously (the no-QUIC
// check fires in dispatch before any network I/O). Live negotiation (h1/h2/h3 on
// the wire) is covered by http_version_live_test.
#include <stdio.h>
#include <string.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal void test_setter_and_h1(void) {
  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/0);
  CHECK(client_ok(&c));

  CHECK(c.http_version == HttpVersion_Auto);  // default
  client_set_http_version(&c, HttpVersion_H2);
  CHECK(c.http_version == HttpVersion_H2);

  client_set_http_version(&c, HttpVersion_H1);
  CHECK(c.http_version == HttpVersion_H1);
  // h1_tls advertises only "http/1.1" (length-prefixed) and no ALPS...
  CHECK(c.h1_tls.alpn_wire_len == 9);
  CHECK(c.h1_tls.alpn_wire[0] == 8);
  CHECK(memcmp(c.h1_tls.alpn_wire + 1, "http/1.1", 8) == 0);
  CHECK(c.h1_tls.alps_count == 0);
  // ...but otherwise carries Chrome's TLS knobs (copied from the profile).
  CHECK(c.h1_tls.cipher_list == c.profile->tls.cipher_list);
  CHECK(c.h1_tls.extension_order == c.profile->tls.extension_order);

  client_cleanup(&c);
  loop_shutdown(&loop);
}

typedef struct Ctx Ctx;
struct Ctx {
  B32 done;
  B32 ok;
  B32 err_quic;
};
internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->done = 1;
  cx->ok = r->ok;
  cx->err_quic = r->error && strstr(r->error, "QUIC") != 0;
}

internal void test_force_h3_without_quic(void) {
  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/1);  // H2-only (no QUIC)
  CHECK(client_ok(&c));
  client_set_http_version(&c, HttpVersion_H3);  // forced, but no QUIC profile

  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(&c, str8_lit("https://example.com/"), on_resp, &cx);
  loop_run(&loop);  // the error is delivered synchronously in dispatch (no I/O)
  CHECK(cx.done);
  CHECK(!cx.ok);       // forced H3 on a non-dual client fails
  CHECK(cx.err_quic);  // ...with a QUIC-profile error

  client_cleanup(&c);
  loop_shutdown(&loop);
}

int main(void) {
  test_setter_and_h1();
  test_force_h3_without_quic();
  fprintf(stderr, "[http_version_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
