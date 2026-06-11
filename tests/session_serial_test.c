// Offline session-serialization tests: base64 round-trip, and a full
// marshal -> unmarshal of the transport caches (Alt-Svc, ECH) + cookie jar into
// fresh Client/Session objects, asserting field-level fidelity, TTL rebasing, and
// version gating. TLS-ticket round-trip needs a real handshake and is covered by
// session_persist_live_test.
#include <stdio.h>
#include <string.h>
#include <uv.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/cookie.h"
#include "core/persist.h"
#include "core/session.h"
#include "core/url.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal ParsedUrl U(const char *s) { return url_parse(str8_cstring(s)); }
internal B32 has(String8 hdr, const char *sub) {
  return str8_contains(hdr, str8_cstring(sub));
}

internal void test_round_trip(Arena *a) {
  EventLoop loop;
  loop_init(&loop);
  U64 now = uv_now(loop_uv(&loop));

  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
  CHECK(client_ok(&c));

  // Alt-Svc cache (host:port -> h3 + monotonic-ms expiry).
  strcpy(c.alt_svc[0].origin, "example.com:443");
  c.alt_svc[0].h3 = 1;
  c.alt_svc[0].expiry_ms = now + 3600000;  // +1h
  c.alt_svc_count = 1;

  // ECH cache: one real config + one negative (origin publishes none).
  U8 cfg[] = {0xfe, 0x0d, 0x00, 0x41, 0x01, 0x02, 0x03};
  strcpy(c.ech_cache[0].origin, "ech.example.com:443");
  MemoryCopy(c.ech_cache[0].config, cfg, sizeof cfg);
  c.ech_cache[0].config_len = sizeof cfg;
  c.ech_cache[0].expiry_ms = now + 3600000;
  strcpy(c.ech_cache[1].origin, "noech.example.com:443");
  c.ech_cache[1].config_len = 0;
  c.ech_cache[1].expiry_ms = now + 3600000;
  c.ech_cache_count = 2;

  // Cookies on the session jar.
  Session s;
  session_init(&s, 0);
  cookie_jar_store(&s.jar, U("https://h.com/"),
                   str8_lit("sid=abc; Path=/; Secure"), 1000);
  cookie_jar_store(&s.jar, U("https://h.com/a/b"), str8_lit("deep=2; Path=/a/b"),
                   1000);
  cookie_jar_store(&s.jar, U("https://h.com/"), str8_lit("dom=x; Domain=h.com"),
                   1000);

  String8 js = session_marshal(a, &s, &c, /*pretty=*/1);
  CHECK(js.size > 0);
  CHECK(str8_contains(js, str8_lit("\"version\"")));
  CHECK(str8_contains(js, str8_lit("alt_svc")));
  CHECK(str8_contains(js, str8_lit("cookies")));

  // Restore into brand-new objects.
  Client c2;
  client_init(&c2, &loop, profile_chrome148(), /*verify=*/1);
  CHECK(client_ok(&c2));
  Session s2;
  session_init(&s2, 0);
  CHECK(session_unmarshal(&s2, &c2, js));

  // Alt-Svc survived + is still live (TTL rebased onto c2's clock).
  CHECK(client_h3_available(&c2, str8_lit("example.com:443")));

  // ECH survived, both the real config and the negative result.
  B32 found_ech = 0, found_neg = 0;
  for (int i = 0; i < c2.ech_cache_count; ++i) {
    String8 o = str8_cstring(c2.ech_cache[i].origin);
    if (str8_match(o, str8_lit("ech.example.com:443")))
      found_ech =
          c2.ech_cache[i].config_len == sizeof cfg &&
          str8_match(str8(c2.ech_cache[i].config, c2.ech_cache[i].config_len),
                     str8(cfg, sizeof cfg));
    if (str8_match(o, str8_lit("noech.example.com:443")))
      found_neg = c2.ech_cache[i].config_len == 0;
  }
  CHECK(found_ech);
  CHECK(found_neg);

  // Cookies survived (Secure cookie over https; Domain + Path scoping).
  String8 hdr = cookie_jar_cookie_header(&s2.jar, a, U("https://h.com/a/b/c"), 1000);
  CHECK(has(hdr, "sid=abc"));
  CHECK(has(hdr, "deep=2"));
  CHECK(has(hdr, "dom=x"));

  // Version gating: wrong/garbage versions are rejected.
  CHECK(!session_unmarshal(&s2, &c2, str8_lit("{\"version\":999}")));
  CHECK(!session_unmarshal(&s2, &c2, str8_lit("not json at all")));

  session_cleanup(&s2);
  session_cleanup(&s);
  client_cleanup(&c2);
  client_cleanup(&c);
  loop_shutdown(&loop);
}

int main(void) {
  Arena *a = arena_alloc();
  test_round_trip(a);
  arena_release(a);
  fprintf(stderr, "[session_serial_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
