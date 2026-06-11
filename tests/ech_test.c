// Offline ECH config extraction: parse a dns.google DoH JSON response for an
// HTTPS record and decode the `ech` SvcParam into the raw ECHConfigList bytes.
#include <stdio.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/ech.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

int main(void) {
  Arena *a = arena_alloc();

  // Real dns.google /resolve response for crypto.cloudflare.com (HTTPS RR).
  String8 json = str8_lit(
      "{\"Status\":0,\"Answer\":[{\"name\":\"crypto.cloudflare.com.\","
      "\"type\":65,\"TTL\":300,\"data\":\"1 . alpn=h2 "
      "ipv4hint=162.159.135.79 "
      "ech=AEX+DQBB7gAgACA5BHtnnuUzrNj6CAEfdhsamXGn6afYhD5jQERS2WJdbgAEAAEAAQAS"
      "Y2xvdWRmbGFyZS1lY2guY29tAAA= "
      "ipv6hint=2606:4700:7::a29f:874f\"}]}");
  String8 cfg = ech_config_from_doh(a, json);
  fprintf(stderr, "  ECHConfigList len=%llu\n", (unsigned long long)cfg.size);
  CHECK(cfg.size == 71);  // ECHConfigList incl. 2-byte length prefix
  CHECK(cfg.size >= 4 && cfg.str[0] == 0x00 && cfg.str[1] == 0x45 &&
        cfg.str[2] == 0xfe && cfg.str[3] == 0x0d);  // len=0x45, version 0xfe0d

  // HTTPS record present but no ech param -> empty (negative result).
  CHECK(ech_config_from_doh(
            a, str8_lit("{\"Answer\":[{\"type\":65,\"data\":\"1 . alpn=h2 "
                        "ipv4hint=1.2.3.4\"}]}"))
            .size == 0);
  // No type-65 record (only an A record) -> empty.
  CHECK(ech_config_from_doh(
            a, str8_lit("{\"Answer\":[{\"type\":1,\"data\":\"1.2.3.4\"}]}"))
            .size == 0);
  // No Answer / malformed -> empty.
  CHECK(ech_config_from_doh(a, str8_lit("{\"Status\":3}")).size == 0);
  CHECK(ech_config_from_doh(a, str8_lit("not json")).size == 0);

  arena_release(a);
  fprintf(stderr, "[ech_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
