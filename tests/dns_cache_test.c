// Offline DNS-cache tests: put/get hit, TTL expiry, unknown-host miss, evict,
// disabled (ttl=0) behavior, full-table eviction, and the port-reset helper.
// Addresses are built with uv_ip4_addr (no network).
#include "net/dns_cache.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>

#include "base/base.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

// Build a v4 sockaddr for ip:port.
internal struct sockaddr_in v4(const char *ip, U16 port) {
  struct sockaddr_in sin;
  uv_ip4_addr(ip, port, &sin);
  return sin;
}
internal U32 v4_ip(const struct sockaddr_storage *ss) {
  return ((const struct sockaddr_in *)ss)->sin_addr.s_addr;
}
internal U16 v4_port(const struct sockaddr_storage *ss) {
  return ntohs(((const struct sockaddr_in *)ss)->sin_port);
}

internal void test_basic(void) {
  DnsCache dc;
  dns_cache_init(&dc, /*ttl_ms=*/1000);
  struct sockaddr_in a = v4("1.2.3.4", 443);
  dns_cache_put(&dc, "a.com", (struct sockaddr *)&a, sizeof a, /*now=*/0);

  struct sockaddr_storage out;
  socklen_t ol = 0;
  CHECK(dns_cache_get(&dc, "a.com", 500, &out, &ol));  // live hit
  CHECK(v4_ip(&out) == a.sin_addr.s_addr);
  CHECK(dns_cache_get(&dc, "A.COM", 500, &out, &ol));   // case-insensitive
  CHECK(!dns_cache_get(&dc, "b.com", 500, &out, &ol));  // unknown -> miss
  CHECK(
      !dns_cache_get(&dc, "a.com", 1000, &out, &ol));  // expired (now>=expiry)
  CHECK(!dns_cache_get(&dc, "a.com", 1500, &out, &ol));  // and stays gone
}

internal void test_evict_and_disabled(void) {
  DnsCache dc;
  dns_cache_init(&dc, 1000);
  struct sockaddr_in a = v4("9.9.9.9", 443);
  struct sockaddr_storage out;
  socklen_t ol = 0;

  dns_cache_put(&dc, "x.com", (struct sockaddr *)&a, sizeof a, 0);
  CHECK(dns_cache_get(&dc, "x.com", 1, &out, &ol));
  dns_cache_evict(&dc, "x.com");
  CHECK(!dns_cache_get(&dc, "x.com", 1, &out, &ol));  // evicted

  // Disabled: put + get are no-ops.
  DnsCache off;
  dns_cache_init(&off, /*ttl_ms=*/0);
  dns_cache_put(&off, "x.com", (struct sockaddr *)&a, sizeof a, 0);
  CHECK(!dns_cache_get(&off, "x.com", 1, &out, &ol));
}

internal void test_full_table_eviction(void) {
  DnsCache dc;
  dns_cache_init(&dc, 100000);
  struct sockaddr_storage out;
  socklen_t ol = 0;
  char host[32];
  // Fill CAP entries with increasing put-times (so entry 0 is the oldest).
  for (int i = 0; i < DNS_CACHE_CAP; ++i) {
    snprintf(host, sizeof host, "h%d.com", i);
    struct sockaddr_in a = v4("1.1.1.1", 443);
    dns_cache_put(&dc, host, (struct sockaddr *)&a, sizeof a, (U64)i);
  }
  CHECK(dns_cache_get(&dc, "h0.com", 1, &out, &ol));  // present before overflow
  // One more put evicts the soonest-expiring (h0, put at t=0).
  struct sockaddr_in b = v4("2.2.2.2", 443);
  dns_cache_put(&dc, "new.com", (struct sockaddr *)&b, sizeof b, 1000);
  CHECK(dns_cache_get(&dc, "new.com", 1001, &out, &ol));  // newcomer cached
  CHECK(!dns_cache_get(&dc, "h0.com", 1001, &out, &ol));  // oldest evicted
  CHECK(dns_cache_get(&dc, "h1.com", 1001, &out, &ol));   // others survive
}

internal void test_set_port(void) {
  struct sockaddr_in a = v4("1.2.3.4", 443);
  struct sockaddr_storage ss;
  MemoryZeroStruct(&ss);
  MemoryCopy(&ss, &a, sizeof a);
  dns_sockaddr_set_port(&ss, 8443);
  CHECK(v4_port(&ss) == 8443);
}

int main(void) {
  test_basic();
  test_evict_and_disabled();
  test_full_table_eviction();
  test_set_port();
  fprintf(stderr, "[dns_cache_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
