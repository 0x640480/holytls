// Offline timing tests: conn_timing_ms / quic_conn_timing_ms phase arithmetic
// and the pooled-reuse gate (setup phases report 0 when the connection was
// already established before the request started). Live end-to-end timing is in
// timing_live_test.
#include <stdio.h>

#include "base/base.h"
#include "core/client.h"
#include "net/connection.h"
#include "net/quic_connection.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

#define MS 1000000ULL  // ns per ms

internal void test_tcp(void) {
  Connection c;
  MemoryZeroStruct(&c);
  c.t_connect_start_ns = 1 * MS;
  c.t_resolved_ns = 3 * MS;      // dns = 2ms
  c.t_connected_ns = 6 * MS;     // tcp = 3ms
  c.t_established_ns = 10 * MS;  // tls = 4ms

  U64 dns, tcp, tls;
  // Request started before the connection was established -> real phases.
  conn_timing_ms(&c, /*req_start=*/0, &dns, &tcp, &tls);
  CHECK(dns == 2 && tcp == 3 && tls == 4);

  // Reuse: request started after the connection was already established -> 0s.
  conn_timing_ms(&c, /*req_start=*/11 * MS, &dns, &tcp, &tls);
  CHECK(dns == 0 && tcp == 0 && tls == 0);

  // Never established -> 0s.
  Connection nc;
  MemoryZeroStruct(&nc);
  conn_timing_ms(&nc, 0, &dns, &tcp, &tls);
  CHECK(dns == 0 && tcp == 0 && tls == 0);
}

internal void test_quic(void) {
  QuicConnection c;
  MemoryZeroStruct(&c);
  c.t_connect_start_ns = 1 * MS;
  c.t_resolved_ns = 2 * MS;      // dns = 1ms
  c.t_established_ns = 12 * MS;  // tls = 10ms (combined QUIC handshake)

  U64 dns, tcp, tls;
  quic_conn_timing_ms(&c, /*req_start=*/0, &dns, &tcp, &tls);
  CHECK(dns == 1 && tcp == 0 && tls == 10);  // QUIC: no separate TCP phase

  quic_conn_timing_ms(&c, /*req_start=*/13 * MS, &dns, &tcp, &tls);  // reuse
  CHECK(dns == 0 && tcp == 0 && tls == 0);
}

internal void test_zero_init(void) {
  Response r;
  MemoryZeroStruct(&r);
  CHECK(r.timing.dns_ms == 0 && r.timing.tcp_ms == 0 && r.timing.tls_ms == 0 &&
        r.timing.total_ms == 0);
}

int main(void) {
  test_tcp();
  test_quic();
  test_zero_init();
  fprintf(stderr, "[timing_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
