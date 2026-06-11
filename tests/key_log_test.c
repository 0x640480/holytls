// Offline TLS key-log tests: the writer plumbing + NSS Key Log Format output, and
// the process-global "first destination wins" semantics. The real-handshake export
// (BoringSSL invoking the callback with live secrets) is covered by
// key_log_live_test.
#include <stdio.h>
#include <string.h>

#include "base/base.h"
#include "base/defer.h"
#include "base/string8.h"
#include "tls/keylog.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

// Read a whole file into `buf` (NUL-terminated); returns bytes read (0 if absent).
internal U64 slurp(const char *path, char *buf, U64 cap) {
  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  defer { fclose(f); };
  U64 n = fread(buf, 1, cap - 1, f);
  buf[n] = 0;
  return n;
}

int main(void) {
  const char *path = "/tmp/holytls_keylog_test.key";
  const char *other = "/tmp/holytls_keylog_other.key";
  remove(path);
  remove(other);

  CHECK(!keylog_enabled());      // off until a destination is set
  CHECK(!keylog_open(0));        // null path rejected
  CHECK(!keylog_open(""));       // empty path rejected
  CHECK(keylog_open(path));      // opens the destination
  CHECK(keylog_enabled());

  // The callback writes NSS Key Log Format lines (one secret per line + '\n').
  keylog_callback(0, "CLIENT_HANDSHAKE_TRAFFIC_SECRET aabb ccdd");
  keylog_callback(0, "SERVER_TRAFFIC_SECRET_0 1122 3344");

  char buf[8192];
  U64 n = slurp(path, buf, sizeof buf);
  CHECK(n > 0);
  String8 s = str8((U8 *)buf, n);
  CHECK(str8_contains(s, str8_lit("CLIENT_HANDSHAKE_TRAFFIC_SECRET aabb ccdd\n")));
  CHECK(str8_contains(s, str8_lit("SERVER_TRAFFIC_SECRET_0 1122 3344\n")));

  // First-destination-wins: a second open does not switch the file.
  CHECK(keylog_open(other));  // returns 1 (already open) but keeps `path`
  keylog_callback(0, "EXPORTER_SECRET ee ff");
  n = slurp(path, buf, sizeof buf);
  CHECK(str8_contains(str8((U8 *)buf, n), str8_lit("EXPORTER_SECRET ee ff\n")));
  CHECK(slurp(other, buf, sizeof buf) == 0);  // the other path was never created

  remove(path);
  remove(other);
  fprintf(stderr, "[key_log_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
