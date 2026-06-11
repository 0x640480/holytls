// Live TLS key-log test: set SSLKEYLOGFILE, make a real request, and assert
// BoringSSL exported the TLS 1.3 traffic secrets to the file in NSS Key Log
// Format (the env path is what Wireshark users actually set). The same callback
// also exports QUIC secrets; this exercises the TLS-over-TCP path.
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>

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

typedef struct Ctx Ctx;
struct Ctx {
  B32 got;
  int status;
};

internal void on_resp(void* user, const Response* r) {
  Ctx* cx = (Ctx*)user;
  cx->got = r->ok;
  cx->status = r->status;
  if (!r->ok)
    fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[key_log_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  const char* path = "/tmp/holytls_keylog_live.key";
  remove(path);
  setenv("SSLKEYLOGFILE", path, 1);  // build_ctx auto-enables from the env var

  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
  CHECK(client_ok(&c));

  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(&c, str8_cstring("https://www.cloudflare.com/"), on_resp, &cx);
  loop_run(&loop);
  CHECK(cx.got && cx.status == 200);

  client_cleanup(&c);
  loop_shutdown(&loop);

  // The handshake's TLS 1.3 secrets must now be in the key-log file.
  char buf[16384];
  FILE* f = fopen(path, "rb");
  CHECK(f != 0);
  U64 n = f ? fread(buf, 1, sizeof buf - 1, f) : 0;
  if (f) fclose(f);
  buf[n] = 0;
  String8 s = str8((U8*)buf, n);
  fprintf(stderr, "  key log: %llu bytes\n", (unsigned long long)n);
  CHECK(n > 0);
  CHECK(
      str8_contains(s, str8_lit("TRAFFIC_SECRET")));  // TLS 1.3 secrets present

  remove(path);
  fprintf(stderr, "[key_log_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
