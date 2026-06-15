// Fuzz client-state restore: arbitrary bytes as the persisted JSON fed to
// client_state_unmarshal against a REAL Client. Unlike fuzz_persist (null
// Client, cookies only), this exercises the transport-cache restore the other
// harness skips — TLS resumption tickets, Alt-Svc, and ECH: each is a JSON walk
// + base64-decode + cache insert (the BoringSSL ticket import sits on the far
// side). The Client is built once (lazily, so this also works under the gcc
// standalone driver, which has no LLVMFuzzerInitialize hook); unmarshal MERGES
// into the Client's bounded, LRU-capped caches, so state carries across inputs
// — a crash in the parse/decode/insert glue still reproduces from a single
// input.
#include "core/client.h"
#include "core/persist.h"
#include "fuzz/fuzz.h"
#include "net/loop.h"
#include "profile/profile.h"

static EventLoop g_loop;
static Client g_client;
static B32
    g_inited;  // reachable static -> LSan sees the Client as still-reachable

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!g_inited) {
    loop_init(&g_loop);
    client_init(&g_client, &g_loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/0);
    g_inited = 1;
  }
  client_state_unmarshal(&g_client, fuzz_str8(data, size));
  return 0;
}
