#include "tls/keylog.h"

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

// Process-global key-log destination. uv_once guarantees the mutex is
// initialized before g_kl_file is ever set, so any thread that observes a
// non-NULL g_kl_file can safely take g_kl_mu.
internal uv_once_t g_kl_once = UV_ONCE_INIT;
internal uv_mutex_t g_kl_mu;
internal FILE *g_kl_file;  // guarded by g_kl_mu

internal void kl_mutex_init(void) { uv_mutex_init(&g_kl_mu); }

B32 keylog_open(const char *path) {
  if (!path || !*path) return 0;
  uv_once(&g_kl_once, kl_mutex_init);
  uv_mutex_lock(&g_kl_mu);
  if (!g_kl_file) g_kl_file = fopen(path, "a");  // first destination wins
  B32 ok = g_kl_file != 0;
  uv_mutex_unlock(&g_kl_mu);
  return ok;
}

void keylog_init_from_env(void) {
  const char *p = getenv("SSLKEYLOGFILE");
  if (p && *p) keylog_open(p);
}

B32 keylog_enabled(void) { return g_kl_file != 0; }

void keylog_callback(const SSL *ssl, const char *line) {
  (void)ssl;
  if (!g_kl_file) return;  // disabled fast-path (file, once set, stays set)
  uv_mutex_lock(&g_kl_mu);
  if (g_kl_file) {
    fputs(line, g_kl_file);
    fputc('\n', g_kl_file);
    fflush(
        g_kl_file);  // a complete line per secret, visible to a live Wireshark
  }
  uv_mutex_unlock(&g_kl_mu);
}
