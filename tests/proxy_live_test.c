// Live proxy test (gated by HOLYTLS_LIVE=1). Reads the proxies to exercise from
// the HOLYTLS_PROXIES env var (';'-separated "scheme://host:port:user:pass") so
// no credentials live in the source. For each it fetches a real HTTPS endpoint
// through the proxy, asserting the tunnel + target TLS deliver a 200. Skipped
// (pass) when HOLYTLS_LIVE or HOLYTLS_PROXIES is unset, so it never breaks CI.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

// The egress IP echo target: returns the caller's public IP as plain text, so a
// working proxy visibly changes the result from a direct connection.
#define TARGET_URL "https://api.ipify.org/"

global EventLoop *g_loop;
global B32 g_ok;
global int g_status;
global char g_body[256];
global char g_alpn[16];

internal void on_resp(void *user, const Response *r) {
  (void)user;
  g_ok = r->ok;
  g_status = r->status;
  U64 n = r->body_len < sizeof g_body - 1 ? r->body_len : sizeof g_body - 1;
  if (r->body && n) MemoryCopy(g_body, r->body, n);
  g_body[n] = 0;
  U64 an = r->alpn.size < sizeof g_alpn - 1 ? r->alpn.size : sizeof g_alpn - 1;
  if (r->alpn.str && an) MemoryCopy(g_alpn, r->alpn.str, an);
  g_alpn[an] = 0;
  uv_stop(loop_uv(g_loop));
}
internal void wd_cb(uv_timer_t *t) {
  (void)t;
  uv_stop(loop_uv(g_loop));
}

// Convert "scheme://host:port:user:pass" -> "scheme://user:pass@host:port".
internal B32 to_proxy_url(Arena *a, String8 line, String8 *out) {
  S64 sep = str8_find(line, str8_lit("://"));
  if (sep < 0) return 0;
  String8 scheme = str8_prefix(line, (U64)sep);
  String8 rest = str8_skip(line, (U64)sep + 3);
  String8 host = str8_chop_by_delim(&rest, ':');
  String8 port = str8_chop_by_delim(&rest, ':');
  String8 user = str8_chop_by_delim(&rest, ':');
  String8 pass = rest;  // remainder (may itself contain ':')
  if (host.size == 0 || port.size == 0) return 0;
  *out = push_str8f(
      a, STR8_Fmt "://" STR8_Fmt ":" STR8_Fmt "@" STR8_Fmt ":" STR8_Fmt,
      STR8_Arg(scheme), STR8_Arg(user), STR8_Arg(pass), STR8_Arg(host),
      STR8_Arg(port));
  return 1;
}

internal B32 fetch_via(String8 proxy_url) {
  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  g_ok = 0;
  g_status = 0;
  g_body[0] = 0;
  g_alpn[0] = 0;

  Client c;
  client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  CHECK(client_set_proxy(&c, proxy_url, /*verify_proxy=*/0));

  uv_timer_t wd;
  uv_timer_init(loop_uv(&loop), &wd);
  uv_timer_start(&wd, wd_cb, 20000, 0);

  client_get(&c, str8_lit(TARGET_URL), on_resp, 0);
  loop_run(&loop);

  uv_timer_stop(&wd);
  uv_close((uv_handle_t *)&wd, 0);
  client_cleanup(&c);
  loop_shutdown(&loop);
  return g_ok && g_status == 200;
}

// Forced HTTP/3 through a SOCKS5 (UDP-capable) proxy: the QUIC handshake
// tunnels over UDP ASSOCIATE. An H3-capable target that echoes the egress IP.
#define H3_TARGET_URL "https://www.cloudflare.com/cdn-cgi/trace"
internal B32 fetch_via_h3(String8 proxy_url) {
  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  g_ok = 0;
  g_status = 0;
  g_body[0] = 0;
  g_alpn[0] = 0;

  Client c;
  client_init(&c, &loop, profile_chrome148(), profile_chrome148_h3(),
              HttpVersion_Auto, /*verify=*/1);
  CHECK(client_set_proxy(&c, proxy_url, /*verify_proxy=*/0));
  client_set_http_version(&c,
                          HttpVersion_H3);  // force QUIC (no alt-svc warmup)

  uv_timer_t wd;
  uv_timer_init(loop_uv(&loop), &wd);
  uv_timer_start(&wd, wd_cb, 25000, 0);

  client_get(&c, str8_lit(H3_TARGET_URL), on_resp, 0);
  loop_run(&loop);

  uv_timer_stop(&wd);
  uv_close((uv_handle_t *)&wd, 0);
  client_cleanup(&c);
  loop_shutdown(&loop);
  return g_ok && g_status == 200 && strcmp(g_alpn, "h3") == 0;
}

// One GET on an existing client + loop (for the runtime-rotation block, which
// keeps a single client across switches). Returns 200-ok; leaves the IP in
// g_body.
internal B32 live_get(EventLoop *loop, uv_timer_t *wd, Client *c) {
  g_ok = 0;
  g_status = 0;
  g_body[0] = 0;
  uv_timer_start(wd, wd_cb, 20000, 0);
  client_get(c, str8_lit(TARGET_URL), on_resp, 0);
  loop_run(loop);
  uv_timer_stop(wd);
  return g_ok && g_status == 200;
}

// Runtime proxy switching on ONE client: direct -> each proxy -> back to
// direct, asserting the egress IP changes under a proxy and returns to the
// direct IP after set_proxy(""). Proves client_set_proxy is safe to call
// between requests.
internal void run_rotation(Arena *a, const String8 *proxies, U64 count) {
  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  Client c;
  client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  uv_timer_t wd;
  uv_timer_init(loop_uv(&loop), &wd);
  uv_unref((uv_handle_t *)&wd);

  char direct_ip[sizeof g_body];
  CHECK(live_get(&loop, &wd, &c));  // direct first
  snprintf(direct_ip, sizeof direct_ip, "%s", g_body);
  fprintf(stderr, "  [rotate direct] ip=%s\n", direct_ip);

  for (U64 i = 0; i < count; ++i) {
    String8 s = proxies[i];
    String8 purl;
    if (!to_proxy_url(a, s, &purl)) continue;
    String8 scheme = str8_prefix(s, (U64)str8_find(s, str8_lit("://")));
    CHECK(client_set_proxy(&c, purl, /*verify_proxy=*/0));
    B32 ok = live_get(&loop, &wd, &c);
    CHECK(ok && strcmp(g_body, direct_ip) != 0);  // proxied IP != direct IP
    fprintf(stderr, "  [rotate " STR8_Fmt "] ip=%s differs=%d\n",
            STR8_Arg(scheme), g_body, strcmp(g_body, direct_ip) != 0);
  }

  CHECK(client_set_proxy(&c, str8_lit(""),
                         /*verify_proxy=*/0));  // back to direct
  CHECK(live_get(&loop, &wd, &c));
  CHECK(strcmp(g_body, direct_ip) ==
        0);  // same egress IP as the first direct call
  fprintf(stderr, "  [rotate direct] ip=%s (restored)\n", g_body);

  uv_close((uv_handle_t *)&wd, 0);
  client_cleanup(&c);
  loop_shutdown(&loop);
}

internal void run_proxy(Arena *a, String8 s) {
  if (s.size == 0 || s.str[0] == '#') return;
  String8 purl;
  if (!to_proxy_url(a, s, &purl)) {
    fprintf(stderr, "  bad proxy: " STR8_Fmt "\n", STR8_Arg(s));
    return;
  }
  String8 scheme = str8_prefix(s, (U64)str8_find(s, str8_lit("://")));
  B32 ok = fetch_via(purl);
  CHECK(ok);
  fprintf(stderr, "  [" STR8_Fmt " h2] status=%d ip=%s -> %s\n",
          STR8_Arg(scheme), g_status, g_body, ok ? "PASS" : "FAIL");

  // A *UDP-capable* SOCKS5 proxy can also carry HTTP/3 (UDP ASSOCIATE). Only
  // such proxies support it (some providers flag them with a `udp.` host); a
  // plain SOCKS5 proxy has no UDP relay, so H3 would correctly fail there.
  if (str8_starts_with(s, str8_lit("socks5://")) &&
      str8_contains_ci(s, str8_lit("udp"))) {
    B32 h3ok = fetch_via_h3(purl);
    CHECK(h3ok);
    fprintf(stderr, "  [" STR8_Fmt " h3] status=%d alpn=%s -> %s\n",
            STR8_Arg(scheme), g_status, g_alpn, h3ok ? "PASS" : "FAIL");
  }
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    fprintf(stderr, "[proxy_live_test] skipped (set HOLYTLS_LIVE=1)\n");
    return 0;
  }

  const char *env = getenv("HOLYTLS_PROXIES");
  if (!env || !env[0]) {
    fprintf(stderr,
            "[proxy_live_test] skipped: set HOLYTLS_PROXIES (';'-separated "
            "\"scheme://host:port:user:pass\")\n");
    return 0;
  }

  Arena *a = arena_alloc();
  // Parse the ';'-separated proxy list from the env (no creds in the source).
  String8 proxies[16];
  U64 n = 0;
  String8 rest = str8_cstring(env);
  while (rest.size && n < ArrayCount(proxies)) {
    String8 one = str8_trim(str8_chop_by_delim(&rest, ';'));
    if (one.size && one.str[0] != '#') proxies[n++] = one;
  }
  for (U64 i = 0; i < n; ++i) run_proxy(a, proxies[i]);
  if (n) {
    fprintf(stderr, "  --- runtime rotation (one client) ---\n");
    run_rotation(a, proxies,
                 n);  // switch proxies mid-session on a single client
  }
  arena_release(a);
  fprintf(stderr, "[proxy_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
