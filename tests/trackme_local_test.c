// Local cross-check against a SELF-HOSTED TrackMe (the open-source backend
// behind tls.peet.ws). It parses the raw ClientHello + H2 frames with an
// INDEPENDENT implementation, so matching it corroborates our Chrome-148 +
// wreq-template fingerprints — not just an echo of browserleaks.
//
// Setup: run a patched self-hosted TrackMe server on 127.0.0.1:8443, then
//   HOLYTLS_TRACKME=1 ./build/trackme_local_test
// Override the URL with HOLYTLS_TRACKME_URL (default
// https://localhost:8443/api/clean). Self-signed cert -> client verify=false.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/base.h"
#include "base/defer.h"
#include "core/client.h"
#include "core/json.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

typedef struct QResult QResult;
struct QResult {
  B32 got;
  char ja4[80];
  char akamai[64];
  char alpn[8];
};

internal void copy_str8(char *dst, U64 cap, String8 v) {
  U64 n = v.size < cap - 1 ? v.size : cap - 1;
  MemoryCopy(dst, v.str, n);
  dst[n] = 0;
}

internal void on_response(void *user, const Response *r) {
  QResult *q = (QResult *)user;
  if (!r->ok) {
    fprintf(stderr, "  request FAILED: %s\n", r->error ? r->error : "unknown");
    return;
  }
  q->got = 1;
  String8 body = str8((U8 *)r->body, r->body_len);
  json_get_str(body, "ja4", q->ja4, sizeof q->ja4);
  json_get_str(body, "akamai_hash", q->akamai, sizeof q->akamai);
  copy_str8(q->alpn, sizeof q->alpn, r->alpn);
}

// Drive one GET against the local oracle and pull the flat /api/clean fields.
internal QResult query(const Profile *profile, const char *url) {
  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client client;
  client_init(&client, &loop, profile, NULL, HttpVersion_H2, /*verify=*/0);
  defer { client_cleanup(&client); };
  CHECK(client_ok(&client));
  QResult q;
  MemoryZeroStruct(&q);
  client_get(&client, str8_cstring(url), on_response, &q);
  loop_run(&loop);
  return q;
}

// ja4_b is the middle (cipher-set) segment, always reliable to compare.
internal String8 ja4_b_of(const char *ja4) {
  String8 s = str8_cstring(ja4);
  S64 u1 = -1, u2 = -1;
  for (U64 i = 0; i < s.size; ++i)
    if (s.str[i] == '_') {
      if (u1 < 0) u1 = (S64)i;
      u2 = (S64)i;
    }
  if (u1 < 0 || u2 == u1) return str8_zero();
  return str8(s.str + u1 + 1, (U64)(u2 - u1 - 1));
}

int main(void) {
  if (!getenv("HOLYTLS_TRACKME")) {
    printf(
        "[trackme_local_test] SKIP (set HOLYTLS_TRACKME=1 + run a local "
        "TrackMe)\n");
    return 0;
  }
  const char *url = getenv("HOLYTLS_TRACKME_URL");
  if (!url) url = "https://localhost:8443/api/clean";
  fprintf(stderr, "[trackme_local_test] oracle = %s\n", url);

  // --- wreq template profile -> the wreq golden fingerprints ---
  {
    QResult q = query(profile_template(), url);
    CHECK(q.got);
    fprintf(stderr, "[template ] alpn=%s ja4=%s akamai=%s\n", q.alpn, q.ja4,
            q.akamai);
    CHECK(strcmp(q.alpn, "h2") == 0);
    CHECK(str8_match(str8_cstring(q.akamai),
                     str8_lit("6ea73faa8fc5aac76bded7bd238f6433")));
    CHECK(str8_match(ja4_b_of(q.ja4), str8_lit("5b57614c22b0")));
#ifdef HOLYTLS_TLS_FORK
    CHECK(str8_match(str8_cstring(q.ja4),
                     str8_lit("t13d1717h2_5b57614c22b0_3cbfd9057e0d")));
#endif
  }

  // --- Chrome 148 H2/TCP profile -> Chrome golden fingerprints ---
  {
    QResult q = query(profile_chrome148(), url);
    CHECK(q.got);
    fprintf(stderr, "[chrome148] alpn=%s ja4=%s akamai=%s\n", q.alpn, q.ja4,
            q.akamai);
    CHECK(strcmp(q.alpn, "h2") == 0);
    CHECK(str8_match(str8_cstring(q.akamai),
                     str8_lit("52d84b11737d980aef856699f885ca86")));
    CHECK(str8_match(str8_cstring(q.ja4),
                     str8_lit("t13d1516h2_8daaf6152771_d8a2da3f94cd")));
  }

  fprintf(stderr, "[trackme_local_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
