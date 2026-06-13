// Live http-version test: force each protocol and confirm the negotiated ALPN.
//   force H2  -> "h2"          force H1 -> "http/1.1"
//   force H3  -> "h3" on the FIRST request (cold QUIC, no alt-svc warmup)
//   Auto      -> "h2" first    (Chrome-faithful: never cold-starts H3)
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/base.h"
#include "base/defer.h"
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
  B32 ok;
  int status;
  char alpn[16];
};
internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->ok = r->ok;
  cx->status = r->status;
  U64 n =
      r->alpn.size < sizeof cx->alpn - 1 ? r->alpn.size : sizeof cx->alpn - 1;
  if (r->alpn.str && n) MemoryCopy(cx->alpn, r->alpn.str, n);
  cx->alpn[n] = 0;
  if (!r->ok)
    fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
}
internal Ctx fetch(Client *c, EventLoop *loop, const char *url) {
  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(c, str8_cstring(url), on_resp, &cx);
  loop_run(loop);
  return cx;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[http_version_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  const char *url = "https://www.cloudflare.com/";

  //- force HTTP/2 -------------------------------------------------------------
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
    defer { client_cleanup(&c); };
    client_set_http_version(&c, HttpVersion_H2);
    Ctx r = fetch(&c, &loop, url);
    fprintf(stderr, "  force h2: ok=%d status=%d alpn=%s\n", r.ok, r.status,
            r.alpn);
    CHECK(r.ok && r.status == 200);
    CHECK(strcmp(r.alpn, "h2") == 0);
  }

  //- force HTTP/1.1 -----------------------------------------------------------
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
    defer { client_cleanup(&c); };
    client_set_http_version(&c, HttpVersion_H1);
    Ctx r = fetch(&c, &loop, url);
    fprintf(stderr, "  force h1: ok=%d status=%d alpn=%s\n", r.ok, r.status,
            r.alpn);
    CHECK(r.ok && r.status == 200);
    CHECK(strcmp(r.alpn, "http/1.1") == 0);
  }

  //- force HTTP/3 (dual client; cold QUIC on the first request) ---------------
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init_dual(&c, &loop, profile_chrome148(), profile_chrome148_h3(),
                     /*verify=*/1);
    defer { client_cleanup(&c); };
    client_set_http_version(&c, HttpVersion_H3);
    Ctx r = fetch(&c, &loop, url);
    fprintf(stderr, "  force h3: ok=%d status=%d alpn=%s\n", r.ok, r.status,
            r.alpn);
    CHECK(r.ok && r.status == 200);
    CHECK(strcmp(r.alpn, "h3") == 0);  // QUIC on the very first request
  }

  //- Auto control (dual): first request is H2, not cold H3 --------------------
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init_dual(&c, &loop, profile_chrome148(), profile_chrome148_h3(),
                     /*verify=*/1);
    defer { client_cleanup(&c); };
    Ctx r = fetch(&c, &loop, url);
    fprintf(stderr, "  auto:     ok=%d status=%d alpn=%s\n", r.ok, r.status,
            r.alpn);
    CHECK(r.ok && r.status == 200);
    CHECK(strcmp(r.alpn, "h2") == 0);  // Chrome-faithful: no cold H3
  }

  fprintf(stderr, "[http_version_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
