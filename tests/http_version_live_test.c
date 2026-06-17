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
// Fetch with a PER-REQUEST http_version override (the client default is untouched).
internal Ctx fetch_ver(Client *c, EventLoop *loop, const char *url,
                       HttpVersion v) {
  Ctx cx;
  MemoryZeroStruct(&cx);
  RequestParams p = {0};
  p.method = Method_GET;
  p.url = str8_cstring(url);
  p.http_version = v;
  client_request(c, &p, on_resp, &cx);
  loop_run(loop);
  return cx;
}

int main(void) {
  // Offline (always runs, incl. CI): a PER-REQUEST H1 override needs c->h1_tls
  // built at client_init even on an H2 client. Assert the http/1.1-only ALPN
  // profile is present (encodes "\x08http/1.1"), ALPS dropped, and that it
  // differs from the H2 profile (which offers h2+http/1.1, len 12).
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/0);
    defer { client_cleanup(&c); };
    CHECK(c.h1_tls.alpn_wire_len == 9 && c.h1_tls.alpn_wire &&
          c.h1_tls.alpn_wire[0] == 8 &&
          memcmp(c.h1_tls.alpn_wire + 1, "http/1.1", 8) == 0);
    CHECK(c.h1_tls.alps_count == 0);
    CHECK(c.profile->tls.alpn_wire_len == 12);  // H2 offers h2 + http/1.1
  }

  if (!getenv("HOLYTLS_LIVE")) {
    printf("[http_version_live_test] offline OK; live SKIP (HOLYTLS_LIVE=1)\n");
    fprintf(stderr, "[http_version_live_test] %d checks, %d failures\n",
            g_checks, g_fails);
    return g_fails ? 1 : 0;
  }
  const char *url = "https://www.cloudflare.com/";

  //- force HTTP/2 -------------------------------------------------------------
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/1);
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
    client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/1);
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
    client_init(&c, &loop, profile_chrome148(), profile_chrome148_h3(),
                HttpVersion_Auto, /*verify=*/1);
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
    client_init(&c, &loop, profile_chrome148(), profile_chrome148_h3(),
                HttpVersion_Auto, /*verify=*/1);
    defer { client_cleanup(&c); };
    Ctx r = fetch(&c, &loop, url);
    fprintf(stderr, "  auto:     ok=%d status=%d alpn=%s\n", r.ok, r.status,
            r.alpn);
    CHECK(r.ok && r.status == 200);
    CHECK(strcmp(r.alpn, "h2") == 0);  // Chrome-faithful: no cold H3
  }

  //- PER-REQUEST override: H1 for one request on an H2-default client ---------
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/1);  // client default stays H2
    defer { client_cleanup(&c); };
    Ctx h1 = fetch_ver(&c, &loop, url, HttpVersion_H1);  // force H1 this request
    Ctx h2 = fetch(&c, &loop, url);  // inherits the H2 default -> h2
    fprintf(stderr, "  per-req: forced-h1 alpn=%s  default alpn=%s\n", h1.alpn,
            h2.alpn);
    CHECK(h1.ok && h1.status == 200 && strcmp(h1.alpn, "http/1.1") == 0);
    CHECK(h2.ok && h2.status == 200 &&
          strcmp(h2.alpn, "h2") == 0);  // override didn't disturb the client
  }

  fprintf(stderr, "[http_version_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
