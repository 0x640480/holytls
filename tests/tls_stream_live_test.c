// Raw TLS stream test. Offline (always, incl. CI): a connect to a dead port
// fails gracefully (error set, clean teardown — exercised under ASan). Live
// (HOLYTLS_LIVE=1): (a) a raw HTTP/1.0 request over the stream to an HTTPS host
// (no ALPN -> the server speaks http/1.1) returns an "HTTP/" response, proving
// raw write+read over the client's fingerprinted TLS; (b) an IMAP server's
// greeting (the real use case) reads back "* OK".
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/base.h"
#include "base/defer.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/tls_stream.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

int main(void) {
  // Offline (always): a connect to a refused loopback port fails cleanly.
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/0);
    defer { client_cleanup(&c); };
    TlsStream *s =
        tls_stream_connect(&c, str8_lit("127.0.0.1"), 1, /*timeout_ms=*/2000);
    CHECK(s != 0);
    CHECK(tls_stream_error(s) != 0);  // connect refused -> error set
    // read on a failed stream returns an error, not a crash.
    U8 b[8];
    CHECK(tls_stream_read(s, b, sizeof b, 1000) < 0);
    tls_stream_free(s);  // frees cleanly (ASan job checks this)
  }

  if (!getenv("HOLYTLS_LIVE")) {
    printf("[tls_stream_live_test] offline OK; live SKIP (HOLYTLS_LIVE=1)\n");
    fprintf(stderr, "[tls_stream_live_test] %d checks, %d failures\n", g_checks,
            g_fails);
    return g_fails ? 1 : 0;
  }

  // Live (a): raw HTTP/1.0 over the stream — no ALPN, so the server picks
  // http/1.1; we read the status line back.
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/1);
    defer { client_cleanup(&c); };
    TlsStream *s = tls_stream_connect(&c, str8_lit("www.cloudflare.com"), 443,
                                      /*timeout_ms=*/30000);
    CHECK(s && !tls_stream_error(s));
    if (s && !tls_stream_error(s)) {
      String8 req = str8_lit(
          "GET / HTTP/1.0\r\nHost: www.cloudflare.com\r\nConnection: "
          "close\r\n\r\n");
      CHECK(tls_stream_write(s, req.str, req.size));
      U8 buf[4096];
      int n = tls_stream_read(s, buf, sizeof buf, 30000);
      fprintf(stderr, "  raw-http: read %d bytes, starts: %.12s\n", n,
              n > 0 ? (char *)buf : "");
      CHECK(n >= 5 && memcmp(buf, "HTTP/", 5) == 0);
    }
    if (s) tls_stream_free(s);
  }

  // Live (b): IMAP greeting (the real use case) — no creds needed.
  {
    EventLoop loop;
    loop_init(&loop);
    defer { loop_shutdown(&loop); };
    Client c;
    client_init(&c, &loop, profile_chrome148(), NULL, HttpVersion_H2,
                /*verify=*/1);
    defer { client_cleanup(&c); };
    TlsStream *s = tls_stream_connect(&c, str8_lit("imap.gmail.com"), 993,
                                      /*timeout_ms=*/30000);
    CHECK(s && !tls_stream_error(s));
    if (s && !tls_stream_error(s)) {
      U8 buf[512];
      int n = tls_stream_read(s, buf, sizeof buf, 30000);
      fprintf(stderr, "  imap: read %d bytes, starts: %.12s\n", n,
              n > 0 ? (char *)buf : "");
      CHECK(n >= 4 && memcmp(buf, "* OK", 4) == 0);
    }
    if (s) tls_stream_free(s);
  }

  fprintf(stderr, "[tls_stream_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
