// examples/powhttp_proxy.c — route holytls requests through powhttp (a MITM
// debugging proxy) so powhttp can capture the EXACT wire bytes holytls sends: the
// real ClientHello (TLS fingerprint), the HTTP/2 SETTINGS/HEADERS frames, and the
// request headers. powhttp terminates (decrypts) the TLS, presenting a per-host
// leaf cert signed by its root CA — so we trust that root with client_add_ca_file
// and keep verification ON, then point the client at the proxy with
// client_set_proxy. holytls's fingerprint is unchanged by the proxy; inspect it
// in powhttp itself (its UI, or the powhttp MCP tools get_tls / get_http2_stream
// / fingerprint).
//
// Start powhttp at 127.0.0.1:8888, then from the repo root:
//   ./build/powhttp_proxy [url] [ca.pem] [proxy-url]
// defaults: https://www.google.com/  "powhttp Root Certificate.pem"  http://127.0.0.1:8888
#include <stdio.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

typedef struct Ctx Ctx;
struct Ctx {
  B32 done;
};

static void on_response(void* user, const Response* resp) {
  Ctx* cx = (Ctx*)user;
  cx->done = 1;
  if (!resp->ok) {
    fprintf(stderr, "request failed: %s\n", resp->error ? resp->error : "?");
    return;
  }
  printf("HTTP %d  alpn=%.*s  %llu bytes  (%.*s)\n", resp->status,
         (int)resp->alpn.size, (const char*)resp->alpn.str,
         (unsigned long long)resp->body_len, (int)resp->final_url.size,
         (const char*)resp->final_url.str);
  printf("-> inspect the captured ClientHello + HTTP/2 frames in powhttp.\n");
}

int main(int argc, char** argv) {
  const char* url = argc > 1 ? argv[1] : "https://www.google.com/";
  const char* ca = argc > 2 ? argv[2] : "powhttp Root Certificate.pem";
  const char* proxy = argc > 3 ? argv[3] : "http://127.0.0.1:8888";

  EventLoop loop;
  loop_init(&loop);

  // H2-only client: a proxy forces the TCP path anyway (HTTP/3 isn't proxied
  // through an HTTP CONNECT proxy). verify=1 so powhttp's MITM cert is validated.
  Client client;
  client_init(&client, &loop, profile_chrome149(), /*verify=*/1);
  client_set_max_redirects(&client, 10);  // follow redirects, like a browser

  // Trust powhttp's root CA so its per-host MITM certs verify — no need to turn
  // verification off.
  if (!client_add_ca_file(&client, ca)) {
    fprintf(stderr, "could not load CA file: %s (run from the repo root?)\n", ca);
    client_cleanup(&client);
    loop_shutdown(&loop);
    return 1;
  }
  // Route every request through powhttp.
  if (!client_set_proxy(&client, str8_cstring(proxy), /*verify_proxy=*/0)) {
    fprintf(stderr, "bad proxy URL: %s\n", proxy);
    client_cleanup(&client);
    loop_shutdown(&loop);
    return 1;
  }

  Ctx cx = {0};
  client_get(&client, str8_cstring(url), on_response, &cx);
  loop_run(&loop);

  client_cleanup(&client);
  loop_shutdown(&loop);
  return cx.done ? 0 : 1;
}
