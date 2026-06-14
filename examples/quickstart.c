// examples/quickstart.c — the smallest complete holytls program. Spin up a
// libuv loop, create a Chrome-fingerprinted client, issue one async GET, and
// read the response in the callback.
//
// holytls is ASYNC: you submit a request and the response arrives in a callback
// when loop_run drives the loop — there is no blocking client.Do(). The
// response headers/body are valid ONLY during the callback (copy out anything
// you keep).
//
// Run:  ./build/quickstart [url]   (default https://tls.peet.ws/api/all)
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

static void on_response(void *user, const Response *resp) {
  Ctx *cx = (Ctx *)user;
  cx->done = 1;
  if (!resp->ok) {  // a transport/TLS failure, NOT an HTTP error status
    fprintf(stderr, "request failed: %s\n", resp->error ? resp->error : "?");
    return;
  }

  // Response accessors — call them only here; the views die when we return.
  String8 ctype = response_get_header(resp, str8_lit("content-type"));
  String8 body = response_text(resp);
  printf("HTTP %d over %s  (%llu bytes, content-type: " STR8_Fmt ")\n",
         resp->status, response_is_success(resp) ? "ok" : "non-2xx",
         (unsigned long long)resp->body_len, STR8_Arg(ctype));

  // A taste of the body (first 200 bytes).
  U64 n = body.size < 200 ? body.size : 200;
  printf("%.*s%s\n", (int)n, (const char *)body.str,
         body.size > n ? " ..." : "");
}

int main(int argc, char **argv) {
  String8 url =
      str8_cstring(argc > 1 ? argv[1] : "https://tls.peet.ws/api/all");

  EventLoop loop;
  loop_init(&loop);

  // The fingerprint lives on the Client: this one impersonates Chrome 149 over
  // HTTP/2. verify=1 validates the server certificate, exactly as a browser
  // does. (client_init_dual(.., profile_chrome149_h3(), ..) would add HTTP/3.)
  Client client;
  client_init(&client, &loop, profile_chrome149(), /*verify=*/1);
  client_set_timeout_ms(&client, 30000);  // give up after 30s

  Ctx cx = {0};
  client_get(&client, url, on_response, &cx);  // submit; nothing runs yet...
  loop_run(&loop);  // ...this drives it to completion

  client_cleanup(&client);
  loop_shutdown(&loop);
  return cx.done ? 0 : 1;
}
