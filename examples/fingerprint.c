// examples/fingerprint.c — prove the impersonation. holytls reproduces a real
// Chrome's TLS + HTTP/2 fingerprint byte-for-byte. This fetches tls.peet.ws —
// an oracle that reports the fingerprint IT observed on the wire — and prints
// the JA3 / JA4 (TLS) and Akamai (HTTP/2) fingerprints the server saw. Point a
// real Chrome 149 at the same URL and the hashes match.
//
// Run:  ./build/fingerprint
#include <stdio.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/json.h"
#include "net/loop.h"
#include "profile/profile.h"

typedef struct Ctx Ctx;
struct Ctx {
  B32 done;
};

static void on_response(void *user, const Response *resp) {
  Ctx *cx = (Ctx *)user;
  cx->done = 1;
  if (!resp->ok) {
    fprintf(stderr, "request failed: %s\n", resp->error ? resp->error : "?");
    return;
  }

  // Parse the JSON body into a scratch arena — the doc and the String8 views
  // into it live until we release the arena. response_json(resp, a) is just
  // json_parse(a, response_text(resp)).
  Arena *a = arena_alloc();
  yyjson_doc *doc = response_json(resp, a);
  if (!doc) {
    fprintf(stderr, "could not parse the tls.peet.ws response as JSON\n");
    arena_release(a);
    return;
  }

  // tls.peet.ws/api/all reports what it observed. These are the fingerprints
  // anti-bot systems key on; holytls reproduces Chrome's exactly.
  printf("negotiated ALPN : " STR8_Fmt "\n", STR8_Arg(resp->alpn));
  printf("user-agent      : " STR8_Fmt "\n",
         STR8_Arg(json_ptr_str(doc, "/user_agent")));
  printf("TLS  JA3 hash   : " STR8_Fmt "\n",
         STR8_Arg(json_ptr_str(doc, "/tls/ja3_hash")));
  printf("TLS  JA4        : " STR8_Fmt "\n",
         STR8_Arg(json_ptr_str(doc, "/tls/ja4")));
  printf("TLS  PeetPrint# : " STR8_Fmt "\n",
         STR8_Arg(json_ptr_str(doc, "/tls/peetprint_hash")));
  printf("HTTP/2 Akamai   : " STR8_Fmt "\n",
         STR8_Arg(json_ptr_str(doc, "/http2/akamai_fingerprint")));
  printf("HTTP/2 Akamai#  : " STR8_Fmt "\n",
         STR8_Arg(json_ptr_str(doc, "/http2/akamai_fingerprint_hash")));

  arena_release(a);
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);

  // Chrome 149 over HTTP/2 — the Akamai (HTTP/2) fingerprint needs an H2
  // connection, and JA3/JA4 come from the same ClientHello either way.
  Client client;
  client_init(&client, &loop, profile_chrome149(), /*verify=*/1);
  client_set_timeout_ms(&client, 30000);

  Ctx cx = {0};
  client_get(&client, str8_lit("https://tls.peet.ws/api/all"), on_response,
             &cx);
  loop_run(&loop);

  client_cleanup(&client);
  loop_shutdown(&loop);
  return cx.done ? 0 : 1;
}
