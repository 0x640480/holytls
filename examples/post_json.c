// examples/post_json.c — a POST with a JSON body and custom headers, reading
// the JSON response back. This is the full-control entry point: client_request
// with a RequestParams options struct (named fields = self-documenting).
// Targets httpbin.org/post, which echoes the request back as JSON so we can
// prove the round-trip.
//
// Run:  ./build/post_json
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
  printf("HTTP %d\n", resp->status);

  // httpbin echoes the request: the parsed body under "json", and the headers
  // it received under "headers". We read back content-type to confirm our
  // header set was applied (httpbin's AWS frontend strips arbitrary X-* headers
  // from its echo, so content-type is the reliable proof here).
  Arena *a = arena_alloc();
  yyjson_doc *doc = response_json(resp, a);
  if (doc) {
    printf("echoed json.client     : " STR8_Fmt "\n",
           STR8_Arg(json_ptr_str(doc, "/json/client")));
    printf("server saw content-type: " STR8_Fmt "\n",
           STR8_Arg(json_ptr_str(doc, "/headers/Content-Type")));
  }
  arena_release(a);
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);

  Client client;
  client_init(&client, &loop, profile_chrome149(), /*verify=*/1);
  client_set_timeout_ms(&client, 30000);

  // A fixed JSON body. (A dynamic shape could be built with the json_mut_*
  // helpers in core/json.h.) Content-Length is added automatically.
  String8 body = str8_lit("{\"client\":\"holytls\",\"lang\":\"c\"}");

  // Extra request headers ride ALONGSIDE Chrome's default header set — this is
  // not override mode, so user-agent / sec-ch-ua / sec-fetch-* are still sent
  // and the fingerprint is unchanged. content-type is what Chrome sends on a
  // JSON POST; x-request-id is just to show arbitrary headers go through.
  Header headers[] = {
      header_lit("content-type", "application/json"),
      header_lit("x-request-id", "holytls-demo-1"),
  };

  Ctx cx = {0};
  client_request(&client,
                 &(RequestParams){.method = Method_POST,
                                  .url = str8_lit("https://httpbin.org/post"),
                                  .headers = headers,
                                  .header_count = ArrayCount(headers),
                                  .body = body},
                 on_response, &cx);
  loop_run(&loop);

  client_cleanup(&client);
  loop_shutdown(&loop);
  return cx.done ? 0 : 1;
}
