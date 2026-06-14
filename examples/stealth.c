// examples/stealth.c — the full Chrome-faithful configuration. A dual-transport
// client (HTTP/2 first, then HTTP/3 once the origin advertises alt-svc: h3 —
// exactly what Chrome does; it never cold-starts H3) with the browser behaviors
// holytls keeps OFF by default (so the default path is a byte-exact FRESH
// handshake every time):
//   * real ECH (encrypted SNI; GREASE when the origin publishes no config),
//   * TLS 1.3 session resumption + 0-RTT early data on reconnects.
//
// It issues three sequential requests to one origin so you can watch the
// behaviors light up: req 1 = H2 + a fresh handshake; req 2 = HTTP/3 (the
// origin's alt-svc is now cached); req 3 = a resumed handshake (maybe 0-RTT).
// The FIRST connection to an origin is always a fresh, byte-exact handshake —
// only reconnects resume.
//
// (Connection pooling — client_set_max_conns_per_origin — is left OFF here so
// each request opens its own connection and the H2->H3 upgrade is observable;
// turn it on for high-throughput reuse. See examples/session.c.)
//
// Run:  ./build/stealth [url]   (default https://www.google.com/)
#include <stdio.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

#define REQUESTS 3

typedef struct App App;
struct App {
  Client *client;
  String8 url;
  int done;
};

static void fetch_next(App *app);

static void on_response(void *user, const Response *resp) {
  App *app = (App *)user;
  app->done += 1;
  if (!resp->ok) {
    fprintf(stderr, "req %d FAILED: %s\n", app->done,
            resp->error ? resp->error : "?");
  } else {
    printf(
        "req %d: HTTP %d  alpn=" STR8_Fmt
        "  resumed=%d  early_data=%d  (dns=%llums tls=%llums total=%llums)\n",
        app->done, resp->status, STR8_Arg(resp->alpn), resp->resumed,
        resp->early_data, (unsigned long long)resp->timing.dns_ms,
        (unsigned long long)resp->timing.tls_ms,
        (unsigned long long)resp->timing.total_ms);
  }
  // Chain the next request from inside the callback (allowed — only
  // client_cleanup is forbidden here). Reusing the same Client carries the
  // alt-svc + resumption caches forward.
  if (app->done < REQUESTS) fetch_next(app);
}

static void fetch_next(App *app) {
  client_get(app->client, app->url, on_response, app);
}

int main(int argc, char **argv) {
  String8 url = str8_cstring(argc > 1 ? argv[1] : "https://www.google.com/");

  EventLoop loop;
  loop_init(&loop);

  // Dual transport: Chrome 149 over both H2 and HTTP/3.
  Client client;
  client_init_dual(&client, &loop, profile_chrome149(), profile_chrome149_h3(),
                   /*verify=*/1);

  client_set_ech_enabled(&client, 1);         // real ECH (GREASE if no config)
  client_set_resumption_enabled(&client, 1);  // TLS 1.3 ticket resumption
  client_set_early_data_enabled(&client, 1);  // 0-RTT on resumed connections
  client_set_timeout_ms(&client, 30000);

  App app = {&client, url, 0};
  fetch_next(&app);  // req 1; its callback chains 2 and 3
  loop_run(&loop);

  client_cleanup(&client);
  loop_shutdown(&loop);
  return app.done == REQUESTS ? 0 : 1;
}
