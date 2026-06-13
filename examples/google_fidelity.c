// examples/google_fidelity.c — fetch https://www.google.com/ with holytls's
// highest-fidelity Chrome configuration:
//   * dual transport: HTTP/2 first, then HTTP/3 once the origin advertises
//     alt-svc: h3 — exactly what Chrome does (it never cold-starts H3);
//   * certificate verification on;
//   * real ECH (encrypted SNI when the origin publishes a config, GREASE if
//   not);
//   * TLS 1.3 session resumption + 0-RTT early data on reconnects;
//   * a cookie jar + browser-faithful redirect following (the Session layer);
//   * the profile's full navigation header set (user-agent, sec-ch-ua,
//     sec-fetch-*, accept, …) — i.e. NOT override_default_headers.
// It issues a few sequential requests so the fidelity features are observable:
// request 1 is H2 + a fresh handshake; once Google's alt-svc is cached, request
// 2 upgrades to HTTP/3; request 3 reconnects and resumes (and may send 0-RTT).
//
// Build: add a CMake target like the other examples; run
// ./build/google_fidelity.
#include <stdio.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/session.h"
#include "net/loop.h"
#include "profile/profile.h"

#define GOOGLE_URL \
  "https://www.walmart.com/"  // where google.com 301-redirects to
#define REQUESTS 3

typedef struct App App;
struct App {
  Client *client;
  Session *session;
  int done;
};

static void fetch_next(App *app);

static void on_response(void *user, const Response *resp) {
  App *app = (App *)user;
  app->done += 1;
  if (!resp->ok) {
    fprintf(stderr, "request %d FAILED: %s\n", app->done,
            resp->error ? resp->error : "unknown");
  } else {
    printf(
        "request %d: HTTP %d  alpn=%-3.*s  resumed=%d  early_data=%d  %llu "
        "bytes "
        "(%.*s)\n",
        app->done, resp->status, (int)resp->alpn.size,
        (const char *)resp->alpn.str, resp->resumed, resp->early_data,
        (unsigned long long)resp->body_len, (int)resp->final_url.size,
        (const char *)resp->final_url.str);
  }
  // Chain the next request from inside the callback (allowed — only
  // client_cleanup is forbidden here). Reusing the same Client carries the
  // alt-svc + session caches forward, so request 2 upgrades H2 -> HTTP/3 and
  // request 3 resumes.
  if (app->done < REQUESTS) fetch_next(app);
}

static void fetch_next(App *app) {
  // session_get sends the profile's full navigation header set — the complete
  // Chrome request shape (no override_default_headers here, on purpose).
  session_get(app->session, app->client, str8_lit(GOOGLE_URL), on_response,
              app);
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);

  // Fingerprint + transport: Chrome 149 over both H2 and HTTP/3. Dual transport
  // means H2 first, then QUIC once an origin advertises alt-svc: h3 (exactly
  // what Chrome does). verify = validate the server certificate (Chrome does).
  Client client;
  client_init_dual(&client, &loop, profile_chrome149(), profile_chrome149_h3(),
                   /*verify=*/1);

  // Behaviors a real Chrome exhibits. These are OFF by default in holytls so
  // the default path is a byte-exact FRESH handshake; turned on here for
  // fidelity to real browsing. The FIRST connection to an origin is always a
  // fresh, byte- exact handshake regardless — only reconnects resume / send
  // 0-RTT.
  client_set_ech_enabled(&client,
                         1);  // real ECH (encrypted SNI; GREASE if none)
  client_set_resumption_enabled(&client, 1);  // TLS 1.3 ticket resumption
  client_set_early_data_enabled(&client,
                                1);       // 0-RTT early data on resumed conns
  client_set_timeout_ms(&client, 30000);  // whole-operation deadline

  // A Session adds the cookie jar + browser-faithful redirect following.
  SessionConfig cfg;
  session_config_default(&cfg);  // cookies on, follow up to 10 redirects
  Session session;
  session_init(&session, &cfg);

  App app = {&client, &session, 0};
  fetch_next(&app);  // request 1; the callback chains the rest
  loop_run(&loop);   // drives all REQUESTS to completion

  session_cleanup(&session);
  client_cleanup(&client);
  loop_shutdown(&loop);
  return 0;
}
