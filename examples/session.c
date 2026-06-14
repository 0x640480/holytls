// examples/session.c — stateful browsing with the Session layer: a cookie jar +
// browser-faithful redirect following on top of a shared Client. Sessions are
// lightweight (no loop or socket of their own), so thousands run concurrently
// on one shared transport — "one Session per task". This drives a small cookie
// flow on httpbin.org: set a cookie (a 302 the Session follows), then read it
// back to prove the jar carried it across requests.
//
// Optional proxy: set PROXY=socks5://user:pass@host:port (or http://… /
// socks5h://…) to route every request through it — the target's TLS fingerprint
// is unchanged either way.
//
// Run:  [PROXY=socks5://…] ./build/session
#include "core/session.h"

#include <stdio.h>
#include <stdlib.h>  // getenv

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"

typedef struct App App;
struct App {
  Client *client;
  Session *session;
  int step;
};

static void on_read(void *user, const Response *resp) {
  App *app = (App *)user;
  app->step = 2;
  if (!resp->ok) {
    fprintf(stderr, "read failed: %s\n", resp->error ? resp->error : "?");
    return;
  }
  // The jar carried the cookie set on the previous request:
  // {"cookies": {"flavor": "chocolate"}}
  printf("cookie read : HTTP %d  " STR8_Fmt "\n", resp->status,
         STR8_Arg(response_text(resp)));
}

static void on_set(void *user, const Response *resp) {
  App *app = (App *)user;
  if (!resp->ok) {
    fprintf(stderr, "set failed: %s\n", resp->error ? resp->error : "?");
    return;
  }
  // The Session followed the 302 and absorbed the Set-Cookie along the way.
  printf("set + follow: HTTP %d -> " STR8_Fmt "\n", resp->status,
         STR8_Arg(resp->final_url));
  // Reuse the same Session (its jar) and Client (its warm pooled connection).
  session_get(app->session, app->client,
              str8_lit("https://httpbin.org/cookies"), on_read, app);
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);

  // One shared transport for all sessions. Connection pooling lets the
  // session's requests reuse one multiplexed connection (Chrome-like: 1 per
  // origin).
  Client client;
  client_init(&client, &loop, profile_chrome149(), /*verify=*/1);
  client_set_max_conns_per_origin(&client, 1);
  client_set_timeout_ms(&client, 30000);

  // A Session = a cookie jar + a redirect budget. Cheap; one per task.
  SessionConfig cfg;
  session_config_default(&cfg);  // cookies on, follow up to 10 redirects
  Session session;
  session_init(&session, &cfg);

  // /cookies/set/<k>/<v> sets a cookie then 302s to /cookies; the Session
  // follows the redirect AND stores the cookie as it passes through.
  App app = {&client, &session, 0};
  session_get(&session, &client,
              str8_lit("https://httpbin.org/cookies/set/flavor/chocolate"),
              on_set, &app);
  loop_run(&loop);

  session_cleanup(&session);
  client_cleanup(&client);
  loop_shutdown(&loop);
  return app.step == 2 ? 0 : 1;
}
