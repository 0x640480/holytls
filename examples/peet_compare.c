// holytls equivalent of the bogdanfinn/tls-client (Go) "GET
// tls.peet.ws/api/all" example. The big structural difference: holytls is ASYNC
// — you submit a request and the response arrives in a callback when the libuv
// loop runs; there is no blocking client.Do(). The response body is
// arena-scoped and valid only during the callback (use/copy it there). Build:
// add to CMakeLists like the other examples (target_link_libraries(...
// holytls)).
#include <stdio.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/session.h"
#include "net/loop.h"
#include "profile/profile.h"

// Go: resp, _ := client.Do(req); body, _ := io.ReadAll(resp.Body)
static void on_response(void* user, const Response* resp) {
  (void)user;
  if (!resp->ok) {  // transport/TLS failure (not an HTTP status)
    fprintf(stderr, "request error: %s\n", resp->error ? resp->error : "?");
    return;
  }
  printf("status code: %d\n", resp->status);  // resp.StatusCode
  String8 body = response_text(resp);  // io.ReadAll — view, valid here only
  printf("%.*s\n", (int)body.size, (const char*)body.str);
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);

  // WithClientProfile(profiles.Chrome_144): the fingerprint lives on the
  // Client. client_init = HTTP/2 over TCP; client_init_dual(..,
  // profile_chrome149_h3(),..) would add Chrome's H2->H3 (alt-svc) upgrade.
  Client client;
  const Profile* profile = profile_chrome149();
  client_init(&client, &loop, profile, /*verify=*/1);
  client_set_timeout_ms(&client, 30000);  // WithTimeoutSeconds(30)

  // NewCookieJar() + WithCookieJar(jar): a Session carries the cookie jar +
  // config.
  SessionConfig cfg;
  session_config_default(&cfg);  // cookies on, 10 redirects
  cfg.max_redirects = 0;         // WithNotFollowRedirects()
  Session session;
  session_init(&session, &cfg);

  // Override the profile's default headers: send ONLY the headers below — none of
  // the profile's browser headers (sec-ch-ua, sec-fetch-*, accept-encoding). This
  // is what lets us replicate the Go example, which replaces req.Header wholesale.
  // The TLS/HTTP2 fingerprint is unchanged; only the request header set changes.
  client_override_default_headers(&client, 1);

  // req.Header{...}: the header set + values. As in Go's map, the order in this
  // array does not matter — the wire order is set explicitly just below.
  Header headers[] = {
      header_lit("user-agent",
                 "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, "
                 "like Gecko) Chrome/123.0.0.0 Safari/537.36"),
      header_lit("accept", "*/*"),
      header_lit("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"),
  };

  // http.HeaderOrderKey{...}: the explicit wire order. It composes with override
  // mode, so these three are emitted in exactly this order regardless of the
  // array order above (pseudo-headers :method/:authority/:scheme/:path stay
  // first, in the profile's order).
  client_set_header_order_str(&client, "accept, accept-language, user-agent");

  // client.Do(req) — async: submit now, the response lands in on_response.
  session_request(&session, &client, Method_GET,
                  str8_lit("https://tls.peet.ws/api/all"), headers,
                  ArrayCount(headers), /*body=*/0, /*body_len=*/0, on_response,
                  /*user=*/0);

  loop_run(
      &loop);  // runs until the request completes (this is the "blocking" bit)

  session_cleanup(&session);
  client_cleanup(&client);
  loop_shutdown(&loop);
  return 0;
}
