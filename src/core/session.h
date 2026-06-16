// Session — a lightweight, per-task browser-like identity: a cookie jar +
// state, nothing more. It does NOT own a loop, client, or thread (thousands run
// concurrently). The transport (EventLoop + Client + connection pool) is shared
// and passed in per request — e.g. a scheduler worker's Client. The session
// attaches matching cookies to each request, absorbs Set-Cookie from responses,
// and follows redirects itself (so cookies are applied/absorbed per hop), all
// on top of the Client's async model.
//
// Concurrency: a Session's jar is not internally locked (like the Client, it is
// single-threaded). Drive one Session from one loop at a time — "one session
// per task" upholds this. Different sessions on a shared Client are
// independent.
#ifndef HOLYTLS_SESSION_H
#define HOLYTLS_SESSION_H

#include "core/client.h"
#include "core/cookie.h"

typedef struct SessionConfig SessionConfig;
struct SessionConfig {
  const char *preset;   // informational (fingerprint is the passed-in Client's)
  B32 cookies_enabled;  // jar on/off (default on)
  B32 follow_redirects;  // follow 3xx (default on); 0 => single hop. Decoupled
                         // from max_redirects so an explicit 0 budget is
                         // honored
  B32 has_follow_redirects;  // 1 => follow_redirects is set; lets a zeroed
                             // config still default to "follow" (back-compat)
  U64 max_redirects;  // session-level redirect budget (default 10); honored
                      // verbatim now (0 => no following), no silent ?:10
};

// Browser-faithful defaults: cookies on, follow redirects, budget 10.
void session_config_default(SessionConfig *cfg);

typedef struct Session Session;
struct Session {
  Arena *arena;  // owns the jar + session-lifetime allocations
  CookieJar jar;
  B32 cookies_enabled;
  B32 follow_redirects;  // 0 => never follow (single hop), independent of
                         // budget
  U64 max_redirects;
};

// Initialize a caller-owned (e.g. stack) session: arena + jar. No I/O, no
// SSL_CTX — cheap. Returns 1.
B32 session_init(Session *s, const SessionConfig *cfg);
void session_cleanup(Session *s);  // arena_release (struct is the caller's)

// Heap-allocate a session (struct + jar in one arena) for the Manager / dynamic
// use; pair with session_destroy.
Session *session_create(const SessionConfig *cfg);
void session_destroy(Session *s);

// Issue a request on `client` (the shared transport) described by `p` (see
// RequestParams in core/client.h), with this session's cookies + its own
// per-hop redirect loop. Async: the response is delivered to `cb` (valid only
// during the callback, like the Client). Set `p->fetch_mode` for coherent
// Sec-Fetch-* headers (replaces the old session_fetch). `p->no_redirects` and
// `p->deadline_ns` are ignored — the Session runs its own cookie-aware redirect
// loop (up to s->max_redirects, and only when s->follow_redirects is set) and
// derives one chain-wide deadline from client_set_timeout_ms. `p->on_chunk` IS
// honored (the body is streamed to
// the sink); as in client_request a streamed body is terminal, so a streaming
// request does NOT follow redirects.
void session_request(Session *s, Client *client, const RequestParams *p,
                     ResponseFn cb, void *user);
void session_get(Session *s, Client *client, String8 url, ResponseFn cb,
                 void *user);

#endif  // HOLYTLS_SESSION_H
