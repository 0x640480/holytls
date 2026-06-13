#include "core/session.h"

#include <time.h>
#include <uv.h>

#include "core/url.h"

void session_config_default(SessionConfig *cfg) {
  MemoryZeroStruct(cfg);
  cfg->preset = "chrome-latest";
  cfg->cookies_enabled = 1;
  cfg->max_redirects = 10;
}

internal void session_init_fields(Session *s, Arena *a,
                                  const SessionConfig *cfg) {
  s->arena = a;
  cookie_jar_init(&s->jar, a);
  s->cookies_enabled = cfg ? cfg->cookies_enabled : 1;
  s->max_redirects = (cfg && cfg->max_redirects) ? cfg->max_redirects : 10;
}

B32 session_init(Session *s, const SessionConfig *cfg) {
  MemoryZeroStruct(s);
  session_init_fields(s, arena_alloc(), cfg);
  return 1;
}

void session_cleanup(Session *s) {
  if (s->arena) arena_release(s->arena);
  s->arena = 0;
}

Session *session_create(const SessionConfig *cfg) {
  Arena *a = arena_alloc();
  Session *s = push_struct(a, Session);  // zeroed; lives in its own arena
  session_init_fields(s, a, cfg);
  return s;
}

void session_destroy(Session *s) {
  if (s) arena_release(s->arena);  // frees the struct + jar; s is dangling after
}

//- per-request cookie-aware redirect loop -----------------------------------
typedef struct SessionReq SessionReq;
struct SessionReq {
  Arena *arena;  // own; persists across hops, freed at chain end
  Session *session;
  Client *client;
  ResponseFn user_cb;
  void *user;
  Method method;
  HeaderList caller_headers;  // never contains the jar's Cookie (recomputed/hop)
  String8 body;
  String8 cur_url;
  U64 left;
  U64 chain_start_ns;  // whole-chain start (uv_hrtime) for total_ms
  U64 deadline_ns;     // whole-chain timeout deadline (0 = none), shared by all hops
};

internal void session_hop_cb(void *user, const Response *r);

internal void session_dispatch_hop(SessionReq *req) {
  Session *s = req->session;
  ParsedUrl pu = url_parse(req->cur_url);

  // Effective per-hop headers = caller headers (+ the jar's Cookie for THIS hop,
  // unless the caller supplied one). The injected Cookie lands at the profile's
  // cookie slot via build_ordered_headers, so the fingerprint is unchanged.
  HeaderList hop;
  header_list_init(&hop, req->arena);
  for (U64 i = 0; i < req->caller_headers.count; ++i)
    header_list_push(&hop, req->caller_headers.v[i].name,
                     req->caller_headers.v[i].value,
                     req->caller_headers.v[i].flags);
  if (s->cookies_enabled && pu.ok &&
      !header_list_has_ci(&req->caller_headers, str8_lit("cookie"))) {
    String8 cookie =
        cookie_jar_cookie_header(&s->jar, req->arena, pu, (U64)time(0));
    if (cookie.size) header_list_push(&hop, str8_lit("cookie"), cookie, 0);
  }

  // client_send_deadline = single hop (no client-side redirects) carrying the one
  // chain-wide deadline -> we own the redirect loop, the timeout spans all hops.
  client_send_deadline(req->client, req->method, req->cur_url, hop.v, hop.count,
                       req->body.str, req->body.size, session_hop_cb, req,
                       req->deadline_ns);
}

internal void session_hop_cb(void *user, const Response *r) {
  SessionReq *req = (SessionReq *)user;
  Session *s = req->session;

  // 1) Absorb every Set-Cookie for the current hop (copies bytes into the jar
  //    arena before the transient response view dies).
  if (s->cookies_enabled) {
    ParsedUrl pu = url_parse(req->cur_url);
    if (pu.ok) {
      U64 now = (U64)time(0);
      for (U64 i = 0; i < r->header_count; ++i)
        if (str8_match_ci(r->headers[i].name, str8_lit("set-cookie")))
          cookie_jar_store(&s->jar, pu, r->headers[i].value, now);
    }
  }

  // 2) Follow a redirect ourselves (so the next hop gets its own cookies),
  //    via the hop logic shared with client.c's redirect loop (the carried
  //    caller headers never include the jar's Cookie — it's recomputed per hop).
  RedirectHop hop;
  if (req->left > 0 &&
      redirect_prepare_hop(req->arena, req->cur_url, req->method,
                           &req->caller_headers, r, &hop)) {
    req->caller_headers = hop.headers;
    req->method = hop.next_method;
    if (hop.drop_body) req->body = str8_zero();
    req->cur_url = hop.next_url;
    req->left--;
    session_dispatch_hop(req);  // re-entrant re-dispatch (pool defers submit)
    return;
  }

  // 3) Terminal: forward the live response, then free the request chain once.
  // Override total_ms to span the whole hop chain (per-hop value covers only the
  // final hop). Shallow copy — header/body pointers stay valid for the callback.
  if (req->user_cb) {
    Response rc = *r;
    rc.timing.total_ms = (uv_hrtime() - req->chain_start_ns) / 1000000;
    req->user_cb(req->user, &rc);
  }
  arena_recycle(req->arena);  // terminal hop: clear + return to the pool
}

void session_request(Session *s, Client *client, Method m, String8 url,
                     const Header *headers, U64 header_count, const U8 *body,
                     U64 body_len, ResponseFn cb, void *user) {
  Arena *a = arena_acquire();
  SessionReq *req = push_struct(a, SessionReq);
  req->arena = a;
  req->session = s;
  req->client = client;
  req->user_cb = cb;
  req->user = user;
  req->method = m;
  req->left = s->max_redirects;
  req->chain_start_ns = uv_hrtime();
  U64 t = client_get_timeout_ms(client);  // one deadline for the whole hop chain
  req->deadline_ns = t ? uv_hrtime() + t * 1000000ull : 0;
  req->cur_url = push_str8_copy(a, url);
  header_list_init(&req->caller_headers, a);
  for (U64 i = 0; i < header_count; ++i)
    header_list_push(&req->caller_headers, push_str8_copy(a, headers[i].name),
                     push_str8_copy(a, headers[i].value), headers[i].flags);
  req->body = body_len ? push_str8_copy(a, str8((U8 *)body, body_len))
                       : str8_zero();
  session_dispatch_hop(req);
}

void session_get(Session *s, Client *client, String8 url, ResponseFn cb,
                 void *user) {
  session_request(s, client, Method_GET, url, 0, 0, 0, 0, cb, user);
}

void session_fetch(Session *s, Client *client, FetchMode mode, Method m,
                   String8 url, const Header *headers, U64 header_count,
                   const U8 *body, U64 body_len, ResponseFn cb, void *user) {
  Arena *a = arena_acquire();
  HeaderList merged;
  header_list_init(&merged, a);
  sec_fetch_merge(&merged, mode, url, headers, header_count);
  session_request(s, client, m, url, merged.v, merged.count, body, body_len, cb,
                  user);
  arena_recycle(a);  // copied synchronously by session_request (-> SessionReq arena)
}
