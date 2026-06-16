// holytls_capi.c — implementation of the flat FFI ABI (see holytls_capi.h).
//
// This is a deliberate exception to holytls's arena discipline: every value
// returned across the boundary (a holytls_response and the strings/bytes it
// owns) must OUTLIVE the per-request arena and be freed by the foreign caller
// (Python), so it is malloc'd, not arena-pushed. The per-call scratch arena
// holds only the transient RequestParams/Header array that lives just for the
// duration of one blocking call.
//
// The async->blocking bridge: holytls fires its ResponseFn on the loop thread
// when loop_run drives the loop. Our callback copies the response out and, when
// the last in-flight request of a call has landed, stops the loop so loop_run
// returns. Two rules keep this correct across libuv's uv_stop semantics:
//   1. ALWAYS call loop_run after submitting — even if everything already
//      delivered synchronously — because uv_run clears the stop flag on exit; a
//      skipped run would leave a stale flag that makes the NEXT call's loop_run
//      return immediately without doing any work.
//   2. For a batch, set the pending counter to the FULL submit count before
//      submitting any request, so a request that errors synchronously during
//      the submit loop can't drive pending to 0 (and stop the loop) while other
//      requests are still being queued.
#include "holytls_capi.h"

#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/session.h"
#include "ws/ws.h"
#include "net/loop.h"
#include "profile/profile.h"

// ---------------------------------------------------------------------------
// Handles.
// ---------------------------------------------------------------------------

struct holytls_client {
  EventLoop loop;  // this client's own single loop (one client per thread)
  Client client;
};

struct holytls_session {
  Session session;  // a cookie jar + redirect identity; transport is borrowed
};

// ---------------------------------------------------------------------------
// Enum maps (explicit, so a reorder on either side is caught at compile time).
// ---------------------------------------------------------------------------

internal Method map_method(holytls_method m) {
  switch (m) {
    case HOLYTLS_POST: return Method_POST;
    case HOLYTLS_PUT: return Method_PUT;
    case HOLYTLS_DELETE: return Method_DELETE;
    case HOLYTLS_HEAD: return Method_HEAD;
    case HOLYTLS_PATCH: return Method_PATCH;
    case HOLYTLS_OPTIONS: return Method_OPTIONS;
    case HOLYTLS_GET:
    default: return Method_GET;
  }
}

internal FetchMode map_fetch(holytls_fetch_mode f) {
  switch (f) {
    case HOLYTLS_FETCH_NAVIGATE: return FetchMode_Navigate;
    case HOLYTLS_FETCH_CORS: return FetchMode_Cors;
    case HOLYTLS_FETCH_NO_CORS: return FetchMode_NoCors;
    case HOLYTLS_FETCH_SAME_ORIGIN: return FetchMode_SameOrigin;
    case HOLYTLS_FETCH_DEFAULT:
    default: return FetchMode_Default;
  }
}

internal HttpVersion map_http_version(holytls_http_version v) {
  switch (v) {
    case HOLYTLS_HTTP_1: return HttpVersion_H1;
    case HOLYTLS_HTTP_2: return HttpVersion_H2;
    case HOLYTLS_HTTP_3: return HttpVersion_H3;
    case HOLYTLS_HTTP_AUTO:
    default: return HttpVersion_Auto;
  }
}

// Resolve a profile by name from the central registry; ""/NULL => the registry
// default (newest). Returns 0 if the name is unknown.
internal const Profile *pick_profile_named(const char *name) {
  if (name && *name) return profile_by_name(str8_cstring(name));
  U64 n = 0;
  const ProfileEntry *r = profile_registry(&n);
  return n ? r[0].h2() : 0;
}
internal const QuicProfile *pick_quic_named(const char *name) {
  if (name && *name) return profile_quic_by_name(str8_cstring(name));
  U64 n = 0;
  const ProfileEntry *r = profile_registry(&n);
  return n ? r[0].h3() : 0;
}
// Legacy enum -> registry name (ABI compat). CHROME (the default alias) maps to
// the registry default; specific versions map to their canonical names.
internal const char *profile_enum_name(holytls_profile_id id) {
  switch (id) {
    case HOLYTLS_PROFILE_CHROME_148: return "chrome148";
    case HOLYTLS_PROFILE_CHROME_149: return "chrome149";
    case HOLYTLS_PROFILE_FIREFOX_151: return "firefox151";  // (== FIREFOX)
    case HOLYTLS_PROFILE_CHROME:
    default: return 0;  // 0 => registry default
  }
}

// ---------------------------------------------------------------------------
// Heap copy-out helpers (malloc — the result is owned by the foreign caller).
// ---------------------------------------------------------------------------

internal char *dup_cstr(const char *s) {
  if (!s) return 0;
  size_t n = strlen(s);
  char *p = (char *)malloc(n + 1);
  if (!p) return 0;
  memcpy(p, s, n + 1);
  return p;
}

// NUL-terminated copy of a (non-NUL-terminated) String8; "" for an empty view.
internal char *dup_str8(String8 s) {
  char *p = (char *)malloc(s.size + 1);
  if (!p) return 0;
  if (s.size) memcpy(p, s.str, s.size);
  p[s.size] = 0;
  return p;
}

// Binary-safe copy of `n` body bytes, plus a trailing NUL for convenience.
internal uint8_t *dup_bytes(const U8 *b, U64 n) {
  uint8_t *p = (uint8_t *)malloc(n + 1);
  if (!p) return 0;
  if (n) memcpy(p, b, n);
  p[n] = 0;
  return p;
}

// Copy the response out of holytls's "valid only during the callback" views
// into a single caller-owned heap object. Called from inside the ResponseFn.
internal holytls_response *response_copy(const Response *r) {
  holytls_response *out = (holytls_response *)calloc(1, sizeof *out);
  if (!out) return 0;
  out->ok = r->ok ? 1 : 0;
  out->status = r->status;
  out->resumed = r->resumed ? 1 : 0;
  out->early_data = r->early_data ? 1 : 0;
  out->error = r->error ? dup_cstr(r->error) : 0;
  out->body = dup_bytes(r->body, r->body_len);
  out->body_len = r->body_len;
  out->final_url = dup_str8(r->final_url);
  out->alpn = dup_str8(r->alpn);
  out->dns_ms = r->timing.dns_ms;
  out->tcp_ms = r->timing.tcp_ms;
  out->tls_ms = r->timing.tls_ms;
  out->total_ms = r->timing.total_ms;
  if (r->header_count && r->headers) {
    holytls_header *hs =
        (holytls_header *)calloc(r->header_count, sizeof *hs);
    if (!hs) {  // OOM: fail honestly rather than return a 0-header "success"
      holytls_response_free(out);
      return 0;
    }
    for (U64 i = 0; i < r->header_count; i++) {
      hs[i].name = dup_str8(r->headers[i].name);
      hs[i].value = dup_str8(r->headers[i].value);
    }
    out->headers = hs;
    out->header_count = r->header_count;
  }
  return out;
}

// A synthetic ok=0 response so the caller always gets a freeable object back.
internal holytls_response *make_error_response(const char *msg) {
  holytls_response *r = (holytls_response *)calloc(1, sizeof *r);
  if (!r) return 0;
  r->error = dup_cstr(msg);
  return r;
}

// ---------------------------------------------------------------------------
// The async->blocking bridge.
// ---------------------------------------------------------------------------

// Per-request delivery context: where to stash the copied response, and the
// shared pending counter whose fall to 0 stops the loop.
typedef struct CallCtx CallCtx;
struct CallCtx {
  EventLoop *loop;
  holytls_response **slot;
  int *pending;
};

internal void on_response(void *user, const Response *resp) {
  CallCtx *cx = (CallCtx *)user;
  *cx->slot = response_copy(resp);
  if (--(*cx->pending) == 0) loop_stop(cx->loop);  // last one home -> wake up
}

// Fill `out` (zeroed) from the flat request; Header bytes are borrowed views
// into `req`'s caller-owned strings (valid for the whole blocking call), Header
// rows live in `a`.
internal void build_params(Arena *a, const holytls_request *req,
                           RequestParams *out) {
  MemoryZeroStruct(out);
  out->method = map_method(req->method);
  out->url = str8_cstring(req->url);
  if (req->body && req->body_len) out->body = str8((U8 *)req->body, req->body_len);
  out->fetch_mode = map_fetch(req->fetch_mode);
  out->no_redirects = req->no_redirects ? 1 : 0;
  if (req->proxy) out->proxy = str8_cstring(req->proxy);
  if (req->header_order) out->header_order = str8_cstring(req->header_order);
  if (req->header_count && req->headers) {
    Header *hs = push_array(a, Header, req->header_count);
    for (size_t i = 0; i < req->header_count; i++) {
      hs[i].name = str8_cstring(req->headers[i].name);
      hs[i].value = str8_cstring(req->headers[i].value);
      hs[i].flags = 0;
    }
    out->headers = hs;
    out->header_count = req->header_count;
  }
}

// ---------------------------------------------------------------------------
// Client lifecycle + configuration.
// ---------------------------------------------------------------------------

// Init a caller-owned EventLoop + Client pair from a resolved profile/mode.
// Returns 1 on success (loop + client initialized), 0 if the selection is
// invalid (no profile, or an H3-capable mode with no QUIC variant) — in which
// case nothing was initialized. Shared by the blocking + async constructors.
internal int client_loop_init(EventLoop *loop, Client *client,
                              const Profile *h2, const QuicProfile *h3,
                              holytls_http_version mode, int verify) {
  HttpVersion hv = map_http_version(mode);
  // client_init derives the QUIC build from (hv, h3). Reject a QUIC-needing
  // mode with no h3 variant up front so the FFI caller gets a NULL rather than
  // a silent H2 client.
  int needs_h3 = (hv == HttpVersion_Auto) || (hv == HttpVersion_H3);
  if (!h2 || (needs_h3 && !h3))
    return 0;  // unknown profile name / no h3 variant
  loop_init(loop);
  client_init(client, loop, h2, h3, hv, verify ? 1 : 0);
  return 1;
}

internal holytls_client *client_new_from(const Profile *h2,
                                         const QuicProfile *h3,
                                         holytls_http_version mode, int verify) {
  holytls_client *hc = (holytls_client *)calloc(1, sizeof *hc);
  if (!hc) return 0;
  if (!client_loop_init(&hc->loop, &hc->client, h2, h3, mode, verify)) {
    free(hc);
    return 0;
  }
  return hc;
}

holytls_client *holytls_client_new(holytls_profile_id pid,
                                   holytls_http_version mode, int verify) {
  const char *name = profile_enum_name(pid);
  return client_new_from(pick_profile_named(name), pick_quic_named(name), mode,
                         verify);
}

holytls_client *holytls_client_new_named(const char *profile_name,
                                         holytls_http_version mode, int verify) {
  return client_new_from(pick_profile_named(profile_name),
                         pick_quic_named(profile_name), mode, verify);
}

size_t holytls_profile_count(void) {
  U64 n = 0;
  profile_registry(&n);
  return (size_t)n;
}
const char *holytls_profile_name(size_t index) {
  U64 n = 0;
  const ProfileEntry *r = profile_registry(&n);
  return index < n ? r[index].name : 0;
}

void holytls_client_free(holytls_client *hc) {
  if (!hc) return;
  client_cleanup(&hc->client);  // also drains the pool
  loop_shutdown(&hc->loop);     // closes lingering handles, then the loop
  free(hc);
}

void holytls_client_set_max_redirects(holytls_client *c, uint64_t max) {
  if (c) client_set_max_redirects(&c->client, max);
}
void holytls_client_set_timeout_ms(holytls_client *c, uint64_t ms) {
  if (c) client_set_timeout_ms(&c->client, ms);
}
void holytls_client_set_http_version(holytls_client *c, holytls_http_version v) {
  if (c) client_set_http_version(&c->client, map_http_version(v));
}
void holytls_client_set_ech_enabled(holytls_client *c, int on) {
  if (c) client_set_ech_enabled(&c->client, on ? 1 : 0);
}
void holytls_client_set_resumption_enabled(holytls_client *c, int on) {
  if (c) client_set_resumption_enabled(&c->client, on ? 1 : 0);
}
void holytls_client_set_early_data_enabled(holytls_client *c, int on) {
  if (c) client_set_early_data_enabled(&c->client, on ? 1 : 0);
}
void holytls_client_set_max_conns_per_origin(holytls_client *c, uint64_t max) {
  if (c) client_set_max_conns_per_origin(&c->client, max);
}
void holytls_client_set_dns_cache_ttl_ms(holytls_client *c, uint64_t ms) {
  if (c) client_set_dns_cache_ttl_ms(&c->client, ms);
}
void holytls_client_override_default_headers(holytls_client *c, int on) {
  if (c) client_override_default_headers(&c->client, on ? 1 : 0);
}
int holytls_client_set_header_order(holytls_client *c, const char *csv) {
  if (!c) return 0;
  return client_set_header_order_str(&c->client, csv ? csv : "") ? 1 : 0;
}
int holytls_client_set_proxy(holytls_client *c, const char *url,
                             int verify_proxy) {
  if (!c || !url) return 0;
  return client_set_proxy(&c->client, str8_cstring(url), verify_proxy ? 1 : 0)
             ? 1
             : 0;
}
int holytls_client_add_proxy(holytls_client *c, const char *url,
                             int verify_proxy) {
  if (!c || !url) return 0;
  return client_add_proxy(&c->client, str8_cstring(url), verify_proxy ? 1 : 0)
             ? 1
             : 0;
}
int holytls_client_set_local_address(holytls_client *c, const char *ip) {
  if (!c || !ip) return 0;
  return client_set_local_address(&c->client, str8_cstring(ip)) ? 1 : 0;
}
int holytls_client_add_ca_file(holytls_client *c, const char *path) {
  if (!c || !path) return 0;
  return client_add_ca_file(&c->client, path) ? 1 : 0;
}
int holytls_client_set_client_cert(holytls_client *c, const char *cert_path,
                                   const char *key_path,
                                   const char *passphrase) {
  if (!c || !cert_path || !key_path) return 0;
  return client_set_client_cert(
             &c->client, str8_cstring(cert_path), str8_cstring(key_path),
             passphrase ? str8_cstring(passphrase) : str8_zero())
             ? 1
             : 0;
}
int holytls_client_pin_certificate(holytls_client *c, const char *hostname,
                                   const char *sha256_b64,
                                   int include_subdomains) {
  if (!c || !hostname || !sha256_b64) return 0;
  return client_pin_certificate(&c->client, hostname, sha256_b64,
                                include_subdomains ? 1 : 0)
             ? 1
             : 0;
}
void holytls_client_set_key_log_file(holytls_client *c, const char *path) {
  if (c && path) client_set_key_log_file(&c->client, path);
}

// ---------------------------------------------------------------------------
// Requests.
// ---------------------------------------------------------------------------

holytls_response *holytls_perform(holytls_client *hc,
                                  const holytls_request *req) {
  if (!hc || !req || !req->url) return make_error_response("invalid request");
  Arena *a = arena_acquire();
  RequestParams p;
  build_params(a, req, &p);
  holytls_response *resp = 0;
  int pending = 1;
  CallCtx ctx = {&hc->loop, &resp, &pending};
  client_request(&hc->client, &p, on_response, &ctx);
  loop_run(&hc->loop);  // always (see rule 1 at the top of this file)
  arena_recycle(a);
  return resp ? resp : make_error_response("no response");
}

holytls_response *holytls_perform_stream(
    holytls_client *hc, const holytls_request *req,
    void (*on_chunk)(void *user, const uint8_t *data, uint64_t len),
    void *user) {
  if (!hc || !req || !req->url) return make_error_response("invalid request");
  Arena *a = arena_acquire();
  RequestParams p;
  build_params(a, req, &p);
  p.on_chunk = on_chunk;  // BodyChunkFn == void(*)(void*,const U8*,U64), exact
  p.chunk_user = user;
  holytls_response *resp = 0;
  int pending = 1;
  CallCtx ctx = {&hc->loop, &resp, &pending};
  client_request(&hc->client, &p, on_response, &ctx);
  loop_run(&hc->loop);
  arena_recycle(a);
  return resp ? resp : make_error_response("no response");
}

size_t holytls_perform_many(holytls_client *hc, const holytls_request *reqs,
                            size_t count, holytls_response **out) {
  if (!hc || !reqs || !out || count == 0) return 0;
  for (size_t i = 0; i < count; i++) out[i] = 0;

  // Pass 1: count the submittable requests (so `pending` starts at the full
  // total and a synchronous early delivery can't stop the loop mid-submit).
  size_t n_submit = 0;
  for (size_t i = 0; i < count; i++)
    if (reqs[i].url) n_submit++;

  Arena *a = arena_acquire();
  CallCtx *ctxs = push_array(a, CallCtx, count);
  int pending = (int)n_submit;

  // Pass 2: submit every valid request onto the one loop.
  for (size_t i = 0; i < count; i++) {
    if (!reqs[i].url) {
      out[i] = make_error_response("invalid request (no url)");
      continue;
    }
    RequestParams p;
    build_params(a, &reqs[i], &p);
    ctxs[i].loop = &hc->loop;
    ctxs[i].slot = &out[i];
    ctxs[i].pending = &pending;
    client_request(&hc->client, &p, on_response, &ctxs[i]);
  }

  loop_run(&hc->loop);  // drive all in-flight requests to completion
  arena_recycle(a);

  for (size_t i = 0; i < count; i++)
    if (!out[i]) out[i] = make_error_response("no response");
  return count;
}

void holytls_response_free(holytls_response *r) {
  if (!r) return;
  free((void *)r->error);
  free((void *)r->body);
  free((void *)r->final_url);
  free((void *)r->alpn);
  if (r->headers) {
    for (size_t i = 0; i < r->header_count; i++) {
      free((void *)r->headers[i].name);
      free((void *)r->headers[i].value);
    }
    free((void *)r->headers);
  }
  free(r);
}

// ---------------------------------------------------------------------------
// Async client — non-blocking submit + a loop on a caller-spawned thread.
//
// Threading model: the loop runs on ONE dedicated thread (holytls_async_run).
// All Client state (dispatch, response copy, cleanup) is touched ONLY there. The
// asyncio thread calls holytls_async_submit/stop, which touch only the mutex'd
// queue + uv_async_send (the one libuv call documented thread-safe). A request's
// bytes are deep-copied (malloc, not arena — arenas are loop-thread-only) before
// crossing; the completion's holytls_response is plain malloc'd memory, so the
// caller can marshal + free it on whatever thread it lands the result on.
// ---------------------------------------------------------------------------

// One queued submission: owned malloc copies of a flat request, crossing from
// the submitting thread to the loop thread; freed on the loop thread after
// dispatch.
typedef struct AsyncSubmit AsyncSubmit;
struct AsyncSubmit {
  AsyncSubmit *next;
  char *url;
  holytls_header *headers;  // each name/value malloc'd
  size_t header_count;
  uint8_t *body;
  size_t body_len;
  char *proxy;
  char *header_order;
  holytls_method method;
  holytls_fetch_mode fetch_mode;
  int no_redirects;
  uint64_t req_id;
  holytls_async_complete_fn cb;
  void *user;
};

typedef struct AsyncCtx AsyncCtx;

struct holytls_async_client {
  holytls_client base;  // {EventLoop loop; Client client;} — reuse the sync body
  uv_async_t async;     // persistent: keeps the loop alive AND wakes it
  uv_mutex_t qlock;     // guards the submission queue + stopping
  AsyncSubmit *qhead, *qtail;
  int stopping;
  AsyncCtx *inflight;   // dll of dispatched-not-yet-completed ctxs (LOOP THREAD
                        // ONLY); survivors are freed at teardown so a request
                        // abandoned at stop doesn't leak its ctx
  Arena *arena;         // loop-thread-only scratch for per-dispatch Header rows.
                        // Owned (not the thread-local arena_acquire pool, which
                        // would leak when THIS loop thread exits).
};

// Per-request completion trampoline ctx. malloc'd (not arena): client_request
// may deliver synchronously OR much later, so this must outlive the submit.
// Intrusively linked into holytls_async_client.inflight on the loop thread.
struct AsyncCtx {
  AsyncCtx *prev, *next;
  holytls_async_client *ac;
  uint64_t req_id;
  holytls_async_complete_fn cb;
  void *user;
};

internal void async_submit_free(AsyncSubmit *s) {
  if (!s) return;
  free(s->url);
  free(s->body);
  free(s->proxy);
  free(s->header_order);
  if (s->headers) {
    for (size_t i = 0; i < s->header_count; i++) {
      free((void *)s->headers[i].name);
      free((void *)s->headers[i].value);
    }
    free(s->headers);
  }
  free(s);
}

// Deep-copy a flat request into an owned AsyncSubmit (runs off the loop thread).
// Returns NULL on OOM (any partial copies are freed).
internal AsyncSubmit *async_submit_copy(const holytls_request *req,
                                        uint64_t req_id,
                                        holytls_async_complete_fn cb,
                                        void *user) {
  AsyncSubmit *s = (AsyncSubmit *)calloc(1, sizeof *s);
  if (!s) return 0;
  s->method = req->method;
  s->fetch_mode = req->fetch_mode;
  s->no_redirects = req->no_redirects ? 1 : 0;
  s->req_id = req_id;
  s->cb = cb;
  s->user = user;
  s->url = dup_cstr(req->url);
  if (!s->url) goto oom;
  if (req->body && req->body_len) {
    s->body = dup_bytes(req->body, req->body_len);
    if (!s->body) goto oom;
    s->body_len = req->body_len;
  }
  if (req->proxy) {
    s->proxy = dup_cstr(req->proxy);
    if (!s->proxy) goto oom;
  }
  if (req->header_order) {
    s->header_order = dup_cstr(req->header_order);
    if (!s->header_order) goto oom;
  }
  if (req->header_count && req->headers) {
    s->headers = (holytls_header *)calloc(req->header_count, sizeof *s->headers);
    if (!s->headers) goto oom;
    s->header_count = req->header_count;  // set before the loop so OOM cleanup
                                          // walks every (zeroed) slot
    for (size_t i = 0; i < req->header_count; i++) {
      s->headers[i].name = dup_cstr(req->headers[i].name);
      s->headers[i].value = dup_cstr(req->headers[i].value);
      if (!s->headers[i].name || !s->headers[i].value) goto oom;
    }
  }
  return s;
oom:
  async_submit_free(s);
  return 0;
}

// Reconstruct a flat holytls_request view over the owned copies, then reuse
// build_params (Header rows land in `a`; client_request copies them out).
internal void build_params_from_submit(Arena *a, const AsyncSubmit *s,
                                       RequestParams *out) {
  holytls_request req;
  MemoryZeroStruct(&req);
  req.method = s->method;
  req.url = s->url;
  req.headers = s->headers;
  req.header_count = s->header_count;
  req.body = s->body;
  req.body_len = s->body_len;
  req.fetch_mode = s->fetch_mode;
  req.no_redirects = s->no_redirects;
  req.proxy = s->proxy;
  req.header_order = s->header_order;
  build_params(a, &req, out);
}

// Response trampoline — fires on the loop thread when a request completes.
// Copies the "valid only during the callback" Response into owned heap memory
// and hands ownership to the user's completion callback.
internal void on_async_response(void *user, const Response *resp) {
  AsyncCtx *cx = (AsyncCtx *)user;
  holytls_response *out = response_copy(resp);
  if (!out) out = make_error_response("out of memory copying response");
  if (out) cx->cb(cx->user, cx->req_id, out);
  // Unlink from the in-flight list (loop thread; no lock) and free.
  if (cx->prev)
    cx->prev->next = cx->next;
  else
    cx->ac->inflight = cx->next;
  if (cx->next) cx->next->prev = cx->prev;
  free(cx);
}

// uv_async callback — runs on the loop thread. Drains the whole submit queue
// (uv coalesces sends, so process all) and dispatches each via client_request.
internal void on_async(uv_async_t *h) {
  holytls_async_client *ac = (holytls_async_client *)h->data;

  // Detach under the lock, then process unlocked so a synchronous completion
  // that re-submits can re-lock without deadlocking.
  uv_mutex_lock(&ac->qlock);
  AsyncSubmit *batch = ac->qhead;
  ac->qhead = ac->qtail = 0;
  int stopping = ac->stopping;
  uv_mutex_unlock(&ac->qlock);

  for (AsyncSubmit *s = batch; s;) {
    AsyncSubmit *next = s->next;
    if (stopping) {
      // Never dispatched — complete it so the awaiter doesn't hang.
      holytls_response *er = make_error_response("client closing");
      if (er) s->cb(s->user, s->req_id, er);
    } else {
      AsyncCtx *cx = (AsyncCtx *)calloc(1, sizeof *cx);
      if (!cx) {
        holytls_response *er = make_error_response("out of memory");
        if (er) s->cb(s->user, s->req_id, er);
      } else {
        cx->ac = ac;
        cx->req_id = s->req_id;
        cx->cb = s->cb;
        cx->user = s->user;
        // Link BEFORE dispatch: client_request may deliver synchronously, and
        // on_async_response must find cx already in the list to unlink it.
        cx->prev = 0;
        cx->next = ac->inflight;
        if (ac->inflight) ac->inflight->prev = cx;
        ac->inflight = cx;
        Temp t = temp_begin(ac->arena);  // rewinds the Header rows per dispatch
        RequestParams p;
        build_params_from_submit(ac->arena, s, &p);
        client_request(&ac->base.client, &p, on_async_response, cx);
        temp_end(t);  // client_request copied url/headers/body synchronously
      }
    }
    async_submit_free(s);
    s = next;
  }

  // Stop is signalled by setting `stopping` + waking us: just uv_stop so
  // uv_run returns. The async handle is NOT closed here (loop_shutdown closes it
  // during _free — closing it twice would abort libuv).
  if (stopping) uv_stop(loop_uv(&ac->base.loop));
}

holytls_async_client *holytls_async_client_new_named(const char *profile_name,
                                                     holytls_http_version mode,
                                                     int verify) {
  const Profile *h2 = pick_profile_named(profile_name);
  const QuicProfile *h3 = pick_quic_named(profile_name);
  holytls_async_client *ac = (holytls_async_client *)calloc(1, sizeof *ac);
  if (!ac) return 0;
  if (!client_loop_init(&ac->base.loop, &ac->base.client, h2, h3, mode, verify)) {
    free(ac);
    return 0;
  }
  if (uv_mutex_init(&ac->qlock) != 0) {
    client_cleanup(&ac->base.client);
    loop_shutdown(&ac->base.loop);
    free(ac);
    return 0;
  }
  if (uv_async_init(loop_uv(&ac->base.loop), &ac->async, on_async) != 0) {
    uv_mutex_destroy(&ac->qlock);
    client_cleanup(&ac->base.client);
    loop_shutdown(&ac->base.loop);
    free(ac);
    return 0;
  }
  ac->async.data = ac;
  ac->arena = arena_alloc();
  return ac;
}

holytls_client *holytls_async_client_base(holytls_async_client *ac) {
  return ac ? &ac->base : 0;
}

int holytls_async_submit(holytls_async_client *ac, const holytls_request *req,
                         uint64_t req_id, holytls_async_complete_fn cb,
                         void *user) {
  if (!ac || !req || !req->url || !cb) return 0;
  AsyncSubmit *s = async_submit_copy(req, req_id, cb, user);  // off-loop copy
  if (!s) return 0;
  uv_mutex_lock(&ac->qlock);
  if (ac->stopping) {
    uv_mutex_unlock(&ac->qlock);
    async_submit_free(s);
    return 0;
  }
  if (ac->qtail)
    ac->qtail->next = s;
  else
    ac->qhead = s;
  ac->qtail = s;
  uv_mutex_unlock(&ac->qlock);
  uv_async_send(&ac->async);  // the one thread-safe libuv call
  return 1;
}

int holytls_async_submit_many(holytls_async_client *ac,
                              const holytls_request *reqs, size_t count,
                              const uint64_t *req_ids,
                              holytls_async_complete_fn cb, void *user) {
  if (!ac || !cb) return 0;
  if (count == 0) return 1;  // no-op; the caller has no futures to submit
  if (!reqs || !req_ids) return 0;

  // Phase 1: deep-copy all N off the loop thread into a local sub-list (no
  // lock; async_submit_copy only touches its own mallocs). All-or-nothing: any
  // failure frees the partial list and returns 0, so cb fires for NONE (same
  // contract as holytls_async_submit) and the caller fails all N awaiters.
  AsyncSubmit *head = 0, *tail = 0;
  for (size_t i = 0; i < count; i++) {
    if (!reqs[i].url) goto fail;
    AsyncSubmit *s = async_submit_copy(&reqs[i], req_ids[i], cb, user);
    if (!s) goto fail;
    s->next = 0;  // keep the spliced list well-terminated (qtail = tail below)
    if (tail)
      tail->next = s;
    else
      head = s;
    tail = s;
  }

  // Phase 2: splice the WHOLE sub-list onto the queue under ONE lock, one send.
  uv_mutex_lock(&ac->qlock);
  if (ac->stopping) {
    uv_mutex_unlock(&ac->qlock);
    goto fail;
  }
  if (ac->qtail)
    ac->qtail->next = head;
  else
    ac->qhead = head;
  ac->qtail = tail;
  uv_mutex_unlock(&ac->qlock);
  uv_async_send(&ac->async);  // ONE wakeup for the whole batch
  return 1;

fail:
  for (AsyncSubmit *s = head; s;) {
    AsyncSubmit *next = s->next;
    async_submit_free(s);
    s = next;
  }
  return 0;
}

void holytls_async_run(holytls_async_client *ac) {
  if (!ac) return;
  uv_run(loop_uv(&ac->base.loop), UV_RUN_DEFAULT);
  // Straggler drain (same idiom as loop_run): reap handles closed during the
  // final closing-handles pass so the loop is left quiesced for _free.
  if (uv_loop_alive(loop_uv(&ac->base.loop)))
    uv_run(loop_uv(&ac->base.loop), UV_RUN_NOWAIT);
  // This thread is about to exit; release the per-thread arena pools the request
  // path (h2req_start/quicreq_start via arena_acquire) built here, else they'd
  // leak when this thread's thread_local storage is destroyed.
  arena_thread_cleanup();
}

void holytls_async_stop(holytls_async_client *ac) {
  if (!ac) return;
  uv_mutex_lock(&ac->qlock);
  ac->stopping = 1;  // reject further submits; observed by on_async
  uv_mutex_unlock(&ac->qlock);
  uv_async_send(&ac->async);
}

void holytls_async_client_free(holytls_async_client *ac) {
  if (!ac) return;
  // Precondition: the loop thread has returned from holytls_async_run and been
  // joined, so in_callback==0 and no thread races us here.
  client_cleanup(&ac->base.client);
  loop_shutdown(&ac->base.loop);  // closes the async handle + any stragglers
  if (ac->arena) arena_release(ac->arena);
  uv_mutex_destroy(&ac->qlock);
  for (AsyncSubmit *s = ac->qhead; s;) {  // defensive: any residual queue
    AsyncSubmit *next = s->next;
    async_submit_free(s);
    s = next;
  }
  for (AsyncCtx *cx = ac->inflight; cx;) {  // ctxs of requests abandoned at stop
    AsyncCtx *next = cx->next;
    free(cx);
    cx = next;
  }
  free(ac);
}

// ---------------------------------------------------------------------------
// Session.
// ---------------------------------------------------------------------------

holytls_session *holytls_session_new(int cookies_enabled, int follow_redirects,
                                     uint64_t max_redirects) {
  holytls_session *hs = (holytls_session *)calloc(1, sizeof *hs);
  if (!hs) return 0;
  SessionConfig cfg;
  session_config_default(&cfg);
  cfg.cookies_enabled = cookies_enabled ? 1 : 0;
  cfg.follow_redirects = follow_redirects ? 1 : 0;
  cfg.has_follow_redirects = 1;
  cfg.max_redirects = max_redirects;  // honored verbatim now (0 => no follow)
  session_init(&hs->session, &cfg);
  return hs;
}

void holytls_session_free(holytls_session *hs) {
  if (!hs) return;
  session_cleanup(&hs->session);
  free(hs);
}

holytls_response *holytls_session_perform(holytls_session *hs,
                                          holytls_client *hc,
                                          const holytls_request *req) {
  if (!hs || !hc || !req || !req->url)
    return make_error_response("invalid request");
  Arena *a = arena_acquire();
  RequestParams p;
  build_params(a, req, &p);
  holytls_response *resp = 0;
  int pending = 1;
  CallCtx ctx = {&hc->loop, &resp, &pending};
  session_request(&hs->session, &hc->client, &p, on_response, &ctx);
  loop_run(&hc->loop);
  arena_recycle(a);
  return resp ? resp : make_error_response("no response");
}

// ---------------------------------------------------------------------------
// WebSocket. A thin wrapper over WsConn, which is itself blocking (it drives the
// client's loop until each event) — so unlike holytls_perform there is no
// per-call CallCtx/loop_run here; WsConn owns that. The connection persists
// across calls (it is NOT closed between them).
// ---------------------------------------------------------------------------

struct holytls_ws {
  WsConn *conn;  // bound to the client's loop + transport
};

holytls_ws *holytls_ws_connect(holytls_client *hc, const char *url,
                               const holytls_header *headers,
                               size_t header_count) {
  if (!hc || !url) return 0;
  holytls_ws *ws = (holytls_ws *)calloc(1, sizeof *ws);
  ws->conn = ws_conn_alloc(&hc->client);
  // The handshake headers only need to live across the connect call (WsConn
  // copies them into its own arena) — the per-call scratch arena suffices.
  Arena *a = arena_acquire();
  Header *hs = 0;
  if (header_count && headers) {
    hs = push_array(a, Header, header_count);
    for (size_t i = 0; i < header_count; ++i) {
      hs[i].name = str8_cstring(headers[i].name);
      hs[i].value = str8_cstring(headers[i].value);
      hs[i].flags = 0;
    }
  }
  ws_conn_connect(ws->conn, str8_cstring(url), hs, header_count);
  arena_recycle(a);
  return ws;  // a failed handshake is reported via holytls_ws_error()
}

int holytls_ws_send_text(holytls_ws *ws, const char *text, size_t len) {
  if (!ws || (!text && len)) return 0;
  return ws_conn_send(ws->conn, WsOp_Text, (const U8 *)text, len) ? 1 : 0;
}
int holytls_ws_send_binary(holytls_ws *ws, const uint8_t *data, size_t len) {
  if (!ws || (!data && len)) return 0;
  return ws_conn_send(ws->conn, WsOp_Binary, data, len) ? 1 : 0;
}

int holytls_ws_recv(holytls_ws *ws, holytls_ws_message *out,
                    uint64_t timeout_ms) {
  if (!ws || !out) return -1;
  WsEvent ev;
  int rc = ws_conn_recv(ws->conn, &ev, timeout_ms);
  MemoryZeroStruct(out);
  if (rc < 0) return rc;  // -1 error, -2 timeout
  out->is_text = (ev.op == WsOp_Text) ? 1 : 0;
  out->data = ev.data;  // WsConn-owned; valid until the next holytls_ws_* call
  out->len = ev.len;
  out->close_code = ev.close_code;
  return rc;  // 1 = message, 0 = peer Close
}

void holytls_ws_close(holytls_ws *ws, uint16_t code, const char *reason) {
  if (!ws) return;
  ws_conn_close(ws->conn, code, reason ? str8_cstring(reason) : str8_zero());
}
void holytls_ws_free(holytls_ws *ws) {
  if (!ws) return;
  ws_conn_free(ws->conn);
  free(ws);
}

int holytls_ws_transport(holytls_ws *ws) {
  return ws ? (int)ws_conn_transport(ws->conn) : 0;
}
const char *holytls_ws_error(holytls_ws *ws) {
  return ws ? ws_conn_error(ws->conn) : 0;
}

// ---------------------------------------------------------------------------
// Misc.
// ---------------------------------------------------------------------------

const char *holytls_version(void) { return "holytls-capi 0.1.0"; }
