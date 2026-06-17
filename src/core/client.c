#include "core/client.h"

#include <uv.h>

#include "base/platform_net.h"  // inet_pton (validate client_set_local_address)
#include "core/alt_svc.h"
#include "core/client_internal.h"
#include "core/decompress.h"
#include "core/ech.h"
#include "core/header_order.h"
#include "core/json.h"
#include "core/pool.h"
#include "core/url.h"
#include "h1/h1.h"
#include "h2/h2.h"
#include "h3/h3_session.h"
#include "net/connection.h"
#include "net/quic_connection.h"
#include "tls/cert_pin.h"
#include "tls/keylog.h"

// Chrome's default Accept-Encoding (added when the caller didn't set one, so
// the response is decoded transparently and the request stays Chrome-coherent).
#define DEFAULT_ACCEPT_ENCODING "gzip, deflate, br, zstd"

// ALPN wire (RFC 7301: length-prefixed) advertising only HTTP/1.1, used when
// the caller forces HttpVersion_H1 so the server cannot negotiate h2.
global const U8 k_alpn_http11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

internal String8 method_str(Method m) {
  switch (m) {
    case Method_GET:
      return str8_lit("GET");
    case Method_POST:
      return str8_lit("POST");
    case Method_PUT:
      return str8_lit("PUT");
    case Method_DELETE:
      return str8_lit("DELETE");
    case Method_HEAD:
      return str8_lit("HEAD");
    case Method_PATCH:
      return str8_lit("PATCH");
    case Method_OPTIONS:
      return str8_lit("OPTIONS");
  }
  return str8_lit("GET");
}

internal String8 origin_of(Arena *a, ParsedUrl pu) {
  return push_str8f(a, "%.*s:%u", (int)pu.host.size, pu.host.str, pu.port);
}

// ---------------------------------------------------------------------------
// TLS 1.3 session resumption (opt-in ticket cache;
// client_set_resumption_enabled)
// ---------------------------------------------------------------------------
// Per-connection context stashed at SSL ex_data so the single SSL_CTX-level
// new-session callback can route a freshly issued ticket to its origin. Lives
// in the connection's arena; the callback only fires while the connection is
// processing received handshake records, so the pointer is always valid then.
typedef struct ResumeCtx ResumeCtx;
struct ResumeCtx {
  Client *client;
  String8 origin;  // copied into the connection arena
};

// Re-entrancy guard: a response callback may issue new requests on this
// client, but must NOT call client_cleanup — on return, the delivery path
// still touches state cleanup frees (pool, contexts, caches). Tracked as a
// depth counter around every user-callback invocation; client_cleanup asserts
// it is zero in debug builds.
internal void client_cb_enter(Client *c) { c->in_callback += 1; }
internal void client_cb_exit(Client *c) { c->in_callback -= 1; }

internal SSL_SESSION *resume_cache_get(Client *c, String8 origin) {
  for (int i = 0; i < c->resume_cache_count; ++i)
    if (str8_match(origin, str8_cstring(c->resume_cache[i].origin))) {
      c->resume_cache[i].last_used_ms = uv_now(loop_uv(c->loop));
      return c->resume_cache[i].session;
    }
  return 0;
}

// Find the entry for `origin`, or claim one: a fresh slot while the cache has
// room, else the least-recently-used entry is evicted (its ticket freed) and
// recycled. A new origin always gets a slot — a full cache degrades to LRU
// instead of silently refusing resumption for every origin past capacity.
internal ResumeCacheEntry *resume_cache_slot(Client *c, String8 origin) {
  ResumeCacheEntry *e = 0;
  for (int i = 0; i < c->resume_cache_count; ++i)
    if (str8_match(origin, str8_cstring(c->resume_cache[i].origin))) {
      e = &c->resume_cache[i];
      break;
    }
  if (!e) {
    if (c->resume_cache_count < (int)ArrayCount(c->resume_cache)) {
      e = &c->resume_cache[c->resume_cache_count++];
    } else {
      e = &c->resume_cache[0];
      for (int i = 1; i < c->resume_cache_count; ++i)
        if (c->resume_cache[i].last_used_ms < e->last_used_ms)
          e = &c->resume_cache[i];
      if (e->session) SSL_SESSION_free(e->session);
      MemoryZeroStruct(e);
    }
    U64 n =
        origin.size < sizeof e->origin - 1 ? origin.size : sizeof e->origin - 1;
    MemoryCopy(e->origin, origin.str, n);
    e->origin[n] = 0;
  }
  e->last_used_ms = uv_now(loop_uv(c->loop));
  return e;
}

// Store the most recent ticket for `origin`, taking ownership of `session` (the
// callback returned 1). Replaces (and frees) any prior ticket for the origin.
internal void resume_cache_put(Client *c, String8 origin,
                               SSL_SESSION *session) {
  ResumeCacheEntry *e = resume_cache_slot(c, origin);
  if (e->session) SSL_SESSION_free(e->session);  // supersede the older ticket
  e->session = session;
}

// After a 0-RTT rejection, replace the origin's cached session with an
// early-data-stripped copy so subsequent connections still resume (1-RTT) but
// no longer re-attempt 0-RTT (which the server just refused). Also drops any
// cached QUIC 0-RTT transport params for the origin (so the H3 gate fails too).
internal void resume_cache_strip_early(Client *c, String8 origin) {
  for (int i = 0; i < c->resume_cache_count; ++i)
    if (str8_match(origin, str8_cstring(c->resume_cache[i].origin))) {
      ResumeCacheEntry *e = &c->resume_cache[i];
      if (e->session) {
        SSL_SESSION *stripped = SSL_SESSION_copy_without_early_data(e->session);
        // On copy failure (OOM) keep the original 1-RTT-resumable ticket rather
        // than dropping it; the next 0-RTT attempt simply re-strips,
        // harmlessly.
        if (stripped) {
          SSL_SESSION_free(e->session);
          e->session = stripped;
        }
      }
      e->zrtt_tp_len = 0;
      return;
    }
}

// Cache the QUIC 0-RTT transport params for `origin` (paired with the ticket so
// a future connection can offer 0-RTT). Updates an existing entry or appends
// one.
internal void resume_cache_put_tp(Client *c, String8 origin, const U8 *tp,
                                  U64 tp_len) {
  // Transport params are only useful PAIRED with a ticket: when the cache is
  // full and this origin has no entry, drop the tp rather than letting
  // resume_cache_slot evict another origin's usable ticket for an orphan tp.
  if (c->resume_cache_count >= (int)ArrayCount(c->resume_cache)) {
    B32 found = 0;
    for (int i = 0; i < c->resume_cache_count; ++i)
      if (str8_match(origin, str8_cstring(c->resume_cache[i].origin))) {
        found = 1;
        break;
      }
    if (!found) return;
  }
  ResumeCacheEntry *e = resume_cache_slot(c, origin);
  U64 n = tp_len < sizeof e->zrtt_tp ? tp_len : sizeof e->zrtt_tp;
  if (n) MemoryCopy(e->zrtt_tp, tp, n);
  e->zrtt_tp_len = n;
}

// Fetch the cached QUIC 0-RTT transport params for `origin` (0 if none).
internal const U8 *resume_cache_tp(Client *c, String8 origin, U64 *out_len) {
  *out_len = 0;
  for (int i = 0; i < c->resume_cache_count; ++i)
    if (str8_match(origin, str8_cstring(c->resume_cache[i].origin)) &&
        c->resume_cache[i].zrtt_tp_len) {
      *out_len = c->resume_cache[i].zrtt_tp_len;
      return c->resume_cache[i].zrtt_tp;
    }
  return 0;
}

// SSL_CTX new-session callback: cache the ticket against its origin. Returning
// 1 takes ownership of the reference (we free it on replacement /
// client_cleanup).
internal int client_resume_new_cb(SSL *ssl, SSL_SESSION *session) {
  ResumeCtx *rc = (ResumeCtx *)SSL_get_ex_data(ssl, ssl_resume_ex_index());
  if (!rc || !rc->client) return 0;  // not ours -> library frees it
  resume_cache_put(rc->client, rc->origin, session);
  return 1;
}

// Build the per-connection resume context (origin copied into `a`).
internal void *client_resume_ctx_make(Client *c, Arena *a, String8 origin) {
  ResumeCtx *rc = push_struct(a, ResumeCtx);
  rc->client = c;
  rc->origin = push_str8_copy(a, origin);
  return rc;
}

internal void client_note_alt_svc(Client *c, String8 origin, String8 value);
internal EchConfigEntry *ech_cache_get(Client *c, String8 origin);
internal void client_dispatch_inner(Client *c, Method m, String8 url,
                                    const Header *headers, U64 header_count,
                                    const U8 *body, U64 body_len, ResponseFn cb,
                                    void *user, U64 deadline_ns,
                                    const ProxyConfig *proxy,
                                    BodyChunkFn on_chunk, void *chunk_user,
                                    String8 header_order);

// Build the ordered request headers (+ default accept-encoding /
// content-length) for a request into `out` (initialised on `arena`). Returns
// the arena-dup'd body view.
// Non-internal (declared in client_internal.h) so the white-box header test can
// assert the assembled wire order, incl. the named-slot fill below.
String8 build_request_headers(Arena *arena, const DefaultHeader *defaults,
                              U64 default_count, const Header *caller,
                              U64 caller_count, const U8 *body, U64 body_len,
                              B32 override_defaults, Method method,
                              HeaderList *out) {
  header_list_init(out, arena);
  // Named-slot template: if the caller placed an EMPTY content-length slot, fill
  // it in place (keeping its wire position) instead of letting
  // build_ordered_headers drop it and re-appending content-length at the end
  // below. Triggers ONLY when such a slot exists (the browser-default header
  // sets never have one), so every other path stays byte-exact. The caller array
  // is const, so fill a one-shot arena copy.
  for (U64 i = 0; i < caller_count; ++i) {
    if (caller[i].value.size == 0 &&
        str8_match_ci(caller[i].name, str8_lit("content-length"))) {
      String8 cl = str8_zero();
      if (body_len)
        cl = str8_from_u64(arena, body_len, 10, 0);
      else if (method == Method_POST || method == Method_PUT ||
               method == Method_PATCH)
        cl = str8_lit("0");
      if (cl.size) {
        Header *copy = push_array_no_zero(arena, Header, caller_count);
        MemoryCopy(copy, caller, caller_count * sizeof(Header));
        copy[i].value = cl;
        caller = copy;  // local rebind; we own the copy (caller stays const)
      }
      break;  // first content-length slot only
    }
  }
  // Override-default-headers mode: drop the profile's browser headers entirely
  // — build_ordered_headers with zero defaults emits only the caller's headers,
  // in their array order — and skip the Accept-Encoding default. Content-Length
  // is still added below (framing correctness). client_set_header_order, if
  // set, still reorders at the call site (this is the SET; the order override
  // is the ORDER).
  build_ordered_headers(arena, override_defaults ? 0 : defaults,
                        override_defaults ? 0 : default_count, caller,
                        caller_count, out);
  if (!override_defaults &&
      !header_list_has_ci(out, str8_lit("accept-encoding")))
    header_list_push(out, str8_lit("accept-encoding"),
                     str8_lit(DEFAULT_ACCEPT_ENCODING), 0);
  String8 b = str8_zero();
  if (body_len) {
    b = push_str8_copy(arena, str8((U8 *)body, body_len));
    if (!header_list_has_ci(out, str8_lit("content-length")))
      header_list_push(out, str8_lit("content-length"),
                       str8_from_u64(arena, body_len, 10, 0), 0);
  } else if ((method == Method_POST || method == Method_PUT ||
              method == Method_PATCH) &&
             !header_list_has_ci(out, str8_lit("content-length"))) {
    // Body-carrying methods send Content-Length: 0 even with an empty body, the
    // way Chrome does (GET/HEAD/DELETE/OPTIONS do not).
    header_list_push(out, str8_lit("content-length"), str8_lit("0"), 0);
  }
  return b;
}

// A fetch/XHR request is one whose Sec-Fetch-Mode is present and not "navigate"
// (set by sec_fetch_merge from the FetchMode). Browsers order fetch headers
// differently from navigations, so this selects the profile's fetch_order.
internal B32 headers_are_fetch(HeaderList *h) {
  String8 *m = header_list_get_ci(h, str8_lit("sec-fetch-mode"));
  return m && m->size && !str8_match(*m, str8_lit("navigate"));
}

// Reorder `h` by a profile fetch_order (a const char* name list). No-op if the
// profile has no fetch order. Names absent from the request are skipped.
internal void apply_fetch_order(Arena *arena, HeaderList *h,
                                const char *const *order, U8 count) {
  if (!order || count == 0) return;
  String8 *names = push_array_no_zero(arena, String8, count);
  for (U8 i = 0; i < count; ++i) names[i] = str8_cstring(order[i]);
  reorder_headers(arena, h, names, count);
}

// Split a comma/whitespace-separated header-name list into `out` (views into
// `csv`'s bytes — the caller must keep `csv` alive while the views are used).
// Returns the count, clamped to `cap`; empty/whitespace-only => 0. Shared by
// the client-level setter and the per-request header_order parse.
internal U64 parse_header_order_csv(String8 csv, String8 *out, U64 cap) {
  U64 n = 0, i = 0;
  while (i < csv.size && n < cap) {
    while (i < csv.size &&
           (csv.str[i] == ',' || csv.str[i] == ' ' || csv.str[i] == '\t'))
      i++;  // skip delimiters
    U64 start = i;
    while (i < csv.size && csv.str[i] != ',' && csv.str[i] != ' ' &&
           csv.str[i] != '\t')
      i++;
    if (i > start) out[n++] = str8(csv.str + start, i - start);
  }
  return n;
}

// The one place a request's final wire order is chosen, shared by the pooled
// and non-pooled submit paths (the pooled path used to skip it ->
// set_header_order was a silent no-op when pooling). Precedence: a non-empty
// per-request order
// (`req_order_csv`, a comma/whitespace name list) REPLACES the client-level
// order, which overrides the profile's fetch_order auto-pick. `fetch_order`/
// `fo_count` are the active profile's (h2 vs h3) fetch order. No-op when none
// applies (default fingerprint intact). The CSV's bytes need only outlive this
// call (reorder_headers moves entries, it does not retain the name views).
internal void apply_header_order(Client *c, Arena *arena, HeaderList *list,
                                 String8 req_order_csv,
                                 const char *const *fetch_order, U8 fo_count) {
  if (req_order_csv.size) {
    String8 names[CLIENT_HEADER_ORDER_MAX];
    U64 n =
        parse_header_order_csv(req_order_csv, names, CLIENT_HEADER_ORDER_MAX);
    if (n) {
      reorder_headers(arena, list, names, n);
      return;
    }
  }
  if (c->header_order_count)
    reorder_headers(arena, list, c->header_order, c->header_order_count);
  else if (!c->override_default_headers && headers_are_fetch(list))
    apply_fetch_order(arena, list, fetch_order, fo_count);
}

// --- request/response hooks (opt-in middleware) ----------------------------
internal B32 name_ci_prefix(String8 n, String8 p) {
  return n.size >= p.size && str8_match_ci(str8_prefix(n, p.size), p);
}
// Headers the profile owns (fingerprint-defining): a hook may not change them.
internal B32 hook_header_protected(String8 n) {
  return str8_match_ci(n, str8_lit("user-agent")) ||
         str8_match_ci(n, str8_lit("accept-encoding")) ||
         name_ci_prefix(n, str8_lit("sec-fetch-")) ||
         name_ci_prefix(n, str8_lit("sec-ch-ua"));
}
B32 hook_request_set_header(HookRequest *req, String8 name, String8 value) {
  if (!req || !req->headers || hook_header_protected(name)) return 0;
  String8 *existing = header_list_get_ci(req->headers, name);
  if (existing) {
    *existing =
        push_str8_copy(req->headers->arena, value);  // override in place
    return 1;
  }
  header_list_push(req->headers, push_str8_copy(req->headers->arena, name),
                   push_str8_copy(req->headers->arena, value), 0);
  return 1;
}
// Fired once per wire request, right after headers are finalized. Mutates the
// already-arena-backed HeaderList in place (no copy). No-op when no hook is
// set.
internal void client_run_pre_hook(Client *c, Method m, String8 url,
                                  HeaderList *h) {
  if (!c->pre_hook) return;
  HookRequest req = {m, url, h};
  client_cb_enter(c);  // hooks are user code: same no-cleanup contract as cbs
  (void)c->pre_hook(&req, c->pre_hook_user);  // return value reserved
  client_cb_exit(c);
}
// Fired once per wire response, on the live Response (no copy), just before the
// caller callback. No-op when no hook is set.
internal void client_run_post_hook(Client *c, Response *resp) {
  if (!c || !c->post_hook) return;
  client_cb_enter(c);  // hooks are user code: same no-cleanup contract as cbs
  c->post_hook(resp, c->post_hook_user);
  client_cb_exit(c);
}

// Resolve a header's HTTP/1.1 wire casing (mirrors wreq's original-case map): a
// profile default's `wire_name`, a builtin for the managed names, else the name
// as the caller passed it (already original-case).
internal String8 h1_wire_name(const Profile *p, String8 name) {
  for (U64 i = 0; i < p->default_header_count; ++i)
    if (str8_match_ci(name, str8_cstring(p->default_headers[i].name))) {
      const char *w = p->default_headers[i].wire_name;
      return w ? str8_cstring(w) : name;
    }
  if (str8_match_ci(name, str8_lit("content-length")))
    return str8_lit("Content-Length");
  if (str8_match_ci(name, str8_lit("accept-encoding")))
    return str8_lit("Accept-Encoding");
  return name;
}

// Re-case the merged (lowercase-default) request headers to their HTTP/1.1 wire
// spelling, preserving order, into `out`. h2/h3 keep using the lowercase list.
internal void build_h1_headers(Arena *arena, const Profile *p, HeaderList *src,
                               HeaderList *out) {
  header_list_init(out, arena);
  for (U64 i = 0; i < src->count; ++i)
    header_list_push(out, h1_wire_name(p, src->v[i].name), src->v[i].value,
                     src->v[i].flags);
}

// ---------------------------------------------------------------------------
// H2 / TCP request
// ---------------------------------------------------------------------------
typedef struct H2Request H2Request;
struct H2Request {
  Arena *arena;
  Client *client;
  Connection conn;
  H2Session *h2;  // one of h2/h1 is set after on_ready (decided by ALPN)
  H1Session *h1;
  ResponseFn cb;
  void *user;
  U64 t_start_ns;  // request start (uv_hrtime) for Response.timing.total_ms
  String8 method, scheme, authority, path, origin, body, url, host;
  U16 port;
  HeaderList req_headers;
  HeaderList resp_headers;  // filtered view when the body is decoded
  B32 responded;
  B32 closing;
  B32 idempotent;  // GET/HEAD: eligible to be sent as 0-RTT early data
  B32 submitted;   // the request was handed to the h2/h1 session
  B32 retrying;    // closing in order to reconnect (0-RTT reject fallback)
  B32 retried_no_early;  // already retried once without 0-RTT (one-shot guard)
  ReqTimer *timeout;     // whole-operation deadline timer (0 = no timeout)
  ProxyConfig proxy;     // resolved proxy for this request (type None = direct)
  BodyChunkFn
      on_chunk;  // streaming sink (0 = buffer); set => empty Response body
  void *chunk_user;
};

internal void h2req_deliver_error(H2Request *req, const char *err);
internal void h2req_finish(H2Request *req);
internal void tcp_deliver(H2Request *req, int status, HeaderList *headers,
                          const U8 *body, U64 body_len, B32 ok, String8 alpn);
internal void h1req_on_response(void *user, const H1Response *r);
internal void build_h1_headers(Arena *arena, const Profile *p, HeaderList *src,
                               HeaderList *out);

internal void h2req_send(void *user, const U8 *data, U64 len) {
  H2Request *req = (H2Request *)user;
  conn_send_plaintext(&req->conn, data, len);
}

internal void h2req_drain(void *user) {
  H2Request *req = (H2Request *)user;
  if (req->closing) return;
  U8 buf[16384];
  for (;;) {
    int n = conn_read_plaintext(&req->conn, buf, sizeof buf);
    if (n <= 0) break;
    S64 r;
    if (req->h2)
      r = h2_session_recv(req->h2, buf, (U64)n);
    else if (req->h1)
      r = h1_session_recv(req->h1, buf, (U64)n);
    else
      break;
    if (r < 0) {
      h2req_deliver_error(req,
                          req->h2 ? "h2 protocol error" : "h1 parse error");
      h2req_finish(req);
      return;
    }
    if (req->closing) return;
  }
}

// Transparently decode the response's Content-Encoding in place: on success the
// body is replaced with the decoded bytes and the headers are rebuilt into
// `scratch` without content-encoding/content-length (both describe the wire
// form, not the decoded body). A decode failure (unknown coding, bomb cap,
// corrupt stream) leaves the response as received. The one copy of this logic —
// shared by the non-pooled H2/H1 + QUIC paths and (via the unity build) pool.c.
internal void response_decode_encoding(Arena *arena, Response *resp,
                                       HeaderList *scratch) {
  String8 ce = str8_zero();
  for (U64 i = 0; i < resp->header_count; ++i)
    if (str8_match_ci(resp->headers[i].name, str8_lit("content-encoding"))) {
      ce = resp->headers[i].value;
      break;
    }
  String8 decoded;
  if (!ce.size ||
      !decode_content(arena, ce, resp->body, resp->body_len, &decoded))
    return;
  resp->body = decoded.str;
  resp->body_len = decoded.size;
  header_list_init(scratch, arena);
  for (U64 i = 0; i < resp->header_count; ++i) {
    const Header *h = &resp->headers[i];
    if (!str8_match_ci(h->name, str8_lit("content-encoding")) &&
        !str8_match_ci(h->name, str8_lit("content-length")))
      header_list_push(scratch, h->name, h->value, h->flags);
  }
  resp->headers = scratch->v;
  resp->header_count = scratch->count;
}

// Build the unified Response from a completed exchange (h2 or h1): record
// alt-svc, transparently decode Content-Encoding (stripping the stale c-e/c-l
// headers), deliver to the caller, finish. Shared by both transports.
internal void tcp_deliver(H2Request *req, int status, HeaderList *headers,
                          const U8 *body, U64 body_len, B32 ok, String8 alpn) {
  if (req->responded) return;
  req->responded = 1;
  if (req->client && headers) {
    String8 *as = header_list_get_ci(headers, str8_lit("alt-svc"));
    if (as) client_note_alt_svc(req->client, req->origin, *as);
  }
  Response resp;
  MemoryZeroStruct(&resp);
  resp.ok = ok;
  resp.status = status;
  resp.headers = headers ? headers->v : 0;
  resp.header_count = headers ? headers->count : 0;
  resp.body = body;
  resp.body_len = body_len;
  resp.alpn = alpn;
  resp.resumed = conn_resumed(&req->conn);
  resp.early_data = conn_early_data_accepted(&req->conn);
  resp.final_url = req->url;
  conn_timing_ms(&req->conn, req->t_start_ns, &resp.timing.dns_ms,
                 &resp.timing.tcp_ms, &resp.timing.tls_ms);
  resp.timing.total_ms = (uv_hrtime() - req->t_start_ns) / 1000000;
  response_decode_encoding(req->arena, &resp, &req->resp_headers);
  // Streaming: an H2-streamed body already left via on_chunk (empty here, so
  // this no-ops); an H1 body is buffered, so hand it over as one chunk. Either
  // way the final Response carries no body.
  if (req->on_chunk && resp.body_len > 0) {
    req->on_chunk(req->chunk_user, resp.body, resp.body_len);
    resp.body = 0;
    resp.body_len = 0;
  }
  client_run_post_hook(req->client, &resp);
  client_cb_enter(req->client);
  if (req->cb) req->cb(req->user, &resp);
  client_cb_exit(req->client);
  h2req_finish(req);
}

internal void h2req_on_response(void *user, const H2Response *r) {
  H2Request *req = (H2Request *)user;
  tcp_deliver(req, r->status, r->headers, r->body, r->body_len, r->ok,
              str8_lit("h2"));
}

internal void h1req_on_response(void *user, const H1Response *r) {
  H2Request *req = (H2Request *)user;
  tcp_deliver(req, r->status, r->headers, r->body, r->body_len, r->ok,
              str8_lit("http/1.1"));
}

// Allocate the protocol session (h2/h1 by ALPN) and submit the request. The
// same path runs whether the bytes go out as 0-RTT early data (the early-ready
// window) or after a completed handshake. Returns 1 on success; on failure it
// has already delivered an error + finished the request.
internal B32 h2req_send_request(H2Request *req) {
  if (str8_match(conn_alpn(&req->conn), str8_lit("h2"))) {
    req->h2 = h2_session_alloc(&req->client->profile->h2, h2req_send, req);
    if (!req->h2 || !h2_session_start(req->h2)) {
      h2req_deliver_error(req, "h2 session init failed");
      h2req_finish(req);
      return 0;
    }
    conn_on_readable(&req->conn, h2req_drain, req);
    S32 sid = h2_session_submit_request(
        req->h2, req->method, req->scheme, req->authority, req->path,
        req->req_headers.v, req->req_headers.count, req->body.str,
        req->body.size, h2req_on_response, req, req->on_chunk, req->chunk_user);
    if (sid < 0) {
      h2req_deliver_error(req, "submit failed");
      h2req_finish(req);
      return 0;
    }
  } else {
    // http/1.1 (or empty ALPN -> assume HTTP/1.1).
    HeaderList h1_headers;
    build_h1_headers(req->arena, req->client->profile, &req->req_headers,
                     &h1_headers);
    req->h1 = h1_session_alloc(h2req_send, req);
    if (!req->h1) {
      h2req_deliver_error(req, "h1 session init failed");
      h2req_finish(req);
      return 0;
    }
    conn_on_readable(&req->conn, h2req_drain, req);
    B32 is_head = str8_match(req->method, str8_lit("HEAD"));
    if (h1_session_submit_request(req->h1, req->method, req->authority,
                                  req->path, h1_headers.v, h1_headers.count,
                                  req->body.str, req->body.size, is_head,
                                  h1req_on_response, req) < 0) {
      h2req_deliver_error(req, "submit failed");
      h2req_finish(req);
      return 0;
    }
  }
  req->submitted = 1;
  return 1;
}

// 0-RTT window is open: submit the request now so it is written as early data.
internal void h2req_on_early_ready(void *user) {
  H2Request *req = (H2Request *)user;
  h2req_send_request(req);
}

internal void h2req_connect(H2Request *req, B32 allow_early);

internal void h2req_on_ready(void *user, B32 ok, const char *err) {
  H2Request *req = (H2Request *)user;
  if (!ok) {
    // The server rejected our 0-RTT early data: retry the (idempotent) request
    // once on a fresh, non-0-RTT connection. The early-data bytes were
    // discarded; strip 0-RTT from the cached session so the retry resumes plain
    // 1-RTT.
    if (conn_early_rejected(&req->conn) && !req->retried_no_early) {
      req->retried_no_early = 1;
      req->retrying = 1;
      resume_cache_strip_early(req->client, req->origin);
      conn_close(&req->conn);  // -> h2req_on_fully_closed reconnects (no 0-RTT)
      return;
    }
    h2req_deliver_error(req, err ? err : "connect failed");
    h2req_finish(req);
    return;
  }
  // Submit now unless it already went out as early data (0-RTT accepted). Then
  // drain any response the server already sent (incl. an accepted 0-RTT one).
  if (!req->submitted && !h2req_send_request(req)) return;
  h2req_drain(req);
}

// Build-and-deliver an error Response (only .error + .final_url populated) to a
// request callback, bracketed by the re-entrancy guard. The per-request
// `responded` latch stays at each call site — it lives in differently-typed
// request structs (H2Request / QuicRequest / PoolReq) that otherwise share this
// identical tail across the direct and pooled paths.
internal void client_deliver_error(Client *c, ResponseFn cb, void *user,
                                   String8 final_url, const char *err) {
  Response resp;
  MemoryZeroStruct(&resp);
  resp.error = err;
  resp.final_url = final_url;
  client_cb_enter(c);
  if (cb) cb(user, &resp);
  client_cb_exit(c);
}

internal void h2req_deliver_error(H2Request *req, const char *err) {
  if (req->responded) return;
  req->responded = 1;
  client_deliver_error(req->client, req->cb, req->user, req->url, err);
}

internal void h2req_finish(H2Request *req) {
  if (req->closing) return;
  req->closing = 1;
  conn_close(&req->conn);
}

// Deadline reached: deliver a timeout error + tear the request down (both
// guarded, so a response landing in the same loop tick is a no-op). The
// teardown's on_fully_closed disarms the timer.
internal void h2req_on_timeout(void *user) {
  H2Request *req = (H2Request *)user;
  h2req_deliver_error(req, "timeout");
  h2req_finish(req);
}

internal void h2req_on_closed(void *user, const char *e) {
  H2Request *req = (H2Request *)user;
  // A clean EOF finalizes a close-delimited HTTP/1.1 body (success).
  if (req->h1 && !req->responded) h1_session_eof(req->h1);
  if (!req->responded) {
    h2req_deliver_error(req, e ? e : "connection closed");
    h2req_finish(req);
  }
}

internal void h2req_on_fully_closed(void *user) {
  H2Request *req = (H2Request *)user;
  if (req->h2) {
    h2_session_release(req->h2);
    req->h2 = 0;
  }
  if (req->h1) {
    h1_session_release(req->h1);
    req->h1 = 0;
  }
  conn_cleanup(&req->conn);
  if (req->retrying) {
    // 0-RTT-reject fallback: re-dispatch the same request on a fresh connection
    // with early data disabled. The request state (headers/body) is intact.
    req->retrying = 0;
    req->closing = 0;
    req->submitted = 0;
    h2req_connect(req,
                  /*allow_early=*/0);  // keep the timer armed (same deadline)
    return;
  }
  req_timer_disarm(req->timeout);  // before the arena holding `req` is recycled
  arena_recycle(req->arena);       // clear + return to the pool (was: release)
}

// Open the connection for this request and (re)wire its callbacks + per-conn
// TLS options. allow_early controls whether 0-RTT is attempted (off on a
// retry).
internal void h2req_connect(H2Request *req, B32 allow_early) {
  Client *c = req->client;
  // Forced HTTP/1.1 uses the http/1.1-only ALPN profile so the server picks h1.
  const TlsProfile *tls =
      c->http_version == HttpVersion_H1 ? &c->h1_tls : &c->profile->tls;
  conn_init(&req->conn, c->loop, c->ctx.ctx, tls);
  conn_on_fully_closed(&req->conn, h2req_on_fully_closed, req);
  conn_on_closed(&req->conn, h2req_on_closed, req);
  conn_set_dns_cache(&req->conn, &c->dns_cache);
  if (c->has_local_address)  // bind the chosen egress source IP
    conn_set_local_address(&req->conn, str8_cstring(c->local_address));
  if (req->proxy.type != ProxyType_None)  // tunnel through the resolved proxy
    conn_set_proxy(&req->conn, &req->proxy, c->proxy_ctx.ctx, &c->proxy_tls);
  if (c->ech_enabled) {  // offer real ECH if the origin's config is cached
    EchConfigEntry *e = ech_cache_get(c, req->origin);
    if (e && e->config_len) conn_set_ech(&req->conn, e->config, e->config_len);
  }
  if (c->resume_enabled) {  // offer a cached ticket + capture new ones
    SSL_SESSION *sess = resume_cache_get(c, req->origin);
    conn_set_resume(&req->conn, sess,
                    client_resume_ctx_make(c, req->arena, req->origin));
    // 0-RTT only for an idempotent, bodyless request with a cached session; the
    // connection then verifies the session is actually 0-RTT-capable. Early
    // data is replayable, so this gate is a correctness requirement (GET/HEAD
    // only).
    if (allow_early && c->early_data_enabled && req->idempotent &&
        req->body.size == 0 && sess) {
      conn_set_early_data(&req->conn, 1);
      conn_on_early_ready(&req->conn, h2req_on_early_ready, req);
    }
  }
  conn_connect(&req->conn, push_str8_cstr(req->arena, req->host), req->port,
               h2req_on_ready, req);
}

internal void h2req_start(Client *c, Method m, String8 url,
                          const Header *headers, U64 header_count,
                          const U8 *body, U64 body_len, ResponseFn cb,
                          void *user, U64 deadline_ns, const ProxyConfig *proxy,
                          BodyChunkFn on_chunk, void *chunk_user,
                          String8 header_order) {
  Arena *arena = arena_acquire();
  H2Request *req = push_array(arena, H2Request, 1);
  req->arena = arena;
  req->client = c;
  req->cb = cb;
  req->user = user;
  req->proxy = proxy ? *proxy : c->proxy;  // resolved proxy (None = direct)
  req->on_chunk = on_chunk;                // streaming sink (0 = buffer)
  req->chunk_user = chunk_user;
  req->t_start_ns = uv_hrtime();
  req->method = method_str(m);
  req->idempotent = (m == Method_GET || m == Method_HEAD);

  String8 u = push_str8_copy(arena, url);  // views below point into this
  req->url = u;
  ParsedUrl pu = url_parse(u);
  if (!pu.ok || !pu.https) {
    Response resp;
    MemoryZeroStruct(&resp);
    resp.error = "invalid or non-https URL";
    resp.final_url = u;
    client_cb_enter(c);
    if (cb) cb(user, &resp);
    client_cb_exit(c);
    arena_recycle(arena);
    return;
  }
  req->scheme = pu.scheme;
  req->authority = pu.authority;
  req->path = pu.path;
  req->host = pu.host;
  req->port = pu.port;
  req->origin = origin_of(arena, pu);
  req->body = build_request_headers(
      arena, c->profile->default_headers, c->profile->default_header_count,
      headers, header_count, body, body_len, c->override_default_headers, m,
      &req->req_headers);
  client_run_pre_hook(c, m, u, &req->req_headers);
  apply_header_order(c, arena, &req->req_headers, header_order,
                     c->profile->fetch_order, c->profile->fetch_order_count);

  req->timeout = req_timer_arm(c->loop, deadline_ns, h2req_on_timeout, req);
  h2req_connect(req, /*allow_early=*/1);
}

// ---------------------------------------------------------------------------
// H3 / QUIC request
// ---------------------------------------------------------------------------
typedef struct QuicRequest QuicRequest;
struct QuicRequest {
  Arena *arena;
  Client *client;
  QuicConnection conn;
  H3Session *h3;
  ResponseFn cb;
  void *user;
  U64 t_start_ns;  // request start (uv_hrtime) for Response.timing.total_ms
  Method method;
  String8 authority, path, body, url, host, origin;
  U16 port;
  HeaderList req_headers;
  HeaderList resp_headers;
  B32 responded;
  B32 closing;
  B32 idempotent;        // GET/HEAD: eligible for 0-RTT
  B32 submitted;         // the request was handed to the h3 session
  B32 retrying;          // closing to reconnect (0-RTT reject fallback)
  B32 retried_no_early;  // already retried once without 0-RTT (one-shot guard)
  ReqTimer *timeout;     // whole-operation deadline timer (0 = no timeout)
  ProxyConfig proxy;     // resolved proxy for this request (type None = direct)
  BodyChunkFn
      on_chunk;  // streaming sink (0 = buffer); set => empty Response body
  void *chunk_user;
};

internal void quicreq_deliver_error(QuicRequest *req, const char *err);
internal void quicreq_finish(QuicRequest *req);
internal void quicreq_connect(QuicRequest *req, B32 allow_early);

// Capture this (now-established) connection's QUIC 0-RTT transport params so
// the next connection to the origin can offer 0-RTT (paired with the ticket).
internal void quicreq_capture_tp(QuicRequest *req) {
  if (!req->client->resume_enabled) return;
  U8 tp[256];
  U64 n = quic_conn_encode_0rtt_tp(&req->conn, tp, sizeof tp);
  if (n) resume_cache_put_tp(req->client, req->origin, tp, n);
}

internal void quicreq_on_response(void *user, const H3Response *r) {
  QuicRequest *req = (QuicRequest *)user;
  if (req->responded) return;
  req->responded = 1;
  Response resp;
  MemoryZeroStruct(&resp);
  resp.ok = r->ok;
  resp.error = r->error;
  resp.status = r->status;
  resp.headers = r->headers;
  resp.header_count = r->header_count;
  resp.body = r->body;
  resp.body_len = r->body_len;
  resp.alpn = str8_lit("h3");
  resp.resumed = quic_conn_resumed(&req->conn);
  resp.early_data = quic_conn_early_accepted(&req->conn);
  resp.final_url = req->url;
  quic_conn_timing_ms(&req->conn, req->t_start_ns, &resp.timing.dns_ms,
                      &resp.timing.tcp_ms, &resp.timing.tls_ms);
  resp.timing.total_ms = (uv_hrtime() - req->t_start_ns) / 1000000;
  response_decode_encoding(req->arena, &resp, &req->resp_headers);
  // Streaming fallback for H3 (buffered, not memory-bounded in v1): hand the
  // decoded body over as a single chunk; the final Response carries no body.
  if (req->on_chunk && resp.body_len > 0) {
    req->on_chunk(req->chunk_user, resp.body, resp.body_len);
    resp.body = 0;
    resp.body_len = 0;
  }
  client_run_post_hook(req->client, &resp);
  client_cb_enter(req->client);
  if (req->cb) req->cb(req->user, &resp);
  client_cb_exit(req->client);
  quicreq_finish(req);
}

// Create the H3 session + submit the request. Same path whether the bytes go
// out as 0-RTT (early window) or after a completed handshake. Returns 1 on
// success; on failure it has already delivered an error + finished.
internal B32 quicreq_send_request(QuicRequest *req) {
  req->h3 = h3_session_alloc(&req->conn, req->conn.h3);
  if (!req->h3) {
    quicreq_deliver_error(req, "h3 session init failed");
    quicreq_finish(req);
    return 0;
  }
  if (!h3_session_request(req->h3, method_str(req->method), str8_lit("https"),
                          req->authority, req->path, req->req_headers.v,
                          req->req_headers.count, req->body.str, req->body.size,
                          quicreq_on_response, req)) {
    quicreq_deliver_error(req, "h3 request submit failed");
    quicreq_finish(req);
    return 0;
  }
  req->submitted = 1;
  return 1;
}

// 0-RTT window open: submit the request now so it is written as early data.
internal void quicreq_on_early_ready(void *user) {
  QuicRequest *req = (QuicRequest *)user;
  quicreq_send_request(req);
}

internal void quicreq_on_ready(void *user, B32 ok, const char *err) {
  QuicRequest *req = (QuicRequest *)user;
  if (!ok) {
    quicreq_deliver_error(req, err ? err : "connect failed");
    quicreq_finish(req);
    return;
  }
  // 0-RTT rejected: ngtcp2 discarded the early streams. Retry the (idempotent)
  // request once on a fresh, non-0-RTT connection; strip 0-RTT from the cache.
  if (quic_conn_early_rejected(&req->conn) && !req->retried_no_early) {
    req->retried_no_early = 1;
    req->retrying = 1;
    resume_cache_strip_early(req->client, req->origin);
    quic_conn_close(&req->conn);  // -> quicreq_on_fully_closed reconnects
    return;
  }
  // Cache this connection's 0-RTT transport params for a future 0-RTT attempt.
  quicreq_capture_tp(req);
  // Submit now unless it already went out as 0-RTT (the response arrives via
  // the request stream, delivered through quicreq_on_response).
  if (!req->submitted) quicreq_send_request(req);
}

internal void quicreq_deliver_error(QuicRequest *req, const char *err) {
  if (req->responded) return;
  req->responded = 1;
  client_deliver_error(req->client, req->cb, req->user, req->url, err);
}

internal void quicreq_finish(QuicRequest *req) {
  if (req->closing) return;
  req->closing = 1;
  quic_conn_close(&req->conn);
}

internal void quicreq_on_timeout(
    void *user) {  // deadline reached (both guarded)
  QuicRequest *req = (QuicRequest *)user;
  quicreq_deliver_error(req, "timeout");
  quicreq_finish(req);
}

internal void quicreq_on_closed(void *user, const char *e) {
  QuicRequest *req = (QuicRequest *)user;
  if (req->retrying)
    return;  // a stray close during the 0-RTT-reject retry window
  if (!req->responded) {
    quicreq_deliver_error(req, e ? e : "connection closed");
    quicreq_finish(req);
  }
}

internal void quicreq_on_fully_closed(void *user) {
  QuicRequest *req = (QuicRequest *)user;
  if (req->h3) {
    h3_session_release(req->h3);
    req->h3 = 0;
  }
  quic_conn_cleanup(&req->conn);
  if (req->retrying) {
    // 0-RTT-reject fallback: re-dispatch on a fresh connection, no early data.
    req->retrying = 0;
    req->closing = 0;
    req->submitted = 0;
    quicreq_connect(req,
                    /*allow_early=*/0);  // keep the timer armed (same deadline)
    return;
  }
  req_timer_disarm(req->timeout);  // before the arena holding `req` is recycled
  arena_recycle(req->arena);       // clear + return to the pool (was: release)
}

// Open the QUIC connection for this request + (re)wire callbacks / TLS options.
// allow_early controls whether 0-RTT is attempted (off on a retry).
internal void quicreq_connect(QuicRequest *req, B32 allow_early) {
  Client *c = req->client;
  quic_conn_init(&req->conn, c->loop, c->h3_ctx.ctx, &c->h3_profile->tls,
                 &c->h3_profile->h3);
  quic_on_fully_closed(&req->conn, quicreq_on_fully_closed, req);
  quic_on_closed(&req->conn, quicreq_on_closed, req);
  quic_set_dns_cache(&req->conn, &c->dns_cache);
  if (c->has_local_address)  // bind the chosen egress source IP (UDP)
    quic_set_local_address(&req->conn, str8_cstring(c->local_address));
  if (req->proxy.type ==
      ProxyType_Socks5)  // tunnel QUIC via SOCKS5 UDP ASSOCIATE
    quic_set_proxy(&req->conn, &req->proxy);
  if (c->ech_enabled) {  // offer real ECH if the origin's config is cached
    EchConfigEntry *e = ech_cache_get(c, req->origin);
    if (e && e->config_len) quic_set_ech(&req->conn, e->config, e->config_len);
  }
  if (c->resume_enabled) {  // offer a cached ticket + capture new ones
    SSL_SESSION *sess = resume_cache_get(c, req->origin);
    quic_set_resume(&req->conn, sess,
                    client_resume_ctx_make(c, req->arena, req->origin));
    // 0-RTT needs an idempotent bodyless request, a cached session, AND cached
    // transport params (the connection then verifies the session is 0-RTT
    // capable). Replay safety: GET/HEAD only.
    if (allow_early && c->early_data_enabled && req->idempotent &&
        req->body.size == 0 && sess) {
      U64 tp_len = 0;
      const U8 *tp = resume_cache_tp(c, req->origin, &tp_len);
      if (tp && tp_len) {
        quic_set_early_data(&req->conn, tp, tp_len);
        quic_on_early_ready(&req->conn, quicreq_on_early_ready, req);
      }
    }
  }
  quic_conn_connect(&req->conn, push_str8_cstr(req->arena, req->host),
                    req->port, quicreq_on_ready, req);
}

internal void quicreq_start(Client *c, Method m, String8 url,
                            const Header *headers, U64 header_count,
                            const U8 *body, U64 body_len, ResponseFn cb,
                            void *user, U64 deadline_ns,
                            const ProxyConfig *proxy, BodyChunkFn on_chunk,
                            void *chunk_user, String8 header_order) {
  Arena *arena = arena_acquire();
  QuicRequest *req = push_array(arena, QuicRequest, 1);
  req->arena = arena;
  req->client = c;
  req->cb = cb;
  req->user = user;
  req->on_chunk = on_chunk;  // streaming sink (0 = buffer)
  req->chunk_user = chunk_user;
  req->proxy = proxy ? *proxy : c->proxy;  // resolved proxy (None = direct)
  req->t_start_ns = uv_hrtime();
  req->method = m;
  req->idempotent = (m == Method_GET || m == Method_HEAD);

  String8 u = push_str8_copy(arena, url);
  req->url = u;
  ParsedUrl pu = url_parse(u);
  if (!pu.ok || !pu.https) {
    Response resp;
    MemoryZeroStruct(&resp);
    resp.error = "invalid or non-https URL";
    resp.final_url = u;
    client_cb_enter(c);
    if (cb) cb(user, &resp);
    client_cb_exit(c);
    arena_recycle(arena);
    return;
  }
  req->authority = pu.authority;
  req->path = pu.path;
  req->host = pu.host;
  req->port = pu.port;
  req->origin = origin_of(arena, pu);
  req->body = build_request_headers(
      arena, c->h3_profile->default_headers,
      c->h3_profile->default_header_count, headers, header_count, body,
      body_len, c->override_default_headers, m, &req->req_headers);
  client_run_pre_hook(c, m, u, &req->req_headers);
  apply_header_order(c, arena, &req->req_headers, header_order,
                     c->h3_profile->fetch_order,
                     c->h3_profile->fetch_order_count);

  req->timeout = req_timer_arm(c->loop, deadline_ns, quicreq_on_timeout, req);
  quicreq_connect(req, /*allow_early=*/1);
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------
void client_init(Client *c, EventLoop *loop, const Profile *h2,
                 const QuicProfile *h3, HttpVersion mode, B32 verify) {
  MemoryZeroStruct(c);
  c->loop = loop;
  c->profile = h2;
  c->ctx = build_ctx(&h2->tls, verify);
  // Build the QUIC transport iff the chosen mode can use H3 and an h3 profile
  // was given (AUTO upgrades via alt-svc; H3 forces it). H2/H1 stay on TCP, and
  // a NULL h3 is H2/H1-only regardless of mode. `mode` is the wire-protocol
  // policy; client_set_http_version can narrow it later (but can't add QUIC).
  if (h3 && (mode == HttpVersion_Auto || mode == HttpVersion_H3)) {
    c->h3_profile = h3;
    c->h3_ctx = build_ctx(&h3->tls, verify);
  }
  c->http_version = mode;
  c->proxy_verify = 1;  // verify HTTPS-proxy certs by default (per-request)
  dns_cache_init(&c->dns_cache, DNS_CACHE_DEFAULT_TTL_MS);
}

void client_cleanup(Client *c) {
  // Cleanup from inside a response callback is a use-after-free: the delivery
  // path touches client state after the callback returns (see client.h).
  Assert(c->in_callback == 0);
  if (c->pool) {
    pool_drain(c->pool);
    // Pump the loop so each conn's fully-closed cb frees its arena
    // (loop_shutdown closes handles with a NULL cb and would skip them).
    // Bounded as a backstop.
    for (int guard = 0; c->pool->count > 0 && guard < 1000; ++guard)
      uv_run(loop_uv(c->loop), UV_RUN_NOWAIT);
    pool_free(c->pool);
    c->pool = 0;
  }
  // Free cached resumption tickets (done after draining the pool so any ticket
  // a closing connection issued during the pump above is freed here too).
  for (int i = 0; i < c->resume_cache_count; ++i)
    if (c->resume_cache[i].session)
      SSL_SESSION_free(c->resume_cache[i].session);
  c->resume_cache_count = 0;
  if (c->ctx.ctx) SSL_CTX_free(c->ctx.ctx);
  if (c->h3_ctx.ctx) SSL_CTX_free(c->h3_ctx.ctx);
  if (c->proxy_ctx.ctx)
    SSL_CTX_free(c->proxy_ctx.ctx);  // HTTPS-proxy outer TLS
  c->ctx.ctx = 0;
  c->h3_ctx.ctx = 0;
  c->proxy_ctx.ctx = 0;
}

B32 client_ok(Client *c) { return ctx_ok(&c->ctx); }

internal void client_note_alt_svc(Client *c, String8 origin, String8 value) {
  AltSvcInfo info = alt_svc_parse(value);
  if (!info.h3) return;
  U64 expiry = uv_now(loop_uv(c->loop)) + info.ma_seconds * 1000;
  for (int i = 0; i < c->alt_svc_count; ++i)
    if (str8_match(origin, str8_cstring(c->alt_svc[i].origin))) {
      c->alt_svc[i].h3 = 1;
      c->alt_svc[i].expiry_ms = expiry;
      return;
    }
  AltSvcEntry *e;
  if (c->alt_svc_count < (int)ArrayCount(c->alt_svc)) {
    e = &c->alt_svc[c->alt_svc_count++];
  } else {
    // Full: recycle the entry closest to expiry (expired first) so new origins
    // keep getting alt-svc upgrades instead of being silently ignored.
    e = &c->alt_svc[0];
    for (int i = 1; i < c->alt_svc_count; ++i)
      if (c->alt_svc[i].expiry_ms < e->expiry_ms) e = &c->alt_svc[i];
  }
  U64 n =
      origin.size < sizeof e->origin - 1 ? origin.size : sizeof e->origin - 1;
  MemoryCopy(e->origin, origin.str, n);
  e->origin[n] = 0;
  e->h3 = 1;
  e->expiry_ms = expiry;
}

B32 client_h3_available(Client *c, String8 origin) {
  U64 now = uv_now(loop_uv(c->loop));
  for (int i = 0; i < c->alt_svc_count; ++i)
    if (c->alt_svc[i].h3 &&
        str8_match(origin, str8_cstring(c->alt_svc[i].origin)))
      return now < c->alt_svc[i].expiry_ms;
  return 0;
}

// Internal dispatch: client_ok check + Chrome-style H3-vs-H2 selection. The
// public client_request wraps this with redirect handling when enabled.
internal void client_dispatch_inner(Client *c, Method m, String8 url,
                                    const Header *headers, U64 header_count,
                                    const U8 *body, U64 body_len, ResponseFn cb,
                                    void *user, U64 deadline_ns,
                                    const ProxyConfig *proxy,
                                    BodyChunkFn on_chunk, void *chunk_user,
                                    String8 header_order) {
  if (!client_ok(c)) {
    Response r;
    MemoryZeroStruct(&r);
    r.error = "TLS context init failed";
    client_cb_enter(c);
    if (cb) cb(user, &r);
    client_cb_exit(c);
    return;
  }
  HttpVersion hv = c->http_version;
  // The proxy in effect for this request: the per-request override / pool pick
  // (`proxy`) if given, else the client's single proxy. Rotation/override
  // forces the per-request transport path (pooling would defeat the rotation).
  const ProxyConfig *px = proxy ? proxy : &c->proxy;
  // Streaming and rotation/override both take the non-pooled per-request path
  // (the pool buffers + would defeat both).
  B32 use_pool = c->pool && c->max_conns_per_origin && !proxy && !on_chunk;

  // HTTP/HTTPS CONNECT proxies are TCP-only, so H3 can't tunnel through them. A
  // SOCKS5 proxy carries UDP (UDP ASSOCIATE), so H3 IS allowed through SOCKS5.
  if ((px->type == ProxyType_Http || px->type == ProxyType_Https) &&
      hv == HttpVersion_H3) {
    Response r;
    MemoryZeroStruct(&r);
    r.error = "HTTP/3 cannot be used through an HTTP/HTTPS proxy (use SOCKS5)";
    client_cb_enter(c);
    if (cb) cb(user, &r);
    client_cb_exit(c);
    return;
  }

  // Forced HTTP/3: dispatch straight to QUIC (no alt-svc warmup). Strict —
  // needs a dual-transport client; otherwise the request fails rather than
  // falling back.
  if (hv == HttpVersion_H3) {
    if (!(c->h3_profile && ctx_ok(&c->h3_ctx))) {
      Response r;
      MemoryZeroStruct(&r);
      r.error =
          "HTTP/3 forced but client has no QUIC profile (build it with an h3 "
          "profile + HttpVersion_Auto/_H3)";
      client_cb_enter(c);
      if (cb) cb(user, &r);
      client_cb_exit(c);
      return;
    }
    if (use_pool)
      pool_dispatch(c, PoolProto_H3, m, url, headers, header_count, body,
                    body_len, cb, user, deadline_ns, header_order);
    else
      quicreq_start(c, m, url, headers, header_count, body, body_len, cb, user,
                    deadline_ns, proxy, on_chunk, chunk_user, header_order);
    return;
  }

  // Forced HTTP/1.1: pooled (keep-alive) when opted in, else the legacy
  // per-request TCP path (a full handshake per request). Both use c->h1_tls
  // (http/1.1-only ALPN) so the server negotiates http/1.1 — byte-identical
  // wire either way (fingerprint-safe). use_pool is already false for
  // proxy/streaming/ max_conns==0, so those keep the legacy path.
  if (hv == HttpVersion_H1) {
    if (use_pool)
      pool_dispatch(c, PoolProto_H1, m, url, headers, header_count, body,
                    body_len, cb, user, deadline_ns, header_order);
    else
      h2req_start(c, m, url, headers, header_count, body, body_len, cb, user,
                  deadline_ns, proxy, on_chunk, chunk_user, header_order);
    return;
  }

  // Auto (Chrome-style): prefer QUIC for origins known (via alt-svc) to support
  // h3. Forced H2 skips this gate and stays on TCP. A SOCKS5 proxy permits H3
  // (UDP ASSOCIATE); HTTP/HTTPS proxies force TCP.
  if (hv == HttpVersion_Auto &&
      (px->type == ProxyType_None || px->type == ProxyType_Socks5) &&
      c->h3_profile && ctx_ok(&c->h3_ctx)) {
    ParsedUrl pu = url_parse(url);
    if (pu.ok) {
      Temp scratch = scratch_begin(0, 0);
      B32 avail = client_h3_available(c, origin_of(scratch.arena, pu));
      scratch_end(scratch);
      if (avail) {
        if (use_pool)  // opt-in pooling (H3/QUIC)
          pool_dispatch(c, PoolProto_H3, m, url, headers, header_count, body,
                        body_len, cb, user, deadline_ns, header_order);
        else
          quicreq_start(c, m, url, headers, header_count, body, body_len, cb,
                        user, deadline_ns, proxy, on_chunk, chunk_user,
                        header_order);
        return;
      }
    }
  }
  if (use_pool) {  // opt-in pooling (H2/TCP)
    pool_dispatch(c, PoolProto_H2, m, url, headers, header_count, body,
                  body_len, cb, user, deadline_ns, header_order);
    return;
  }
  h2req_start(c, m, url, headers, header_count, body, body_len, cb, user,
              deadline_ns, proxy, on_chunk, chunk_user, header_order);
}

//- real ECH: per-origin ECHConfigList cache + DoH prefetch gate -------------

#define ECH_DOH_ORIGIN "dns.google:443"
#define ECH_CACHE_TTL_MS 600000  // 10 min (HTTPS-RR TTLs ~5 min)

internal EchConfigEntry *ech_cache_get(Client *c, String8 origin) {
  U64 now = uv_now(loop_uv(c->loop));
  for (int i = 0; i < c->ech_cache_count; ++i)
    if (str8_match(origin, str8_cstring(c->ech_cache[i].origin)))
      return now < c->ech_cache[i].expiry_ms ? &c->ech_cache[i] : 0;
  return 0;
}

// Cache the resolved config for `origin`. An empty config is a cached negative
// result (no ECH published -> GREASE) so we don't re-query every request.
internal void ech_cache_put(Client *c, String8 origin, String8 config) {
  U64 expiry = uv_now(loop_uv(c->loop)) + ECH_CACHE_TTL_MS;
  EchConfigEntry *e = 0;
  for (int i = 0; i < c->ech_cache_count; ++i)
    if (str8_match(origin, str8_cstring(c->ech_cache[i].origin))) {
      e = &c->ech_cache[i];
      break;
    }
  if (!e) {
    if (c->ech_cache_count < (int)ArrayCount(c->ech_cache)) {
      e = &c->ech_cache[c->ech_cache_count++];
    } else {
      // Full: recycle the entry closest to expiry (expired first) so new
      // origins still get real ECH instead of silently degrading to GREASE.
      e = &c->ech_cache[0];
      for (int i = 1; i < c->ech_cache_count; ++i)
        if (c->ech_cache[i].expiry_ms < e->expiry_ms) e = &c->ech_cache[i];
    }
    U64 n =
        origin.size < sizeof e->origin - 1 ? origin.size : sizeof e->origin - 1;
    MemoryCopy(e->origin, origin.str, n);
    e->origin[n] = 0;
  }
  U64 clen = config.size < sizeof e->config ? config.size : sizeof e->config;
  if (clen) MemoryCopy(e->config, config.str, clen);
  e->config_len = clen;
  e->expiry_ms = expiry;
}

typedef struct EchPrefetch EchPrefetch;
struct EchPrefetch {
  Arena *arena;  // own; holds the stashed request until the DoH completes
  Client *client;
  String8 origin;
  Method method;
  String8 url;
  HeaderList headers;
  String8 body;
  ResponseFn cb;
  void *user;
  U64 deadline_ns;  // the operation deadline (the DoH round-trip eats into it)
  ProxyConfig proxy;  // the request's resolved proxy (carried across the DoH)
  B32 has_proxy;  // 1 => use proxy on replay; 0 => the client's single proxy
  BodyChunkFn on_chunk;  // streaming sink (carried across the DoH)
  void *chunk_user;
  String8 header_order;  // per-request wire order CSV, carried across the DoH
};

internal void client_ech_doh_cb(void *user, const Response *r) {
  EchPrefetch *pf = (EchPrefetch *)user;
  Client *c = pf->client;
  String8 config = str8_zero();
  if (r->ok && r->body && r->body_len)
    config = ech_config_from_doh(pf->arena, str8((U8 *)r->body, r->body_len));
  ech_cache_put(c, pf->origin, config);
  // Replay the original request, bypassing the gate (already prefetched).
  client_dispatch_inner(c, pf->method, pf->url, pf->headers.v,
                        pf->headers.count, pf->body.str, pf->body.size, pf->cb,
                        pf->user, pf->deadline_ns,
                        pf->has_proxy ? &pf->proxy : 0, pf->on_chunk,
                        pf->chunk_user, pf->header_order);
  arena_release(pf->arena);
}

// Stash the request, fetch the origin's ECHConfigList over DoH, then replay.
internal void client_ech_prefetch(Client *c, Method m, String8 url,
                                  const Header *headers, U64 header_count,
                                  const U8 *body, U64 body_len, ResponseFn cb,
                                  void *user, ParsedUrl pu, U64 deadline_ns,
                                  const ProxyConfig *proxy,
                                  BodyChunkFn on_chunk, void *chunk_user,
                                  String8 header_order) {
  Arena *a = arena_alloc();
  EchPrefetch *pf = push_struct(a, EchPrefetch);
  pf->arena = a;
  pf->client = c;
  pf->origin = origin_of(a, pu);
  pf->deadline_ns = deadline_ns;
  if (proxy) {
    pf->proxy = *proxy;
    pf->has_proxy = 1;
  }
  pf->on_chunk = on_chunk;
  pf->chunk_user = chunk_user;
  pf->method = m;
  pf->url = push_str8_copy(a, url);
  header_list_init(&pf->headers, a);
  for (U64 i = 0; i < header_count; ++i)
    header_list_push(&pf->headers, push_str8_copy(a, headers[i].name),
                     push_str8_copy(a, headers[i].value), headers[i].flags);
  pf->body =
      body_len ? push_str8_copy(a, str8((U8 *)body, body_len)) : str8_zero();
  pf->header_order =
      header_order.size ? push_str8_copy(a, header_order) : str8_zero();
  pf->cb = cb;
  pf->user = user;
  String8 doh = push_str8f(a, "https://dns.google/resolve?name=%.*s&type=HTTPS",
                           (int)pu.host.size, pu.host.str);
  // The DoH lookup itself goes via the client's single proxy (NULL = c->proxy),
  // independent of the original request's rotation/override choice, is never
  // streamed (0,0), and carries no custom header order (str8_zero).
  client_dispatch_inner(c, Method_GET, doh, 0, 0, 0, 0, client_ech_doh_cb, pf,
                        deadline_ns, 0, 0, 0, str8_zero());
}

// The dispatch gate: when ECH is on and the target's config isn't cached yet,
// fetch it first (DoH) and replay; otherwise dispatch normally. `proxy` is the
// request's resolved proxy (0 = the client's single proxy); `on_chunk` streams
// the body (0 = buffer); `header_order` is the per-request wire-order CSV
// (empty = the client-level order).
internal void client_dispatch(Client *c, Method m, String8 url,
                              const Header *headers, U64 header_count,
                              const U8 *body, U64 body_len, ResponseFn cb,
                              void *user, U64 deadline_ns,
                              const ProxyConfig *proxy, BodyChunkFn on_chunk,
                              void *chunk_user, String8 header_order) {
  if (c->ech_enabled) {
    ParsedUrl pu = url_parse(url);
    if (pu.ok && pu.https) {
      Temp scr = scratch_begin(0, 0);
      String8 origin = origin_of(scr.arena, pu);
      B32 prefetch = !str8_match(origin, str8_lit(ECH_DOH_ORIGIN)) &&
                     !ech_cache_get(c, origin);
      scratch_end(scr);
      if (prefetch) {
        client_ech_prefetch(c, m, url, headers, header_count, body, body_len,
                            cb, user, pu, deadline_ns, proxy, on_chunk,
                            chunk_user, header_order);
        return;
      }
    }
  }
  client_dispatch_inner(c, m, url, headers, header_count, body, body_len, cb,
                        user, deadline_ns, proxy, on_chunk, chunk_user,
                        header_order);
}

// The absolute deadline (uv_hrtime ns) for a new operation from the client's
// timeout, or 0 when no timeout is configured.
internal U64 client_deadline(Client *c) {
  return c->timeout_ms ? uv_hrtime() + c->timeout_ms * 1000000ull : 0;
}

//- redirect following

internal B32 is_redirect_status(int s) {
  return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
}

// Browser-faithful next method for a `status` redirect of method `m`; sets
// *drop_body when the request body should be dropped.
Method redirect_next_method(Method m, int status, B32 *drop_body) {
  *drop_body = 0;
  if (status == 303) {  // See Other -> GET
    *drop_body = 1;
    return Method_GET;
  }
  if ((status == 301 || status == 302) && m == Method_POST) {  // POST -> GET
    *drop_body = 1;
    return Method_GET;
  }
  return m;  // 307/308, and non-POST on 301/302: preserve method + body
}

// One redirect hop's state transition — the single copy shared by the client's
// redirect loop and the Session's cookie-aware loop (drift between the two
// would mean subtly different redirect behavior with vs without cookies).
// Given the current request state and its response, decides whether to follow:
// on yes, fills `out` with the resolved next URL, the browser-faithful next
// method, whether the body must be dropped, and the carried headers rebuilt in
// `arena` (stale content-length/type dropped with the body, Authorization
// dropped cross-origin, Sec-Fetch-Site recomputed). Returns 0 to deliver the
// response instead (not a 3xx, no Location, or a non-https target).
typedef struct RedirectHop RedirectHop;
struct RedirectHop {
  String8 next_url;
  Method next_method;
  B32 drop_body;
  HeaderList headers;
};
internal B32 redirect_prepare_hop(Arena *arena, String8 cur_url, Method m,
                                  const HeaderList *carried, const Response *r,
                                  RedirectHop *out) {
  if (!r->ok || !is_redirect_status(r->status)) return 0;
  String8 loc = str8_zero();
  for (U64 i = 0; i < r->header_count; ++i)
    if (str8_match_ci(r->headers[i].name, str8_lit("location"))) {
      loc = r->headers[i].value;
      break;
    }
  if (!loc.size) return 0;
  String8 next = url_resolve(arena, cur_url, loc);
  ParsedUrl npu = url_parse(next);
  if (!npu.ok || !npu.https) return 0;  // only follow http(s)
  out->drop_body = 0;
  out->next_method = redirect_next_method(m, r->status, &out->drop_body);
  out->next_url = next;
  ParsedUrl cpu = url_parse(cur_url);
  B32 cross = !(cpu.ok && str8_match_ci(cpu.host, npu.host));
  // Recompute Sec-Fetch-Site for the new hop (monotonic; from the carried
  // running value + Referer). str8_zero() => leave it as-is (navigations).
  String8 new_site =
      sec_fetch_site_for_redirect(carried->v, carried->count, next);
  header_list_init(&out->headers, arena);
  for (U64 i = 0; i < carried->count; ++i) {
    String8 name = carried->v[i].name;
    if (out->drop_body && (str8_match_ci(name, str8_lit("content-length")) ||
                           str8_match_ci(name, str8_lit("content-type"))))
      continue;  // body gone -> these are stale
    if (cross && str8_match_ci(name, str8_lit("authorization")))
      continue;  // don't leak credentials cross-origin
    String8 value = carried->v[i].value;
    if (new_site.size && str8_match_ci(name, str8_lit("sec-fetch-site")))
      value = new_site;
    header_list_push(&out->headers, name, value, carried->v[i].flags);
  }
  return 1;
}

typedef struct RedirectState RedirectState;
struct RedirectState {
  Arena *arena;  // own arena, persists across hops (freed at chain end)
  Client *client;
  ResponseFn user_cb;
  void *user;
  Method method;
  HeaderList headers;  // carried caller headers (own arena)
  String8 body;        // carried body (own arena)
  String8 cur_url;     // current absolute URL
  U64 left;            // remaining redirect budget
  U64 chain_start_ns;  // whole-chain start (uv_hrtime) for total_ms
  U64 deadline_ns;     // whole-chain timeout deadline (0 = none), shared by all
                       // hops
  ProxyConfig proxy;   // resolved proxy, sticky across the whole chain
  B32 has_proxy;       // 1 => use proxy; 0 => the client's single proxy
  String8 header_order;  // per-request wire order CSV (own arena), every hop
};

internal void client_redirect_cb(void *user, const Response *r) {
  RedirectState *st = (RedirectState *)user;
  RedirectHop hop;
  if (st->left > 0 && redirect_prepare_hop(st->arena, st->cur_url, st->method,
                                           &st->headers, r, &hop)) {
    st->headers = hop.headers;
    st->method = hop.next_method;
    if (hop.drop_body) st->body = str8_zero();
    st->cur_url = hop.next_url;
    st->left--;
    client_dispatch(
        st->client, st->method, st->cur_url, st->headers.v, st->headers.count,
        st->body.str, st->body.size, client_redirect_cb, st, st->deadline_ns,
        st->has_proxy ? &st->proxy : 0, /*on_chunk=*/0, 0, st->header_order);
    return;
  }
  // Final response (or no Location / budget exhausted / error): deliver + free.
  // Override total_ms to span the whole redirect chain (the per-hop value on
  // `r` covers only the final hop). Shallow copy is safe — header/body pointers
  // stay valid for the callback's duration.
  if (st->user_cb) {
    Response rc = *r;
    rc.timing.total_ms = (uv_hrtime() - st->chain_start_ns) / 1000000;
    st->user_cb(st->user, &rc);
  }
  arena_release(st->arena);
}

// Build the shared HTTPS-proxy outer TLS context on first need
// (host-independent — one ctx serves the single proxy, every pool entry, and
// any per-request override). Idempotent; freed in client_cleanup, self-healing
// if a later client_set_proxy frees it.
internal void client_ensure_proxy_ctx(Client *c, B32 verify) {
  if (c->proxy_ctx.ctx) return;
  c->proxy_tls = c->profile->tls;
  c->proxy_tls.alpn_wire = k_alpn_http11;
  c->proxy_tls.alpn_wire_len = (U16)sizeof k_alpn_http11;
  c->proxy_tls.alps_count = 0;
  c->proxy_ctx = build_ctx(&c->proxy_tls, verify);
  c->proxy_verify =
      verify;  // record the verify the live shared ctx was built
               // with, so it stays consistent with the ctx (the
               // ctx is build-once; the FIRST HTTPS proxy's verify
               // wins until a client_set_proxy change frees it)
}

// Resolve the proxy in effect for a request: a per-request override URL (if
// valid) wins, else the next rotation-pool entry (round-robin). Returns 1 +
// fills *out when a rotation/override proxy applies (forcing the non-pooled
// path); 0 means "use the client's single proxy" (the legacy path). Builds the
// HTTPS outer ctx on demand.
internal B32 client_resolve_proxy(Client *c, String8 override_url,
                                  ProxyConfig *out) {
  if (override_url.size) {
    if (!proxy_parse(override_url, out)) return 0;  // malformed -> fall back
    if (out->type == ProxyType_Https)
      client_ensure_proxy_ctx(c, c->proxy_verify);
    return 1;
  }
  if (c->proxy_pool_count) {
    *out = c->proxy_pool[c->proxy_rr];
    c->proxy_rr = (U8)((c->proxy_rr + 1) % c->proxy_pool_count);
    if (out->type ==
        ProxyType_Https)  // (re)build the shared outer ctx on demand
      client_ensure_proxy_ctx(c, c->proxy_verify);
    return 1;
  }
  return 0;
}

void client_request(Client *c, const RequestParams *p, ResponseFn cb,
                    void *user) {
  // Resolve this request's proxy once (per-request override > rotation pool >
  // the client's single proxy), sticky across the whole redirect chain.
  ProxyConfig chosen;
  MemoryZeroStruct(&chosen);
  B32 have_proxy = client_resolve_proxy(c, p->proxy, &chosen);
  const ProxyConfig *px = have_proxy ? &chosen : 0;  // 0 => client's c->proxy
  // Sec-Fetch synthesis (the former client_fetch): when a fetch_mode is set,
  // merge the coherent Sec-Fetch-* headers ahead of dispatch. The merged set
  // lives in its own arena, copied synchronously by the dispatch / redirect
  // setup below, so it's released before we return.
  const Header *headers = p->headers;
  U64 header_count = p->header_count;
  Arena *fetch_arena = 0;
  if (p->fetch_mode != FetchMode_Default) {
    fetch_arena = arena_alloc();
    HeaderList merged;
    header_list_init(&merged, fetch_arena);
    sec_fetch_merge(&merged, p->fetch_mode, p->url, headers, header_count);
    headers = merged.v;
    header_count = merged.count;
  }

  U64 deadline = p->deadline_ns ? p->deadline_ns : client_deadline(c);

  // Single hop: caller forced it (the former client_send), following is
  // disabled on the client, or streaming (a streamed body is terminal — we
  // can't follow a redirect after handing chunks to the sink).
  if (p->no_redirects || c->max_redirects == 0 || p->on_chunk) {
    client_dispatch(c, p->method, p->url, headers, header_count, p->body.str,
                    p->body.size, cb, user, deadline, px, p->on_chunk,
                    p->chunk_user, p->header_order);
    if (fetch_arena) arena_release(fetch_arena);
    return;
  }

  // Carry the request across hops in its own arena (the per-hop request arenas
  // are independent and freed as each hop completes).
  Arena *arena = arena_alloc();
  RedirectState *st = push_struct(arena, RedirectState);
  st->arena = arena;
  st->client = c;
  st->user_cb = cb;
  st->user = user;
  st->method = p->method;
  st->left = c->max_redirects;
  st->chain_start_ns = uv_hrtime();
  st->deadline_ns = deadline;  // one deadline for the whole chain
  st->proxy = chosen;          // sticky proxy across the whole chain
  st->has_proxy = have_proxy;
  st->cur_url = push_str8_copy(arena, p->url);
  header_list_init(&st->headers, arena);
  for (U64 i = 0; i < header_count; ++i)
    header_list_push(&st->headers, push_str8_copy(arena, headers[i].name),
                     push_str8_copy(arena, headers[i].value), headers[i].flags);
  st->body = p->body.size ? push_str8_copy(arena, p->body) : str8_zero();
  st->header_order = p->header_order.size
                         ? push_str8_copy(arena, p->header_order)
                         : str8_zero();
  client_dispatch(c, p->method, st->cur_url, st->headers.v, st->headers.count,
                  st->body.str, st->body.size, client_redirect_cb, st,
                  st->deadline_ns, px, /*on_chunk=*/0, 0,
                  st->header_order);  // redirects never stream
  if (fetch_arena) arena_release(fetch_arena);
}

void client_get(Client *c, String8 url, ResponseFn cb, void *user) {
  client_request(c, &(RequestParams){.method = Method_GET, .url = url}, cb,
                 user);
}

void client_post(Client *c, String8 url, String8 body, ResponseFn cb,
                 void *user) {
  client_request(
      c, &(RequestParams){.method = Method_POST, .url = url, .body = body}, cb,
      user);
}

////////////////////////////////
//~ Blocking (sync) request helpers
//
// Run the loop until the request(s) complete and return an ARENA-OWNED Response
// — body/headers/error/final_url/alpn copied into the caller's `arena`, so a
// caller with a linear flow never writes a ResponseFn + loop_run + copy-out.
// Thin convenience over client_request: identical wire behavior, no fingerprint
// change. Mirrors the blocking C-API (capi/holytls_capi.c) but copies into an
// arena, not malloc. Call from the TOP LEVEL — these run their own loop_run, so
// they must NOT be called from inside a ResponseFn (that would nest loop_run).

// Deep-copy a "valid only during the callback" Response into `arena` so it
// outlives the loop tick (the per-request transport arena is recycled right
// after the callback returns). Mirrors the CAPI response_copy, arena-based.
internal Response *response_copy_arena(Arena *arena, const Response *r) {
  Response *out = push_struct(arena, Response);
  out->ok = r->ok;
  out->status = r->status;
  out->resumed = r->resumed;
  out->early_data = r->early_data;
  out->timing = r->timing;
  out->alpn = push_str8_copy(arena, r->alpn);
  out->final_url = push_str8_copy(arena, r->final_url);
  if (r->error) out->error = push_str8_cstr(arena, str8_cstring(r->error));
  if (r->body_len) {
    U8 *b = push_array_no_zero(arena, U8, r->body_len);
    MemoryCopy(b, r->body, r->body_len);
    out->body = b;
    out->body_len = r->body_len;
  }
  if (r->header_count && r->headers) {
    Header *hs = push_array(arena, Header, r->header_count);
    for (U64 i = 0; i < r->header_count; ++i) {
      hs[i].name = push_str8_copy(arena, r->headers[i].name);
      hs[i].value = push_str8_copy(arena, r->headers[i].value);
      hs[i].flags = r->headers[i].flags;
    }
    out->headers = hs;
    out->header_count = r->header_count;
  }
  return out;
}

// A synthetic ok=0 Response in `arena` for the (defensive) case where the
// callback never delivered one.
internal Response *response_error_arena(Arena *arena, const char *msg) {
  Response *r = push_struct(arena, Response);  // zeroed -> ok=0
  r->error = push_str8_cstr(arena, str8_cstring(msg));
  return r;
}

typedef struct SyncCtx SyncCtx;
struct SyncCtx {
  EventLoop *loop;
  Arena *arena;
  Response **slot;  // where to stash this request's arena-owned copy
  int *pending;     // shared; the loop stops when it reaches 0
};

internal void sync_on_response(void *user, const Response *resp) {
  SyncCtx *cx = (SyncCtx *)user;
  *cx->slot = response_copy_arena(cx->arena, resp);
  if (--(*cx->pending) == 0) loop_stop(cx->loop);  // last one home -> wake up
}

Response *client_request_sync(Client *c, const RequestParams *p, Arena *arena) {
  Response *out = 0;
  int pending = 1;
  SyncCtx cx = {c->loop, arena, &out, &pending};
  client_request(c, p, sync_on_response, &cx);
  loop_run(c->loop);  // always (uv_run clears the stop flag on exit)
  return out ? out : response_error_arena(arena, "no response");
}

Response *client_get_sync(Client *c, String8 url, Arena *arena) {
  return client_request_sync(
      c, &(RequestParams){.method = Method_GET, .url = url}, arena);
}

Response *client_post_sync(Client *c, String8 url, String8 body, Arena *arena) {
  return client_request_sync(
      c, &(RequestParams){.method = Method_POST, .url = url, .body = body},
      arena);
}

Response **client_request_all(Client *c, const RequestParams *reqs, U64 n,
                              Arena *arena) {
  Response **out = push_array(arena, Response *, n);  // zeroed
  if (n == 0) return out;
  // Count submittable (non-empty url) first, so `pending` starts at the full
  // total and a synchronous early delivery can't stop the loop mid-submit.
  int pending = 0;
  for (U64 i = 0; i < n; ++i)
    if (reqs[i].url.size) pending++;
  SyncCtx *ctxs = push_array(arena, SyncCtx, n);
  for (U64 i = 0; i < n; ++i) {
    if (!reqs[i].url.size) {
      out[i] = response_error_arena(arena, "invalid request (no url)");
      continue;
    }
    ctxs[i] = (SyncCtx){c->loop, arena, &out[i], &pending};
    client_request(c, &reqs[i], sync_on_response, &ctxs[i]);
  }
  loop_run(c->loop);  // drive all in-flight requests to completion
  for (U64 i = 0; i < n; ++i)
    if (!out[i]) out[i] = response_error_arena(arena, "no response");
  return out;
}

void client_set_max_redirects(Client *c, U64 max) { c->max_redirects = max; }

void client_set_timeout_ms(Client *c, U64 ms) { c->timeout_ms = ms; }
U64 client_get_timeout_ms(Client *c) { return c->timeout_ms; }

void client_set_ech_enabled(Client *c, B32 on) { c->ech_enabled = on; }

void client_set_resumption_enabled(Client *c, B32 on) {
  c->resume_enabled = on;
  if (!on) return;
  // Turn on the client session cache + capture callback on both TLS contexts.
  // This only controls whether tickets are captured; the ClientHello changes
  // solely when a cached session is later offered (on reconnect).
  SSL_CTX *ctxs[2] = {c->ctx.ctx, c->h3_ctx.ctx};
  for (int i = 0; i < 2; ++i) {
    if (!ctxs[i]) continue;
    SSL_CTX_set_session_cache_mode(ctxs[i], SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(ctxs[i], client_resume_new_cb);
  }
}

void client_set_early_data_enabled(Client *c, B32 on) {
  c->early_data_enabled = on;
  // 0-RTT needs a cached, 0-RTT-capable session, which only the resumption
  // cache provides — enabling early data implies enabling resumption.
  if (on && !c->resume_enabled) client_set_resumption_enabled(c, 1);
}

void client_set_key_log_file(Client *c, const char *path) {
  if (!keylog_open(path)) return;
  // Register on both contexts; the same callback serves TLS and QUIC.
  if (c->ctx.ctx) SSL_CTX_set_keylog_callback(c->ctx.ctx, keylog_callback);
  if (c->h3_ctx.ctx)
    SSL_CTX_set_keylog_callback(c->h3_ctx.ctx, keylog_callback);
}

B32 client_pin_certificate(Client *c, const char *hostname,
                           const char *sha256_b64, B32 include_subdomains) {
  if (!cert_pin_add(&c->pin_store, hostname, sha256_b64, include_subdomains))
    return 0;
  // Make the store reachable from per-connection verification on both contexts
  // (configure_ssl looks it up via the SSL's CTX). Idempotent.
  cert_pin_attach_ctx(c->ctx.ctx, &c->pin_store);
  cert_pin_attach_ctx(c->h3_ctx.ctx, &c->pin_store);
  return 1;
}

B32 client_add_ca_file(Client *c, const char *path) {
  // Add the file's CA cert(s) to BOTH contexts' trust stores, on top of the
  // system roots build_ctx loaded (the X509_STORE accumulates). Same file =>
  // same result on both, so a first-failure return is safe. Only matters with
  // verify=1.
  SSL_CTX *ctxs[2] = {c->ctx.ctx, c->h3_ctx.ctx};
  B32 any = 0;
  for (int i = 0; i < 2; ++i) {
    if (!ctxs[i]) continue;
    if (!SSL_CTX_load_verify_locations(ctxs[i], path, 0)) return 0;
    any = 1;
  }
  return any;
}

// PEM passphrase callback: copy the stashed (NUL-terminated) password into buf.
// userdata is set only for the duration of a single key load, then cleared.
internal int client_pem_passwd_cb(char *buf, int size, int rwflag,
                                  void *userdata) {
  (void)rwflag;
  if (!userdata) return 0;
  const char *pw = (const char *)userdata;
  int n = (int)strlen(pw);
  if (n > size) n = size;
  MemoryCopy(buf, pw, (U64)n);
  return n;
}

B32 client_set_client_cert(Client *c, String8 cert_path, String8 key_path,
                           String8 passphrase) {
  Temp scr = scratch_begin(0, 0);
  const char *cp = push_str8_cstr(scr.arena, cert_path);
  const char *kp = push_str8_cstr(scr.arena, key_path);
  const char *pw = passphrase.size ? push_str8_cstr(scr.arena, passphrase) : 0;
  // Present the cert on BOTH target contexts (H2/TCP + QUIC/H3); the proxy ctx
  // (outer TLS to a proxy) is left alone — a client cert is for the target.
  // SSL_new() inherits the cert/key, so every connection presents it.
  SSL_CTX *ctxs[2] = {c->ctx.ctx, c->h3_ctx.ctx};
  B32 any = 0, ok = 1;
  for (int i = 0; i < 2; ++i) {
    if (!ctxs[i]) continue;
    SSL_CTX_set_default_passwd_cb(ctxs[i], client_pem_passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctxs[i], (void *)pw);
    if (SSL_CTX_use_certificate_chain_file(ctxs[i], cp) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctxs[i], kp, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctxs[i]) != 1)
      ok = 0;
    SSL_CTX_set_default_passwd_cb_userdata(ctxs[i], 0);  // drop the scratch ptr
    any = 1;
  }
  scratch_end(scr);
  return (any && ok) ? 1 : 0;
}

void client_set_dns_cache_ttl_ms(Client *c, U64 ms) {
  c->dns_cache.ttl_ms = ms;
}

void client_set_http_version(Client *c, HttpVersion v) {
  c->http_version = v;
  if (v == HttpVersion_H1) {
    // Chrome's TLS knobs, but advertise only http/1.1 and drop ALPS (an h2-only
    // extension). The SSL_CTX (ciphers/extensions) is unchanged; only the
    // per-connection ALPN/ALPS that configure_ssl applies differ.
    c->h1_tls = c->profile->tls;
    c->h1_tls.alpn_wire = k_alpn_http11;
    c->h1_tls.alpn_wire_len = (U16)sizeof k_alpn_http11;
    c->h1_tls.alps_count = 0;
  }
}

B32 client_set_header_order(Client *c, const String8 *names, U64 count) {
  if (count > CLIENT_HEADER_ORDER_MAX) return 0;
  for (U64 i = 0; i < count; ++i) {
    U64 cap = sizeof c->header_order_buf[i] - 1;
    U64 n = names[i].size < cap ? names[i].size : cap;
    MemoryCopy(c->header_order_buf[i], names[i].str, n);
    c->header_order_buf[i][n] = 0;
    c->header_order[i] = str8((U8 *)c->header_order_buf[i], n);
  }
  c->header_order_count = (U8)count;  // 0 resets to the profile order
  return 1;
}

B32 client_set_header_order_str(Client *c, const char *names) {
  // Split on commas and/or whitespace, so "accept, accept-language, user-agent"
  // and "accept accept-language user-agent" both work. An empty string resets.
  // Names past CLIENT_HEADER_ORDER_MAX are dropped (Chrome sends ~15).
  String8 list[CLIENT_HEADER_ORDER_MAX];
  U64 n = parse_header_order_csv(str8_cstring(names), list,
                                 CLIENT_HEADER_ORDER_MAX);
  return client_set_header_order(c, list, n);  // copies the views
}

U64 client_get_header_order(Client *c, String8 *out, U64 cap) {
  if (c->header_order_count) {  // the active override
    U64 n = c->header_order_count < cap ? c->header_order_count : cap;
    for (U64 i = 0; i < n; ++i) out[i] = c->header_order[i];
    return c->header_order_count;
  }
  const DefaultHeader *d =
      c->profile->default_headers;  // else the profile order
  U64 dc = c->profile->default_header_count;
  U64 n = dc < cap ? dc : cap;
  for (U64 i = 0; i < n; ++i) out[i] = str8_cstring(d[i].name);
  return dc;
}

void client_override_default_headers(Client *c, B32 on) {
  c->override_default_headers = on;
}
B32 client_get_override_default_headers(Client *c) {
  return c->override_default_headers;
}

// Safe to call at runtime to rotate the proxy. An empty URL goes direct. A bad
// URL leaves the current proxy untouched and returns 0. Re-setting the same
// proxy is a no-op (warm pooled conns are kept). On a real change the new proxy
// applies to every subsequent request; in-flight requests finish on the old
// proxy.
B32 client_set_proxy(Client *c, String8 proxy_url, B32 verify_proxy) {
  // Parse the requested config (empty == direct). proxy_parse zeroes first, so
  // a MemoryCompare against the current config reliably detects a real change.
  ProxyConfig next;
  MemoryZeroStruct(&next);
  if (proxy_url.size && !proxy_parse(proxy_url, &next))
    return 0;  // malformed URL: keep the existing proxy unchanged
  if (MemoryCompare(&next, &c->proxy, sizeof next) == 0) return 1;  // no change

  // Changed. The old HTTPS-proxy ctx is safe to free now — any live connection
  // holds its own ref (conn_set_proxy). Install the new config + outer ctx.
  if (c->proxy_ctx.ctx) {
    SSL_CTX_free(c->proxy_ctx.ctx);
    MemoryZeroStruct(&c->proxy_ctx);
  }
  c->proxy = next;
  if (c->proxy.type == ProxyType_Https)        // build the shared outer-TLS ctx
    client_ensure_proxy_ctx(c, verify_proxy);  // records proxy_verify
  // Stop reusing pooled conns established through the old proxy (new requests
  // open fresh conns through the new one). No-op when pooling is off.
  if (c->pool) pool_evict_all(c->pool);
  return 1;
}

B32 client_add_proxy(Client *c, String8 proxy_url, B32 verify_proxy) {
  if (c->proxy_pool_count >= CLIENT_PROXY_POOL_MAX) return 0;
  ProxyConfig pc;
  MemoryZeroStruct(&pc);
  if (!proxy_url.size || !proxy_parse(proxy_url, &pc)) return 0;  // malformed
  c->proxy_pool[c->proxy_pool_count++] = pc;
  if (pc.type == ProxyType_Https)  // build the shared outer-TLS ctx eagerly
    client_ensure_proxy_ctx(c, verify_proxy);  // records proxy_verify
  return 1;
}

String8 client_get_proxy(Client *c, Arena *arena) {
  return proxy_to_url(arena, &c->proxy);
}

B32 client_set_local_address(Client *c, String8 ip) {
  if (ip.size == 0) {  // clear -> OS default
    c->has_local_address = 0;
    c->local_address[0] = 0;
    return 1;
  }
  if (ip.size >= sizeof c->local_address) return 0;
  char buf[64];
  MemoryCopy(buf, ip.str, ip.size);
  buf[ip.size] = 0;
  U64 idx;
  int af = str8_index_of(ip, ':', &idx) ? AF_INET6 : AF_INET;
  U8 tmp[16];
  if (inet_pton(af, buf, tmp) != 1) return 0;  // not a valid IP literal
  MemoryCopy(c->local_address, buf, ip.size + 1);
  c->has_local_address = 1;
  return 1;
}

//- response convenience accessors -------------------------------------------

String8 response_text(const Response *r) {
  return r->body ? str8((U8 *)r->body, r->body_len) : str8_zero();
}

String8 response_get_header(const Response *r, String8 name) {
  for (U64 i = 0; i < r->header_count; ++i)
    if (str8_match_ci(r->headers[i].name, name)) return r->headers[i].value;
  return str8_zero();
}

B32 response_is_success(const Response *r) {
  return r->ok && r->status >= 200 && r->status < 300;
}

B32 response_is_redirect(const Response *r) {
  return r->status >= 300 && r->status < 400;
}

yyjson_doc *response_json(const Response *r, Arena *arena) {
  return json_parse(arena, response_text(r));
}

void client_set_pre_hook(Client *c, PreRequestHook fn, void *user) {
  c->pre_hook = fn;
  c->pre_hook_user = user;
}

void client_set_post_hook(Client *c, PostResponseHook fn, void *user) {
  c->post_hook = fn;
  c->post_hook_user = user;
}

//- connection pooling (opt-in)

void client_set_max_conns_per_origin(Client *c, U64 max) {
  c->max_conns_per_origin = max;
  if (max > 0 && !c->pool)
    c->pool = pool_alloc(c);
  else if (max == 0 && c->pool)
    pool_drain(c->pool);  // stop reusing; freed in client_cleanup
}

void client_set_pool_idle_timeout_ms(Client *c, U64 ms) {
  c->pool_idle_timeout_ms = ms;
}

PoolStats client_pool_stats(Client *c) { return c->pool_stats; }

void client_pool_drain(Client *c) {
  if (c->pool) pool_drain(c->pool);
}
