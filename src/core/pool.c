#include "core/pool.h"

#include "core/decompress.h"
#include "core/url.h"
#include "h3/h3_control.h"

// This file is part of the unity TU and is #included AFTER core/client.c, so it
// reuses client.c's internal helpers directly: method_str, origin_of,
// build_request_headers, client_note_alt_svc, and the legacy h2req_start (used
// for the H1 fallback when a pooled origin negotiates HTTP/1.1).

// H3 per-conn concurrency cap: send_bufs[32] minus the 3 persistent uni streams,
// kept comfortably under the array bound so quic_open_*_stream never runs dry.
#define POOL_H3_MAX_CONCURRENT 16

//- forward decls ------------------------------------------------------------
internal void pool_acquire(ConnPool *p, PoolProto proto, PoolReq *r);
internal void pool_submit(PoolConn *pc, PoolReq *r);
internal void pool_h2_submit(PoolConn *pc, PoolReq *r);
internal void pool_h3_submit(PoolConn *pc, PoolReq *r);
internal void pool_close_conn(PoolConn *pc);
internal void pool_conn_fail_all(PoolConn *pc, const char *err);
internal void pool_update_idle(PoolConn *pc);
internal void pool_flush_waiting(PoolConn *pc);
internal void pool_deliver(PoolReq *r, B32 ok, const char *error, int status,
                           const Header *headers, U64 header_count,
                           const U8 *body, U64 body_len, String8 alpn);
internal void pool_h2_on_ready(void *user, B32 ok, const char *err);
internal void pool_h2_on_closed(void *user, const char *e);
internal void pool_h2_on_fully_closed(void *user);
internal void pool_h2_drain(void *user);
internal void pool_h2_on_response(void *user, const H2Response *hr);
internal void pool_h3_on_ready(void *user, B32 ok, const char *err);
internal void pool_h3_on_closed(void *user, const char *e);
internal void pool_h3_on_fully_closed(void *user);
internal void pool_h3_on_stream_data(void *user, S64 sid, const U8 *data,
                                     U64 len, B32 fin);
internal void pool_h3_on_stream_close(void *user, S64 sid);
internal void pool_h3_recv_done(void *user);
internal void pool_h3_finish(PoolConn *pc, PoolReq *r);
internal void pool_req_timeout(void *user);

//- intrusive request lists --------------------------------------------------
internal void pool_active_push(PoolConn *pc, PoolReq *r) {
  r->active_next = pc->active_head;
  pc->active_head = r;
}
internal void pool_active_remove(PoolConn *pc, PoolReq *r) {
  PoolReq **pp = &pc->active_head;
  while (*pp) {
    if (*pp == r) {
      *pp = r->active_next;
      r->active_next = 0;
      return;
    }
    pp = &(*pp)->active_next;
  }
}
internal void pool_waiting_push(PoolConn *pc, PoolReq *r) {
  r->queue_next = 0;
  if (pc->waiting_tail)
    pc->waiting_tail->queue_next = r;
  else
    pc->waiting_head = r;
  pc->waiting_tail = r;
}
internal PoolReq *pool_waiting_pop(PoolConn *pc) {
  PoolReq *r = pc->waiting_head;
  if (r) {
    pc->waiting_head = r->queue_next;
    if (!pc->waiting_head) pc->waiting_tail = 0;
    r->queue_next = 0;
  }
  return r;
}
internal void pool_waiting_remove(PoolConn *pc, PoolReq *r) {
  PoolReq **pp = &pc->waiting_head, *prev = 0;
  while (*pp) {
    if (*pp == r) {
      *pp = r->queue_next;
      if (pc->waiting_tail == r) pc->waiting_tail = prev;
      r->queue_next = 0;
      return;
    }
    prev = *pp;
    pp = &(*pp)->queue_next;
  }
}

//- loop liveness: an idle pooled conn must not keep loop_run alive -----------
internal void pool_conn_ref(PoolConn *pc) {
  if (pc->proto == PoolProto_H2) {
    if (pc->h2_conn.tcp_inited) uv_ref((uv_handle_t *)&pc->h2_conn.tcp);
  } else {
    if (pc->h3_conn.udp_inited) uv_ref((uv_handle_t *)&pc->h3_conn.udp);
    if (pc->h3_conn.timer_inited) uv_ref((uv_handle_t *)&pc->h3_conn.timer);
  }
}
internal void pool_conn_unref(PoolConn *pc) {
  if (pc->proto == PoolProto_H2) {
    if (pc->h2_conn.tcp_inited) uv_unref((uv_handle_t *)&pc->h2_conn.tcp);
  } else {
    if (pc->h3_conn.udp_inited) uv_unref((uv_handle_t *)&pc->h3_conn.udp);
    if (pc->h3_conn.timer_inited) uv_unref((uv_handle_t *)&pc->h3_conn.timer);
  }
}

//- error delivery -----------------------------------------------------------
// Final teardown of a request: disarm its deadline timer (its memory outlives the
// arena, freed in its own close cb) then free the request's arena.
internal void pool_req_done(PoolReq *r) {
  req_timer_disarm(r->timeout);
  r->timeout = 0;
  arena_release(r->arena);
}
internal void pool_req_deliver_error(PoolReq *r, const char *err) {
  if (r->responded) return;
  r->responded = 1;
  Response resp;
  MemoryZeroStruct(&resp);
  resp.error = err;
  resp.final_url = r->url;
  client_cb_enter(r->client);
  if (r->cb) r->cb(r->user, &resp);
  client_cb_exit(r->client);
}
internal void pool_req_fail(PoolReq *r, const char *err) {
  pool_req_deliver_error(r, err);
  pool_req_done(r);
}

// A request whose connection broke before it got a response (stale idle reuse, a
// GOAWAY-refused stream, a mid-flight close): retry on a fresh connection if the
// budget allows, else deliver the error. Idempotent-safe because we only retry
// when no response bytes were delivered (responded==0).
internal void pool_req_retry_or_fail(PoolReq *r, const char *err) {
  if (r->retries_left > 0 && !r->responded) {
    r->retries_left--;
    r->pc = 0;
    r->h2_stream_id = 0;
    pool_acquire(r->client->pool, r->proto, r);  // broken conn is skipped
    return;
  }
  pool_req_deliver_error(r, err);
  pool_req_done(r);
}

//- pool bookkeeping ---------------------------------------------------------
internal void pool_sweep_cb(uv_timer_t *t);

internal void pool_arm_sweep(ConnPool *p) {
  if (!p->sweep_inited) {
    uv_timer_init(loop_uv(p->client->loop), &p->sweep);
    p->sweep.data = p;
    uv_unref((uv_handle_t *)&p->sweep);  // never keep the loop alive by itself
    p->sweep_inited = 1;
  }
  if (!uv_is_active((uv_handle_t *)&p->sweep))
    uv_timer_start(&p->sweep, pool_sweep_cb, POOL_SWEEP_INTERVAL_MS,
                   POOL_SWEEP_INTERVAL_MS);
}

internal void pool_remove_conn(ConnPool *p, PoolConn *pc) {
  for (int i = 0; i < p->count; ++i)
    if (p->conns[i] == pc) {
      p->conns[i] = p->conns[--p->count];
      break;
    }
  if (p->count == 0 && p->sweep_inited &&
      uv_is_active((uv_handle_t *)&p->sweep))
    uv_timer_stop(&p->sweep);
}

internal B32 pool_conn_has_capacity(PoolConn *pc) {
  if (pc->state != PoolConnState_Ready || pc->broken) return 0;
  if (pc->proto == PoolProto_H2) {
    if (!pc->h2 || h2_session_goaway_received(pc->h2)) return 0;
    return pc->inflight < h2_session_max_concurrent_streams(pc->h2);
  }
  return pc->h3c && pc->inflight < POOL_H3_MAX_CONCURRENT;  // send_buf-bounded
}

//- connection open / close --------------------------------------------------
internal PoolConn *pool_conn_open(ConnPool *p, PoolProto proto, PoolReq *r) {
  if (p->count >= POOL_MAX_CONNS) return 0;
  Arena *a = arena_alloc();
  PoolConn *pc = push_struct(a, PoolConn);
  pc->arena = a;
  pc->client = p->client;
  pc->pool = p;
  pc->proto = proto;
  pc->state = PoolConnState_Handshaking;
  U64 n = r->origin.size < sizeof pc->origin - 1 ? r->origin.size
                                                 : sizeof pc->origin - 1;
  MemoryCopy(pc->origin, r->origin.str, n);
  pc->origin[n] = 0;

  Client *c = p->client;
  if (proto == PoolProto_H2) {
    conn_init(&pc->h2_conn, c->loop, c->ctx.ctx, &c->profile->tls);
    conn_on_fully_closed(&pc->h2_conn, pool_h2_on_fully_closed, pc);
    conn_on_closed(&pc->h2_conn, pool_h2_on_closed, pc);
    conn_set_dns_cache(&pc->h2_conn, &c->dns_cache);
    if (c->proxy.type != ProxyType_None)  // pooled H2 also tunnels through it
      conn_set_proxy(&pc->h2_conn, &c->proxy, c->proxy_ctx.ctx, &c->proxy_tls);
  } else {
    quic_conn_init(&pc->h3_conn, c->loop, c->h3_ctx.ctx, &c->h3_profile->tls,
                   &c->h3_profile->h3);
    quic_on_fully_closed(&pc->h3_conn, pool_h3_on_fully_closed, pc);
    quic_on_closed(&pc->h3_conn, pool_h3_on_closed, pc);
    quic_on_recv_done(&pc->h3_conn, pool_h3_recv_done, pc);
    quic_set_dns_cache(&pc->h3_conn, &c->dns_cache);
    if (c->proxy.type == ProxyType_Socks5)  // pooled H3 also tunnels via SOCKS5 UDP
      quic_set_proxy(&pc->h3_conn, &c->proxy);
  }

  p->conns[p->count++] = pc;
  c->pool_stats.conns_created++;
  pool_arm_sweep(p);
  if (c->ech_enabled) {  // offer real ECH if the origin's config is cached
    EchConfigEntry *e = ech_cache_get(c, r->origin);
    if (e && e->config_len) {
      if (proto == PoolProto_H2)
        conn_set_ech(&pc->h2_conn, e->config, e->config_len);
      else
        quic_set_ech(&pc->h3_conn, e->config, e->config_len);
    }
  }
  if (c->resume_enabled) {  // offer a cached ticket + capture new ones
    void *rc = client_resume_ctx_make(c, a, r->origin);
    SSL_SESSION *sess = resume_cache_get(c, r->origin);
    if (proto == PoolProto_H2)
      conn_set_resume(&pc->h2_conn, sess, rc);
    else
      quic_set_resume(&pc->h3_conn, sess, rc);
  }
  if (proto == PoolProto_H2)
    conn_connect(&pc->h2_conn, push_str8_cstr(a, r->host), r->port,
                 pool_h2_on_ready, pc);
  else
    quic_conn_connect(&pc->h3_conn, push_str8_cstr(a, r->host), r->port,
                      pool_h3_on_ready, pc);
  return pc;
}

internal void pool_close_conn(PoolConn *pc) {
  if (pc->state == PoolConnState_Closing) return;
  pc->state = PoolConnState_Closing;
  if (pc->proto == PoolProto_H2)
    conn_close(&pc->h2_conn);  // -> pool_h2_on_fully_closed
  else
    quic_conn_close(&pc->h3_conn);  // -> pool_h3_on_fully_closed
}

internal void pool_h2_on_fully_closed(void *user) {
  PoolConn *pc = (PoolConn *)user;
  if (pc->h2) h2_session_release(pc->h2);
  conn_cleanup(&pc->h2_conn);
  pool_remove_conn(pc->pool, pc);
  arena_release(pc->arena);  // frees pc itself
}

//- request acquire / dispatch ----------------------------------------------
// Match a usable conn for (origin, proto). Prefer a Ready conn with stream
// capacity (reuse); else queue on a handshaking conn; else open a new conn if
// the origin is under max_conns_per_origin; else submit on any Ready conn
// (nghttp2 queues beyond the concurrency limit).
internal void pool_acquire(ConnPool *p, PoolProto proto, PoolReq *r) {
  Client *c = p->client;
  PoolConn *reusable = 0, *reusable_any = 0, *handshaking = 0;
  int origin_count = 0;
  for (int i = 0; i < p->count; ++i) {
    PoolConn *pc = p->conns[i];
    if (pc->proto != proto || pc->broken ||
        pc->state == PoolConnState_Closing)
      continue;
    if (!str8_match(r->origin, str8_cstring(pc->origin))) continue;
    origin_count++;
    if (pc->state == PoolConnState_Handshaking) {
      if (!handshaking) handshaking = pc;
    } else if (pc->state == PoolConnState_Ready) {
      if (!reusable_any) reusable_any = pc;
      if (!reusable && pool_conn_has_capacity(pc)) reusable = pc;
    }
  }
  if (reusable) {
    c->pool_stats.reuses++;
    pool_submit(reusable, r);
    return;
  }
  if (handshaking) {
    r->pc = handshaking;
    pool_waiting_push(handshaking, r);
    return;
  }
  if (origin_count < (int)c->max_conns_per_origin && p->count < POOL_MAX_CONNS) {
    PoolConn *pc = pool_conn_open(p, proto, r);
    if (!pc) {
      pool_req_fail(r, "pool: connection alloc failed");
      return;
    }
    r->pc = pc;
    pool_waiting_push(pc, r);
    return;
  }
  if (reusable_any) {  // at capacity, can't open more -> let nghttp2 queue it
    c->pool_stats.reuses++;
    pool_submit(reusable_any, r);
    return;
  }
  pool_req_fail(r, "pool: no connection available");
}

void pool_dispatch(Client *c, PoolProto proto, Method m, String8 url,
                   const Header *headers, U64 header_count, const U8 *body,
                   U64 body_len, ResponseFn cb, void *user, U64 deadline_ns) {
  Arena *a = arena_alloc();
  PoolReq *r = push_struct(a, PoolReq);
  r->arena = a;
  r->client = c;
  r->proto = proto;
  r->cb = cb;
  r->user = user;
  r->t_start_ns = uv_hrtime();
  r->deadline_ns = deadline_ns;
  r->method_enum = m;
  r->retries_left = POOL_MAX_RETRIES;
  r->url = push_str8_copy(a, url);

  ParsedUrl pu = url_parse(r->url);
  if (!pu.ok || !pu.https) {
    Response resp;
    MemoryZeroStruct(&resp);
    resp.error = "invalid or non-https URL";
    resp.final_url = r->url;
    client_cb_enter(c);
    if (cb) cb(user, &resp);
    client_cb_exit(c);
    arena_release(a);
    return;
  }
  r->scheme = pu.scheme;
  r->authority = pu.authority;
  r->path = pu.path;
  r->host = push_str8_copy(a, pu.host);
  r->port = pu.port;
  r->origin = origin_of(a, pu);

  r->caller_header_count = header_count;
  if (header_count) {
    r->caller_headers = push_array(a, Header, header_count);
    for (U64 i = 0; i < header_count; ++i) {
      r->caller_headers[i].name = push_str8_copy(a, headers[i].name);
      r->caller_headers[i].value = push_str8_copy(a, headers[i].value);
      r->caller_headers[i].flags = headers[i].flags;
    }
  }
  r->caller_body =
      body_len ? push_str8_copy(a, str8((U8 *)body, body_len)) : str8_zero();

  r->timeout = req_timer_arm(c->loop, deadline_ns, pool_req_timeout, r);
  c->pool_stats.requests++;
  pool_acquire(c->pool, proto, r);
}

//- H2 transport callbacks ---------------------------------------------------
internal void pool_h2_send(void *user, const U8 *data, U64 len) {
  PoolConn *pc = (PoolConn *)user;
  conn_send_plaintext(&pc->h2_conn, data, len);
}

internal void pool_submit(PoolConn *pc, PoolReq *r) {
  r->pc = pc;
  // Re-entrant submit (a user fired a new request from inside a response
  // callback, which runs inside this conn's transport recv): defer it onto the
  // waiting queue; the post-recv flush (pool_h2_drain / pool_h3_recv_done)
  // submits it once the recv unwinds, so we never call nghttp2_session_send /
  // ngtcp2 writev from inside their recv path.
  B32 in_recv = pc->proto == PoolProto_H2 ? pc->in_drain : pc->h3_conn.in_recv;
  if (in_recv) {
    pool_waiting_push(pc, r);
    return;
  }
  if (pc->proto == PoolProto_H2)
    pool_h2_submit(pc, r);
  else
    pool_h3_submit(pc, r);
}

// Submit + book-keep a request as a stream on a Ready conn (proto-common tail).
internal void pool_after_submit(PoolConn *pc, PoolReq *r) {
  if (pc->inflight == 0) {
    pool_conn_ref(pc);  // 0->1: keep the loop alive while busy
    pc->idle = 0;
  }
  pc->inflight++;
  pc->idle_since_ms = 0;
  pool_active_push(pc, r);
}

internal void pool_h2_submit(PoolConn *pc, PoolReq *r) {
  Client *c = pc->client;
  // Build the merged request headers (Chrome defaults + caller) once, per submit.
  r->body = build_request_headers(
      r->arena, c->profile->default_headers, c->profile->default_header_count,
      r->caller_headers, r->caller_header_count, r->caller_body.str,
      r->caller_body.size, c->override_default_headers, &r->req_headers);
  client_run_pre_hook(c, r->method_enum, r->url, &r->req_headers);
  S32 sid = h2_session_submit_request(
      pc->h2, method_str(r->method_enum), r->scheme, r->authority, r->path,
      r->req_headers.v, r->req_headers.count, r->body.str, r->body.size,
      pool_h2_on_response, r);
  if (sid < 0) {
    pool_req_fail(r, "h2 submit failed");
    return;
  }
  r->h2_stream_id = sid;
  pool_after_submit(pc, r);
}

// Submit queued requests while the conn has stream capacity. Called only outside
// the transport recv (post-drain / post-recv / on-ready), never re-entrantly.
internal void pool_flush_waiting(PoolConn *pc) {
  while (pc->waiting_head && pool_conn_has_capacity(pc))
    pool_submit(pc, pool_waiting_pop(pc));
}

// Server negotiated HTTP/1.1 on a pooled-H2 attempt: H1 is not pooled, so
// re-dispatch the queued requests through the legacy per-request path and drop
// this connection.
internal void pool_conn_fallback_legacy(PoolConn *pc) {
  PoolReq *r = pc->waiting_head;
  pc->waiting_head = pc->waiting_tail = 0;
  while (r) {
    PoolReq *next = r->queue_next;
    h2req_start(pc->client, r->method_enum, r->url, r->caller_headers,
                r->caller_header_count, r->caller_body.str, r->caller_body.size,
                r->cb, r->user, r->deadline_ns);
    pool_req_done(r);  // disarm the pooled timer; h2req_start armed its own
    r = next;
  }
  pc->broken = 1;
  pool_close_conn(pc);
}

internal void pool_h2_on_ready(void *user, B32 ok, const char *err) {
  PoolConn *pc = (PoolConn *)user;
  if (!ok) {
    pool_conn_fail_all(pc, err ? err : "connect failed");
    return;
  }
  if (!str8_match(conn_alpn(&pc->h2_conn), str8_lit("h2"))) {
    pool_conn_fallback_legacy(pc);
    return;
  }
  pc->h2 = h2_session_alloc(&pc->client->profile->h2, pool_h2_send, pc);
  if (!pc->h2 || !h2_session_start(pc->h2)) {
    pool_conn_fail_all(pc, "h2 session init failed");
    return;
  }
  conn_on_readable(&pc->h2_conn, pool_h2_drain, pc);
  pc->state = PoolConnState_Ready;
  pool_flush_waiting(pc);
  pool_h2_drain(pc);
}

// Build the unified Response from a completed exchange (transparent
// Content-Encoding decode, stripping the stale c-e/c-l headers) and hand it to
// the caller. Shared by H2 and H3.
internal void pool_deliver(PoolReq *r, B32 ok, const char *error, int status,
                           const Header *headers, U64 header_count,
                           const U8 *body, U64 body_len, String8 alpn) {
  Response out;
  MemoryZeroStruct(&out);
  out.ok = ok;
  out.error = error;
  out.status = status;
  out.headers = headers;
  out.header_count = header_count;
  out.body = body;
  out.body_len = body_len;
  out.alpn = alpn;
  if (r->pc) {
    out.resumed = r->proto == PoolProto_H2 ? conn_resumed(&r->pc->h2_conn)
                                           : quic_conn_resumed(&r->pc->h3_conn);
    if (r->proto == PoolProto_H2)
      conn_timing_ms(&r->pc->h2_conn, r->t_start_ns, &out.timing.dns_ms,
                     &out.timing.tcp_ms, &out.timing.tls_ms);
    else
      quic_conn_timing_ms(&r->pc->h3_conn, r->t_start_ns, &out.timing.dns_ms,
                          &out.timing.tcp_ms, &out.timing.tls_ms);
  }
  out.timing.total_ms = (uv_hrtime() - r->t_start_ns) / 1000000;
  out.final_url = r->url;
  response_decode_encoding(r->arena, &out, &r->resp_headers);
  client_run_post_hook(r->client, &out);
  client_cb_enter(r->client);
  if (r->cb) r->cb(r->user, &out);
  client_cb_exit(r->client);
}

internal void pool_h2_on_response(void *user, const H2Response *hr) {
  PoolReq *r = (PoolReq *)user;
  PoolConn *pc = r->pc;
  Client *c = r->client;
  if (r->responded) return;

  // This stream is closed: detach from the conn first (frees a slot).
  pool_active_remove(pc, r);
  if (pc->inflight > 0) pc->inflight--;

  // A reset/refused stream with no response (e.g. a GOAWAY refusing streams above
  // last-stream-id): retry on a fresh conn instead of erroring the caller.
  if (!hr->ok && hr->status == 0 && r->retries_left > 0) {
    pool_req_retry_or_fail(r, "h2 stream reset");
    return;
  }
  r->responded = 1;
  if (hr->headers) {
    String8 *as = header_list_get_ci(hr->headers, str8_lit("alt-svc"));
    if (as) client_note_alt_svc(c, r->origin, *as);
  }
  pool_deliver(r, hr->ok, 0, hr->status, hr->headers ? hr->headers->v : 0,
               hr->headers ? hr->headers->count : 0, hr->body, hr->body_len,
               str8_lit("h2"));
  pool_req_done(r);  // this stream is done -> disarm + free the request
  // Flushing waiters + idle bookkeeping happens after the drain loop returns
  // (pool_h2_drain), so we never re-enter nghttp2 from inside a recv callback.
}

internal void pool_conn_fail_all(PoolConn *pc, const char *err) {
  if (pc->state == PoolConnState_Closing) return;
  pc->broken = 1;
  pc->inflight = 0;  // detach all before retrying (retry must not see this conn)
  PoolReq *active = pc->active_head, *waiting = pc->waiting_head;
  pc->active_head = 0;
  pc->waiting_head = pc->waiting_tail = 0;
  pool_close_conn(pc);  // mark Closing so retries skip it
  for (PoolReq *r = active; r;) {
    PoolReq *next = r->active_next;
    r->active_next = 0;
    pool_req_retry_or_fail(r, err);
    r = next;
  }
  for (PoolReq *r = waiting; r;) {
    PoolReq *next = r->queue_next;
    r->queue_next = 0;
    pool_req_retry_or_fail(r, err);
    r = next;
  }
}

internal void pool_h2_on_closed(void *user, const char *e) {
  PoolConn *pc = (PoolConn *)user;
  // Skip only if we already started tearing down; a `broken` conn (GOAWAY) that
  // then closes still has in-flight requests to fail/retry.
  if (pc->state == PoolConnState_Closing) return;
  pool_conn_fail_all(pc, e ? e : "connection closed");
}

// inflight==0 -> mark idle + unref (don't hold the loop). broken -> re-route any
// queued reqs to a healthy conn and close once drained.
internal void pool_update_idle(PoolConn *pc) {
  if (pc->state == PoolConnState_Closing) return;
  if (pc->broken) {
    PoolReq *r = pc->waiting_head;
    pc->waiting_head = pc->waiting_tail = 0;
    while (r) {
      PoolReq *next = r->queue_next;
      r->queue_next = 0;
      r->pc = 0;
      pool_acquire(pc->pool, pc->proto, r);  // skips this broken conn
      r = next;
    }
    if (pc->inflight == 0) pool_close_conn(pc);
    return;
  }
  if (pc->inflight == 0 && pc->state == PoolConnState_Ready && !pc->idle) {
    pc->idle = 1;  // edge-triggered: set idle_since + unref once per idle period
    pc->idle_since_ms = uv_now(loop_uv(pc->client->loop));
    pool_conn_unref(pc);
  }
}

internal void pool_h2_drain(void *user) {
  PoolConn *pc = (PoolConn *)user;
  if (pc->state == PoolConnState_Closing) return;
  U8 buf[16384];
  pc->in_drain = 1;  // submits from response callbacks defer onto `waiting`
  for (;;) {
    int n = conn_read_plaintext(&pc->h2_conn, buf, sizeof buf);
    if (n <= 0) break;
    if (!pc->h2) break;
    S64 rv = h2_session_recv(pc->h2, buf, (U64)n);
    if (rv < 0) {
      pc->in_drain = 0;
      pool_conn_fail_all(pc, "h2 protocol error");
      return;
    }
    if (pc->state == PoolConnState_Closing || pc->broken) break;
  }
  pc->in_drain = 0;
  if (pc->h2 && h2_session_goaway_received(pc->h2)) pc->broken = 1;
  // Flush deferred/queued requests now that we're outside the recv callbacks.
  pool_flush_waiting(pc);
  pool_update_idle(pc);
}

//- H3 transport (per-conn QPACK + control/qpack uni streams; per-req bidi) ---
internal nghttp3_nv pool_h3_nv(String8 n, String8 v) {
  nghttp3_nv nv;
  nv.name = n.str;
  nv.namelen = n.size;
  nv.value = v.str;
  nv.valuelen = v.size;
  nv.flags = NGHTTP3_NV_FLAG_NONE;
  return nv;
}

internal PoolReq *pool_h3_find_stream(H3Conn *hc, S64 sid) {
  for (int i = 0; i < hc->stream_count; ++i)
    if (hc->streams[i]->h3_stream_id == sid) return hc->streams[i];
  return 0;
}
internal void pool_h3_remove_stream(H3Conn *hc, S64 sid) {
  for (int i = 0; i < hc->stream_count; ++i)
    if (hc->streams[i]->h3_stream_id == sid) {
      hc->streams[i] = hc->streams[--hc->stream_count];
      return;
    }
}

// Deadline reached for a pooled request: cancel ONLY this stream (siblings on the
// shared connection keep running), then free the request. Detach + reset the stream
// so a late frame can't deref the freed PoolReq. Runs in a timer callback (outside
// the transport recv), so submitting any freed-up waiters here is safe.
internal void pool_req_timeout(void *user) {
  PoolReq *r = (PoolReq *)user;
  if (r->responded) return;  // already delivered; freed on its own path
  PoolConn *pc = r->pc;
  pool_req_deliver_error(r, "timeout");
  if (pc) {
    B32 active = 0;  // submitted (has a stream) vs still queued (waiting)?
    for (PoolReq *a = pc->active_head; a; a = a->active_next)
      if (a == r) {
        active = 1;
        break;
      }
    if (active) {
      if (r->proto == PoolProto_H2) {
        if (pc->h2) h2_session_cancel_stream(pc->h2, r->h2_stream_id);
      } else {
        quic_reset_stream(&pc->h3_conn, r->h3_stream_id);
        if (pc->h3c) pool_h3_remove_stream(pc->h3c, r->h3_stream_id);
      }
      pool_active_remove(pc, r);
      if (pc->inflight > 0) pc->inflight--;
    } else {
      pool_waiting_remove(pc, r);  // queued, no stream yet -> just unlink
    }
  }
  pool_req_done(r);
  if (pc && pc->state != PoolConnState_Closing) {  // a slot freed -> progress others
    pool_flush_waiting(pc);
    pool_update_idle(pc);
  }
}

internal void pool_h3_on_ready(void *user, B32 ok, const char *err) {
  PoolConn *pc = (PoolConn *)user;
  if (!ok) {
    pool_conn_fail_all(pc, err ? err : "connect failed");
    return;
  }
  if (!str8_match(quic_conn_alpn(&pc->h3_conn), str8_lit("h3"))) {
    pool_conn_fail_all(pc, "pool: server did not negotiate h3");
    return;
  }
  H3Conn *hc = push_struct(pc->arena, H3Conn);
  hc->prof = &pc->client->h3_profile->h3;
  hc->mem = nghttp3_mem_default();
  hc->ctrl_id = hc->qenc_id = hc->qdec_id = -1;
  if (nghttp3_qpack_encoder_new(&hc->qenc, 0, hc->mem) != 0 ||  // static only
      nghttp3_qpack_decoder_new(&hc->qdec, 65536, 100, hc->mem) != 0) {
    if (hc->qenc) nghttp3_qpack_encoder_del(hc->qenc);
    pool_conn_fail_all(pc, "h3 qpack init failed");
    return;
  }
  pc->h3c = hc;
  quic_on_stream_data(&pc->h3_conn, pool_h3_on_stream_data, pc);
  quic_on_stream_close(&pc->h3_conn, pool_h3_on_stream_close, pc);
  pc->state = PoolConnState_Ready;
  // on_ready fires inside ngtcp2 read_pkt (in_recv) -> let pool_h3_recv_done,
  // which runs right after read_pkt, flush the waiting queue. Only flush here if
  // somehow outside a recv.
  if (!pc->h3_conn.in_recv) pool_flush_waiting(pc);
}

internal void pool_h3_submit(PoolConn *pc, PoolReq *r) {
  Client *c = pc->client;
  H3Conn *hc = pc->h3c;
  QuicConnection *qc = &pc->h3_conn;
  String8 method = method_str(r->method_enum);
  r->body = build_request_headers(
      r->arena, c->h3_profile->default_headers,
      c->h3_profile->default_header_count, r->caller_headers,
      r->caller_header_count, r->caller_body.str, r->caller_body.size,
      c->override_default_headers, &r->req_headers);
  client_run_pre_hook(c, r->method_enum, r->url, &r->req_headers);

  if (quic_open_bidi_stream(qc, &r->h3_stream_id) != 0) {
    pool_req_retry_or_fail(r, "h3 open stream failed");
    return;
  }
  u8buf_init(&r->h3_in, r->arena, 0);

  // Per-connection control + QPACK uni streams: open once, with the first
  // request's PRIORITY_UPDATE in the control stream. Later requests send a
  // standalone PRIORITY_UPDATE on the open control stream (own PRIORITY_UPDATE
  // each -> byte-exact fingerprint surface per request).
  if (!hc->control_opened) {
    if (quic_open_uni_stream(qc, &hc->ctrl_id) != 0 ||
        quic_open_uni_stream(qc, &hc->qenc_id) != 0 ||
        quic_open_uni_stream(qc, &hc->qdec_id) != 0) {
      pool_req_retry_or_fail(r, "h3 open uni failed");
      return;
    }
    String8 ctrl = build_h3_control_stream(r->arena, hc->prof, r->h3_stream_id);
    quic_stream_send(qc, hc->ctrl_id, ctrl.str, ctrl.size, 0);
    U8 enc_type = 0x02, dec_type = 0x03;
    quic_stream_send(qc, hc->qenc_id, &enc_type, 1, 0);
    quic_stream_send(qc, hc->qdec_id, &dec_type, 1, 0);
    hc->control_opened = 1;
  } else if (hc->prof->send_priority_update) {
    String8 pu = build_h3_priority_update(r->arena, r->h3_stream_id);
    quic_stream_send(qc, hc->ctrl_id, pu.str, pu.size, 0);
  }

  // QPACK-encode (shared static encoder) -> HEADERS frame (+ optional DATA).
  Temp scratch = scratch_begin(&r->arena, 1);
  U64 nva_cap = hc->prof->pseudo_count + r->req_headers.count;
  nghttp3_nv *nva = push_array_no_zero(scratch.arena, nghttp3_nv, nva_cap);
  U64 nvlen = 0;
  for (U8 i = 0; i < hc->prof->pseudo_count; ++i) {
    switch (hc->prof->pseudo_order[i]) {
      case Pseudo_Method:
        nva[nvlen++] = pool_h3_nv(str8_lit(":method"), method);
        break;
      case Pseudo_Authority:
        nva[nvlen++] = pool_h3_nv(str8_lit(":authority"), r->authority);
        break;
      case Pseudo_Scheme:
        nva[nvlen++] = pool_h3_nv(str8_lit(":scheme"), str8_lit("https"));
        break;
      case Pseudo_Path:
        nva[nvlen++] = pool_h3_nv(str8_lit(":path"), r->path);
        break;
    }
  }
  for (U64 i = 0; i < r->req_headers.count; ++i)
    nva[nvlen++] =
        pool_h3_nv(r->req_headers.v[i].name, r->req_headers.v[i].value);

  nghttp3_buf pbuf, rbuf, ebuf;
  U8 raw_pbuf[16];
  pbuf.begin = pbuf.pos = pbuf.last = raw_pbuf;
  pbuf.end = raw_pbuf + sizeof raw_pbuf;
  nghttp3_buf_init(&rbuf);
  nghttp3_buf_init(&ebuf);
  int rv = nghttp3_qpack_encoder_encode(hc->qenc, &pbuf, &rbuf, &ebuf,
                                        r->h3_stream_id, nva, nvlen);
  if (rv != 0) {
    nghttp3_buf_free(&rbuf, hc->mem);
    nghttp3_buf_free(&ebuf, hc->mem);
    scratch_end(scratch);
    pool_req_retry_or_fail(r, "h3 qpack encode failed");
    return;
  }
  U64 pl = nghttp3_buf_len(&pbuf), rl = nghttp3_buf_len(&rbuf);
  U8Buf frame;
  u8buf_init(&frame, scratch.arena, pl + rl + 16);
  quic_varint_put(&frame, 0x01);  // HEADERS frame
  quic_varint_put(&frame, pl + rl);
  u8buf_append(&frame, pbuf.pos, pl);
  u8buf_append(&frame, rbuf.pos, rl);
  nghttp3_buf_free(&rbuf, hc->mem);
  nghttp3_buf_free(&ebuf, hc->mem);
  B32 has_body = r->body.size != 0;
  quic_stream_send(qc, r->h3_stream_id, frame.v, frame.len, !has_body);
  if (has_body) {
    U8Buf dframe;
    u8buf_init(&dframe, scratch.arena, r->body.size + 16);
    quic_varint_put(&dframe, 0x00);  // DATA frame
    quic_varint_put(&dframe, r->body.size);
    u8buf_append(&dframe, r->body.str, r->body.size);
    quic_stream_send(qc, r->h3_stream_id, dframe.v, dframe.len, 1);
  }
  scratch_end(scratch);

  if (hc->stream_count < H3_MAX_STREAMS) hc->streams[hc->stream_count++] = r;
  pool_after_submit(pc, r);
}

internal void pool_h3_finish(PoolConn *pc, PoolReq *r) {
  H3Conn *hc = pc->h3c;
  if (r->responded) return;
  pool_h3_remove_stream(hc, r->h3_stream_id);
  pool_active_remove(pc, r);
  if (pc->inflight > 0) pc->inflight--;

  // Parse frames: DATA payloads compacted to the front of h3_in in place (single
  // contiguous body, no extra buffer); HEADERS decoded via the shared QPACK
  // decoder + a fresh per-stream context (copy of h3_session.c's finish/decode).
  HeaderList h3_headers;
  header_list_init(&h3_headers, r->arena);
  int status = 0;
  U8 *base = r->h3_in.v;
  U64 body_len = 0;
  const U8 *p = r->h3_in.v;
  U64 rem = r->h3_in.len;
  while (rem > 0) {
    U64 n = 0;
    U64 type = quic_varint_get(p, rem, &n);
    if (n == 0) break;
    p += n;
    rem -= n;
    U64 flen = quic_varint_get(p, rem, &n);
    if (n == 0) break;
    p += n;
    rem -= n;
    U64 plen = flen <= rem ? flen : rem;
    const U8 *payload = p;
    p += plen;
    rem -= plen;
    if (type == 0x01) {  // HEADERS
      nghttp3_qpack_stream_context *sctx = 0;
      nghttp3_qpack_stream_context_new(&sctx, r->h3_stream_id, hc->mem);
      const U8 *hp = payload;
      U64 hrem = plen;
      for (;;) {
        nghttp3_qpack_nv nv;
        uint8_t flags = 0;
        nghttp3_ssize dn = nghttp3_qpack_decoder_read_request(
            hc->qdec, sctx, &nv, &flags, hp, hrem, 1);
        if (dn < 0) break;
        hp += dn;
        hrem -= (U64)dn;
        if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
          nghttp3_vec nb = nghttp3_rcbuf_get_buf(nv.name);
          nghttp3_vec vb = nghttp3_rcbuf_get_buf(nv.value);
          String8 name = str8(nb.base, nb.len);
          String8 val = str8(vb.base, vb.len);
          if (str8_match(name, str8_lit(":status")))
            status = (int)str8_to_u64(val);
          else
            header_list_push(&h3_headers, push_str8_copy(r->arena, name),
                             push_str8_copy(r->arena, val), 0);
          nghttp3_rcbuf_decref(nv.name);
          nghttp3_rcbuf_decref(nv.value);
        }
        if (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) break;
        if (dn == 0) break;
      }
      nghttp3_qpack_stream_context_del(sctx);
    } else if (type == 0x00) {  // DATA
      if (base + body_len != payload) MemoryMove(base + body_len, payload, plen);
      body_len += plen;
    }
  }

  // No response headers (stream reset / aborted) -> retry on a fresh conn.
  if (status == 0 && r->retries_left > 0) {
    pool_req_retry_or_fail(r, "h3 stream reset");
    return;
  }
  r->responded = 1;
  B32 ok = status != 0;
  pool_deliver(r, ok, ok ? 0 : "no response headers", status, h3_headers.v,
               h3_headers.count, base, body_len, str8_lit("h3"));
  pool_req_done(r);
}

internal void pool_h3_on_stream_data(void *user, S64 sid, const U8 *data,
                                     U64 len, B32 fin) {
  PoolConn *pc = (PoolConn *)user;
  H3Conn *hc = pc->h3c;
  if (!hc) return;
  PoolReq *r = pool_h3_find_stream(hc, sid);
  if (r) {
    u8buf_append(&r->h3_in, data, len);
    if (fin) {
      r->h3_fin = 1;
      pool_h3_finish(pc, r);
    }
    return;
  }
  // Server-initiated uni stream: first varint is the type; feed the server QPACK
  // encoder stream (0x02) into the shared decoder.
  PoolH3Uni *u = 0;
  for (int i = 0; i < hc->uni_count; ++i)
    if (hc->uni[i].id == sid) {
      u = &hc->uni[i];
      break;
    }
  if (!u && hc->uni_count < (int)ArrayCount(hc->uni)) {
    u = &hc->uni[hc->uni_count++];
    u->id = sid;
    u->type_read = 0;
    u->type = 0;
  }
  if (!u) return;
  const U8 *p = data;
  U64 rem = len;
  if (!u->type_read) {
    if (rem == 0) return;
    U64 n = 0;
    u->type = quic_varint_get(p, rem, &n);
    if (n == 0) return;
    p += n;
    rem -= n;
    u->type_read = 1;
  }
  if (u->type == 0x02 && rem)
    nghttp3_qpack_decoder_read_encoder(hc->qdec, p, rem);
}

internal void pool_h3_on_stream_close(void *user, S64 sid) {
  PoolConn *pc = (PoolConn *)user;
  H3Conn *hc = pc->h3c;
  if (!hc) return;
  PoolReq *r = pool_h3_find_stream(hc, sid);
  if (r && !r->h3_fin) {
    r->h3_fin = 1;
    pool_h3_finish(pc, r);
  }
}

// Post-recv hook (outside ngtcp2 read_pkt): submit requests deferred by response
// callbacks, then run idle bookkeeping.
internal void pool_h3_recv_done(void *user) {
  PoolConn *pc = (PoolConn *)user;
  pool_flush_waiting(pc);
  pool_update_idle(pc);
}

internal void pool_h3_on_closed(void *user, const char *e) {
  PoolConn *pc = (PoolConn *)user;
  if (pc->state == PoolConnState_Closing) return;
  pool_conn_fail_all(pc, e ? e : "connection closed");
}

internal void pool_h3_on_fully_closed(void *user) {
  PoolConn *pc = (PoolConn *)user;
  if (pc->h3c) {
    if (pc->h3c->qenc) nghttp3_qpack_encoder_del(pc->h3c->qenc);
    if (pc->h3c->qdec) nghttp3_qpack_decoder_del(pc->h3c->qdec);
  }
  quic_conn_cleanup(&pc->h3_conn);
  pool_remove_conn(pc->pool, pc);
  arena_release(pc->arena);  // frees pc itself
}

//- sweep --------------------------------------------------------------------
internal void pool_sweep_cb(uv_timer_t *t) {
  ConnPool *p = (ConnPool *)t->data;
  U64 now = uv_now(loop_uv(p->client->loop));
  U64 idle_to = p->client->pool_idle_timeout_ms ? p->client->pool_idle_timeout_ms
                                                : POOL_DEFAULT_IDLE_MS;
  for (int i = 0; i < p->count; ++i) {  // close is async; no removal mid-loop
    PoolConn *pc = p->conns[i];
    if (pc->state == PoolConnState_Closing) continue;
    if (pc->broken && pc->inflight == 0) {
      pool_close_conn(pc);
    } else if (pc->state == PoolConnState_Ready && pc->inflight == 0 &&
               now - pc->idle_since_ms >= idle_to) {
      pool_close_conn(pc);
    }
  }
}

//- lifecycle ----------------------------------------------------------------
ConnPool *pool_alloc(Client *c) {
  Arena *a = arena_alloc();
  ConnPool *p = push_struct(a, ConnPool);
  p->arena = a;
  p->client = c;
  return p;
}

void pool_drain(ConnPool *p) {
  for (int i = p->count - 1; i >= 0; --i) pool_close_conn(p->conns[i]);
  if (p->sweep_inited && !uv_is_closing((uv_handle_t *)&p->sweep)) {
    uv_timer_stop(&p->sweep);
    uv_close((uv_handle_t *)&p->sweep, 0);
    p->sweep_inited = 0;
  }
}

void pool_free(ConnPool *p) { arena_release(p->arena); }

// Runtime proxy switch: every existing conn was established through the OLD proxy,
// so stop reusing them. Mark all broken (pool_acquire then skips them, so new
// requests open fresh conns through the new proxy) in one pass, then close the idle
// ones; in-flight conns stay broken and close when they drain (the sweep handles
// broken+idle). The pool + sweep timer stay live, unlike pool_drain.
void pool_evict_all(ConnPool *p) {
  for (int i = 0; i < p->count; ++i)
    if (p->conns[i]->state != PoolConnState_Closing) p->conns[i]->broken = 1;
  for (int i = p->count - 1; i >= 0; --i)
    if (p->conns[i]->broken && p->conns[i]->inflight == 0)
      pool_close_conn(p->conns[i]);
}
