#include "h2/h2.h"

#include <nghttp2/nghttp2.h>

typedef struct Req Req;
struct Req {
  H2Session *sess;
  S32 stream_id;
  int status;
  HeaderList headers;
  U8 *body;  // growable response-body buffer (arena)
  U64 body_len;
  U64 body_cap;
  H2RespFn cb;
  void *user;
};

struct H2Session {
  Arena *arena;
  const Http2Profile *prof;
  H2SendFn send_fn;
  void *send_user;
  nghttp2_session *session;
  int open_streams;     // concurrent in-flight streams (multiplexing)
  B32 goaway_received;  // server asked us to stop opening new streams
};

// Request body source for nghttp2's DATA-frame read callback (arena-owned).
typedef struct BodySource BodySource;
struct BodySource {
  const U8 *p;
  U64 len;
  U64 off;
};

internal nghttp2_nv make_nv(String8 name, String8 value) {
  nghttp2_nv nv;
  nv.name = (U8 *)name.str;
  nv.value = (U8 *)value.str;
  nv.namelen = name.size;
  nv.valuelen = value.size;
  nv.flags = NGHTTP2_NV_FLAG_NONE;
  return nv;
}

internal void body_append(H2Session *s, Req *req, const U8 *data, U64 len) {
  if (len == 0) return;
  if (req->body_len + len > req->body_cap) {
    U64 newcap = req->body_cap ? req->body_cap * 2 : KB(4);
    while (newcap < req->body_len + len) newcap *= 2;
    U8 *nb = push_array_no_zero(s->arena, U8, newcap);
    if (req->body_len) MemoryCopy(nb, req->body, req->body_len);
    req->body = nb;
    req->body_cap = newcap;
  }
  MemoryCopy(req->body + req->body_len, data, len);
  req->body_len += len;
}

//- nghttp2 callbacks --------------------------------------------------------

internal nghttp2_ssize send_cb(nghttp2_session *session, const U8 *data,
                               size_t length, int flags, void *user) {
  (void)session;
  (void)flags;
  H2Session *s = (H2Session *)user;
  s->send_fn(s->send_user, data, length);
  return (nghttp2_ssize)length;
}

internal int on_header_cb(nghttp2_session *session, const nghttp2_frame *frame,
                          const U8 *name, size_t namelen, const U8 *value,
                          size_t valuelen, U8 flags, void *user) {
  (void)flags;
  (void)user;
  Req *req =
      (Req *)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if (!req) return 0;
  String8 n = str8((U8 *)name, namelen);
  String8 v = str8((U8 *)value, valuelen);
  if (str8_match(n, str8_lit(":status"))) {
    req->status = (int)str8_to_u64(v);
  } else {
    Arena *a = req->sess->arena;
    header_list_push(&req->headers, push_str8_copy(a, n), push_str8_copy(a, v),
                     0);
  }
  return 0;
}

internal int on_data_cb(nghttp2_session *session, U8 flags, S32 stream_id,
                        const U8 *data, size_t len, void *user) {
  (void)flags;
  H2Session *s = (H2Session *)user;
  Req *req = (Req *)nghttp2_session_get_stream_user_data(session, stream_id);
  if (req) body_append(s, req, data, len);
  // With no_auto_window_update (the preface WINDOW_UPDATE is fingerprint
  // bytes), nghttp2 replenishes recv windows only when we report bytes
  // consumed. We consume on delivery, so nghttp2 emits stream + connection
  // WINDOW_UPDATEs (flushed after the recv loop) exactly like a browser;
  // without this, DATA stalls for good once a stream window (profile
  // INITIAL_WINDOW_SIZE) or the connection window (preface increment) drains.
  // Stream-level consume can fail for an already-reset stream — the bytes
  // still count against the connection window, which is the call that matters.
  nghttp2_session_consume_connection(session, len);
  nghttp2_session_consume_stream(session, stream_id, len);
  return 0;
}

internal int on_stream_close_cb(nghttp2_session *session, S32 stream_id,
                                U32 error_code, void *user) {
  H2Session *s = (H2Session *)user;
  Req *req = (Req *)nghttp2_session_get_stream_user_data(session, stream_id);
  if (!req) return 0;
  if (s->open_streams > 0) s->open_streams -= 1;

  H2Response resp;
  MemoryZeroStruct(&resp);
  resp.stream_id = stream_id;
  resp.status = req->status;
  resp.headers = &req->headers;
  resp.body = req->body;
  resp.body_len = req->body_len;
  resp.ok = (error_code == NGHTTP2_NO_ERROR);
  if (req->cb) req->cb(req->user, &resp);
  return 0;  // Req is arena-owned; freed in bulk on h2_session_release
}

// Note a received GOAWAY so the connection pool stops opening new streams on a
// draining connection (already-open streams still complete via
// on_stream_close).
internal int on_frame_recv_cb(nghttp2_session *session,
                              const nghttp2_frame *frame, void *user) {
  (void)session;
  H2Session *s = (H2Session *)user;
  if (frame->hd.type == NGHTTP2_GOAWAY) s->goaway_received = 1;
  return 0;
}

internal nghttp2_ssize body_read_cb(nghttp2_session *session, S32 stream_id,
                                    U8 *buf, size_t length, U32 *data_flags,
                                    nghttp2_data_source *source, void *user) {
  (void)session;
  (void)stream_id;
  (void)user;
  BodySource *bs = (BodySource *)source->ptr;
  U64 remain = bs->len - bs->off;
  U64 n = remain < length ? remain : length;
  if (n) MemoryCopy(buf, bs->p + bs->off, n);
  bs->off += n;
  if (bs->off >= bs->len) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  return (nghttp2_ssize)n;
}

//- lifetime -----------------------------------------------------------------

H2Session *h2_session_alloc(const Http2Profile *prof, H2SendFn send_fn,
                            void *send_user) {
  Arena *arena = arena_alloc();
  H2Session *s = push_struct(arena, H2Session);
  s->arena = arena;
  s->prof = prof;
  s->send_fn = send_fn;
  s->send_user = send_user;

  nghttp2_option *opt = 0;
  nghttp2_option_new(&opt);
  // We control flow-control windows explicitly (fingerprint-relevant).
  nghttp2_option_set_no_auto_window_update(opt, 1);

  nghttp2_session_callbacks *cbs = 0;
  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_send_callback2(cbs, send_cb);
  nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_cb);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_cb);
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs,
                                                         on_stream_close_cb);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv_cb);
  nghttp2_session_client_new2(&s->session, cbs, s, opt);
  nghttp2_session_callbacks_del(cbs);
  nghttp2_option_del(opt);
  return s;
}

void h2_session_release(H2Session *s) {
  if (!s) return;
  if (s->session) nghttp2_session_del(s->session);
  arena_release(s->arena);  // frees the struct + all reqs/headers/bodies
}

//- preface / io -------------------------------------------------------------

B32 h2_session_start(H2Session *s) {
  if (!s->session) return 0;
  Temp scr = scratch_begin(0, 0);
  nghttp2_settings_entry *iv = push_array_no_zero(
      scr.arena, nghttp2_settings_entry, s->prof->settings_count);
  for (U8 i = 0; i < s->prof->settings_count; ++i) {
    iv[i].settings_id = s->prof->settings[i].id;
    iv[i].value = s->prof->settings[i].value;
  }
  B32 ok = nghttp2_submit_settings(s->session, NGHTTP2_FLAG_NONE, iv,
                                   s->prof->settings_count) == 0;
  scratch_end(scr);
  if (!ok) return 0;
  if (s->prof->connection_window_increment) {
    if (nghttp2_submit_window_update(
            s->session, NGHTTP2_FLAG_NONE, 0,
            (S32)s->prof->connection_window_increment) != 0)
      return 0;
  }
  return h2_session_flush(s);
}

S64 h2_session_recv(H2Session *s, const U8 *data, U64 len) {
  if (!s->session) return -1;
  nghttp2_ssize n = nghttp2_session_mem_recv2(s->session, data, len);
  if (n < 0) return n;
  h2_session_flush(s);
  return (S64)n;
}

B32 h2_session_flush(H2Session *s) {
  if (!s->session) return 0;
  return nghttp2_session_send(s->session) == 0;
}

S32 h2_session_submit_request(H2Session *s, String8 method, String8 scheme,
                              String8 authority, String8 path,
                              const Header *headers, U64 header_count,
                              const U8 *body, U64 body_len, H2RespFn cb,
                              void *user) {
  if (!s->session) return -1;

  // The nv array is transient (nghttp2 deep-copies name/value during submit).
  // A Cookie header splits into one field per crumb (Chrome's H2 framing), so
  // size for the post-split field count.
  Temp scr = scratch_begin(0, 0);
  U64 field_count = 0;
  for (U64 i = 0; i < header_count; ++i)
    field_count += str8_match_ci(headers[i].name, str8_lit("cookie"))
                       ? cookie_crumbs(headers[i].value, 0, 0)
                       : 1;
  nghttp2_nv *nva = push_array_no_zero(scr.arena, nghttp2_nv,
                                       s->prof->pseudo_count + field_count);
  U64 n = 0;
  for (U8 i = 0; i < s->prof->pseudo_count; ++i) {
    switch (s->prof->pseudo_order[i]) {
      case Pseudo_Method:
        nva[n++] = make_nv(str8_lit(":method"), method);
        break;
      case Pseudo_Scheme:
        nva[n++] = make_nv(str8_lit(":scheme"), scheme);
        break;
      case Pseudo_Authority:
        nva[n++] = make_nv(str8_lit(":authority"), authority);
        break;
      case Pseudo_Path:
        nva[n++] = make_nv(str8_lit(":path"), path);
        break;
    }
  }
  for (U64 i = 0; i < header_count; ++i) {
    if (str8_match_ci(headers[i].name, str8_lit("cookie"))) {
      U64 cc = cookie_crumbs(headers[i].value, 0, 0);
      String8 *crumbs = push_array_no_zero(scr.arena, String8, cc ? cc : 1);
      cookie_crumbs(headers[i].value, crumbs, cc);
      for (U64 k = 0; k < cc; ++k)
        nva[n++] = make_nv(headers[i].name, crumbs[k]);
    } else {
      nva[n++] = make_nv(headers[i].name, headers[i].value);
    }
  }

  nghttp2_priority_spec pri;
  if (s->prof->use_priority)
    nghttp2_priority_spec_init(&pri, (S32)s->prof->priority_dep_stream,
                               s->prof->priority_weight,
                               s->prof->priority_exclusive ? 1 : 0);

  Req *req = push_struct(s->arena, Req);
  req->sess = s;
  header_list_init(&req->headers, s->arena);
  req->cb = cb;
  req->user = user;

  nghttp2_data_provider2 prd;
  nghttp2_data_provider2 *prdp = 0;
  if (body_len) {
    U8 *copy = push_array_no_zero(s->arena, U8, body_len);
    MemoryCopy(copy, body, body_len);
    BodySource *bs = push_struct(s->arena, BodySource);
    bs->p = copy;
    bs->len = body_len;
    bs->off = 0;
    prd.source.ptr = bs;
    prd.read_callback = body_read_cb;
    prdp = &prd;
  }

  S32 sid = nghttp2_submit_request2(
      s->session, s->prof->use_priority ? &pri : 0, nva, n, prdp, req);
  scratch_end(scr);
  if (sid < 0) return sid;
  req->stream_id = sid;
  s->open_streams += 1;
  h2_session_flush(s);
  return sid;
}

void h2_session_cancel_stream(H2Session *s, S32 stream_id) {
  if (!s->session) return;
  // Null the stream user data first so on_stream_close_cb returns early (it
  // must not invoke the response callback for an aborted, now-freed request).
  // The close callback then won't decrement open_streams either, so do it here.
  nghttp2_session_set_stream_user_data(s->session, stream_id, 0);
  nghttp2_submit_rst_stream(s->session, NGHTTP2_FLAG_NONE, stream_id,
                            NGHTTP2_CANCEL);
  if (s->open_streams > 0) s->open_streams -= 1;
  h2_session_flush(s);  // push the RST_STREAM out
}

B32 h2_session_want_write(H2Session *s) {
  return s->session && nghttp2_session_want_write(s->session);
}
B32 h2_session_want_read(H2Session *s) {
  return s->session && nghttp2_session_want_read(s->session);
}
B32 h2_session_idle(H2Session *s) {
  return s->open_streams == 0 && !h2_session_want_write(s);
}

// The peer's advertised SETTINGS_MAX_CONCURRENT_STREAMS (nghttp2 returns a
// large default until the server's SETTINGS arrive). The pool gates new streams
// on it.
U32 h2_session_max_concurrent_streams(H2Session *s) {
  if (!s->session) return 0;
  return nghttp2_session_get_remote_settings(
      s->session, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
}

B32 h2_session_goaway_received(H2Session *s) { return s->goaway_received; }
