// Offline pooling tests. (1) H2 multiplexing: drive one H2Session with three
// concurrent streams against an in-process nghttp2 server and assert every
// response routes to the right per-stream callback and the session goes idle —
// this is the foundation the connection pool rides on, and it proves deleting
// the old single `open_req` pointer didn't break per-stream routing. (2) Pool
// lifecycle smoke: enable pooling on a Client and drain/free the (empty) pool.
#include <nghttp2/nghttp2.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "h2/h2.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                  \
  Statement(g_checks += 1; if (!(c)) {                            \
    g_fails += 1;                                                 \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

//- in-memory byte channels between the client and server sessions
typedef struct Bytes Bytes;
struct Bytes {
  U8 d[65536];
  U64 len;
};
global Bytes g_c2s;  // client -> server
global Bytes g_s2c;  // server -> client

internal void bytes_put(Bytes *b, const U8 *d, U64 n) {
  if (b->len + n <= sizeof b->d) {
    MemoryCopy(b->d + b->len, d, n);
    b->len += n;
  }
}
internal void cli_sink(void *user, const U8 *d, U64 n) {
  (void)user;
  bytes_put(&g_c2s, d, n);
}
internal nghttp2_ssize srv_send(nghttp2_session *s, const U8 *d, size_t n, int f,
                                void *u) {
  (void)s;
  (void)f;
  (void)u;
  bytes_put(&g_s2c, d, n);
  return (nghttp2_ssize)n;
}

//- server: respond to each completed GET with a stream-specific status + body
internal nghttp2_ssize srv_body(nghttp2_session *s, S32 sid, U8 *buf,
                                size_t len, U32 *flags,
                                nghttp2_data_source *src, void *u) {
  (void)s;
  (void)sid;
  (void)src;
  (void)u;
  const char *b = "hello";
  size_t n = 5 < len ? 5 : len;
  MemoryCopy(buf, b, n);
  *flags |= NGHTTP2_DATA_FLAG_EOF;
  return (nghttp2_ssize)n;
}
internal int srv_frame(nghttp2_session *s, const nghttp2_frame *f, void *u) {
  (void)u;
  if (f->hd.type == NGHTTP2_HEADERS &&
      (f->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
    S32 sid = f->hd.stream_id;
    char st[16];
    snprintf(st, sizeof st, "%d", 200 + (sid - 1) / 2);  // 1->200, 3->201, 5->202
    nghttp2_nv nv;
    nv.name = (U8 *)":status";
    nv.namelen = 7;
    nv.value = (U8 *)st;
    nv.valuelen = strlen(st);
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    nghttp2_data_provider2 prd;
    prd.source.ptr = 0;
    prd.read_callback = srv_body;
    nghttp2_submit_response2(s, sid, &nv, 1, &prd);
  }
  return 0;
}

//- client per-request result
typedef struct Result Result;
struct Result {
  B32 got;
  S32 stream_id;
  int status;
  U64 body_len;
};
internal void cli_resp(void *user, const H2Response *r) {
  Result *res = (Result *)user;
  res->got = 1;
  res->stream_id = r->stream_id;
  res->status = r->status;
  res->body_len = r->body_len;
}

internal void test_h2_multiplex(void) {
  g_c2s.len = g_s2c.len = 0;
  H2Session *cli =
      h2_session_alloc(&profile_chrome148()->h2, cli_sink, 0);
  CHECK(cli != 0);
  h2_session_start(cli);

  nghttp2_session_callbacks *cbs = 0;
  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_send_callback2(cbs, srv_send);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, srv_frame);
  nghttp2_session *srv = 0;
  nghttp2_session_server_new(&srv, cbs, 0);
  nghttp2_session_callbacks_del(cbs);
  nghttp2_submit_settings(srv, NGHTTP2_FLAG_NONE, 0, 0);

  // Three concurrent streams on the one session (the multiplexing pooling needs).
  Result results[3];
  MemoryZeroArray(results);
  S32 ids[3];
  String8 paths[3] = {str8_lit("/a"), str8_lit("/b"), str8_lit("/c")};
  for (int i = 0; i < 3; ++i)
    ids[i] = h2_session_submit_request(cli, str8_lit("GET"), str8_lit("https"),
                                       str8_lit("example.com"), paths[i], 0, 0,
                                       0, 0, cli_resp, &results[i]);
  CHECK(ids[0] == 1 && ids[1] == 3 && ids[2] == 5);  // distinct odd stream ids

  // Pump both directions until quiescent.
  for (int round = 0; round < 16; ++round) {
    B32 progress = 0;
    if (g_c2s.len) {
      nghttp2_session_mem_recv2(srv, g_c2s.d, g_c2s.len);
      g_c2s.len = 0;
      nghttp2_session_send(srv);
      progress = 1;
    }
    if (g_s2c.len) {
      h2_session_recv(cli, g_s2c.d, g_s2c.len);  // flushes client output too
      g_s2c.len = 0;
      progress = 1;
    }
    if (!progress) break;
  }

  // Every stream's response routed to its own callback with the right status.
  for (int i = 0; i < 3; ++i) {
    CHECK(results[i].got);
    CHECK(results[i].stream_id == ids[i]);
    CHECK(results[i].status == 200 + (ids[i] - 1) / 2);
    CHECK(results[i].body_len == 5);
  }
  CHECK(h2_session_idle(cli));  // all streams closed -> open_streams back to 0

  nghttp2_session_del(srv);
  h2_session_release(cli);
}

internal void test_pool_lifecycle(void) {
  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/0);
  CHECK(client_ok(&c));

  PoolStats z = client_pool_stats(&c);
  CHECK(z.conns_created == 0 && z.requests == 0 && z.reuses == 0);
  CHECK(c.pool == 0);  // off by default

  client_set_max_conns_per_origin(&c, 4);
  CHECK(c.pool != 0);  // lazily allocated by the setter
  client_set_pool_idle_timeout_ms(&c, 1000);
  CHECK(c.max_conns_per_origin == 4 && c.pool_idle_timeout_ms == 1000);

  client_set_max_conns_per_origin(&c, 0);  // disable again (drains empty pool)

  client_cleanup(&c);  // drains + frees the (empty) pool, then the SSL_CTX
  CHECK(c.pool == 0);
  loop_shutdown(&loop);
}

int main(void) {
  test_h2_multiplex();
  test_pool_lifecycle();
  fprintf(stderr, "[pool_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
