// Akamai HTTP/2 fingerprint golden: drive H2Session into a raw nghttp2 server,
// reconstruct the akamai text (SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo)
// and assert it byte-for-byte (it MD5s to the project goldens 52d84… / 6ea73…).
#include "h2/h2.h"

#include <nghttp2/nghttp2.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

//- client output sink
typedef struct OutBuf OutBuf;
struct OutBuf {
  U8 data[8192];
  U64 len;
};
internal void out_sink(void *user, const U8 *d, U64 n) {
  OutBuf *o = (OutBuf *)user;
  if (o->len + n <= sizeof o->data) {
    MemoryCopy(o->data + o->len, d, n);
    o->len += n;
  }
}
internal void noop_resp(void *user, const H2Response *r) {
  (void)user;
  (void)r;
}

//- raw nghttp2 server that captures the fingerprint surface
typedef struct Cap Cap;
struct Cap {
  int s_id[16];
  U32 s_val[16];
  int s_count;
  long wu;
  char pseudo[16];
  int pseudo_len;
};
internal nghttp2_ssize srv_send(nghttp2_session *s, const U8 *d, size_t n,
                                int f, void *u) {
  (void)s;
  (void)d;
  (void)f;
  (void)u;
  return (nghttp2_ssize)n;
}
internal int srv_frame(nghttp2_session *s, const nghttp2_frame *f, void *u) {
  (void)s;
  Cap *c = (Cap *)u;
  if (f->hd.type == NGHTTP2_SETTINGS && !(f->hd.flags & NGHTTP2_FLAG_ACK)) {
    for (size_t i = 0; i < f->settings.niv && c->s_count < 16; ++i) {
      c->s_id[c->s_count] = (int)f->settings.iv[i].settings_id;
      c->s_val[c->s_count] = f->settings.iv[i].value;
      c->s_count += 1;
    }
  } else if (f->hd.type == NGHTTP2_WINDOW_UPDATE && f->hd.stream_id == 0) {
    c->wu = f->window_update.window_size_increment;
  }
  return 0;
}
internal int srv_header(nghttp2_session *s, const nghttp2_frame *f,
                        const U8 *name, size_t nl, const U8 *val, size_t vl,
                        U8 fl, void *u) {
  (void)s;
  (void)val;
  (void)vl;
  (void)fl;
  Cap *c = (Cap *)u;
  if (f->hd.type == NGHTTP2_HEADERS && nl > 0 && name[0] == ':') {
    String8 n = str8((U8 *)name, nl);
    char ch = str8_match(n, str8_lit(":method"))      ? 'm'
              : str8_match(n, str8_lit(":authority")) ? 'a'
              : str8_match(n, str8_lit(":scheme"))    ? 's'
              : str8_match(n, str8_lit(":path"))      ? 'p'
                                                      : 0;
    if (ch && c->pseudo_len + 2 <= (int)sizeof c->pseudo) {
      if (c->pseudo_len) c->pseudo[c->pseudo_len++] = ',';
      c->pseudo[c->pseudo_len++] = ch;
    }
  }
  return 0;
}

internal String8 akamai_text(Arena *arena, const Http2Profile *prof) {
  OutBuf out = {{0}, 0};
  H2Session *cli = h2_session_alloc(prof, out_sink, &out);
  h2_session_start(cli);
  h2_session_submit_request(cli, str8_lit("GET"), str8_lit("https"),
                            str8_lit("tls.browserleaks.com"), str8_lit("/"), 0,
                            0, 0, 0, noop_resp, 0);

  Cap cap = {{0}, {0}, 0, -1, {0}, 0};
  nghttp2_session_callbacks *cbs = 0;
  nghttp2_session_callbacks_new(&cbs);
  nghttp2_session_callbacks_set_send_callback2(cbs, srv_send);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, srv_frame);
  nghttp2_session_callbacks_set_on_header_callback(cbs, srv_header);
  nghttp2_session *srv = 0;
  nghttp2_session_server_new(&srv, cbs, &cap);
  nghttp2_session_callbacks_del(cbs);
  nghttp2_submit_settings(srv, NGHTTP2_FLAG_NONE, 0, 0);
  nghttp2_session_send(srv);
  nghttp2_session_mem_recv2(srv, out.data, out.len);
  nghttp2_session_del(srv);
  h2_session_release(cli);

  String8List sl = {0};
  for (int i = 0; i < cap.s_count; ++i)
    str8_list_pushf(arena, &sl, "%d:%u", cap.s_id[i], cap.s_val[i]);
  String8 settings = str8_list_join(arena, &sl, str8_lit(";"));
  return push_str8f(arena, "%.*s|%ld|0|%.*s", (int)settings.size, settings.str,
                    cap.wu, cap.pseudo_len, cap.pseudo);
}

int main(void) {
  Arena *a = arena_alloc();

  String8 chrome = akamai_text(a, &profile_chrome148()->h2);
  fprintf(stderr, "chrome148 akamai = %.*s\n", (int)chrome.size, chrome.str);
  CHECK(str8_match(
      chrome, str8_lit("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p")));

  String8 tmpl = akamai_text(a, &profile_template()->h2);
  fprintf(stderr, "template  akamai = %.*s\n", (int)tmpl.size, tmpl.str);
  CHECK(str8_match(
      tmpl, str8_lit("1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s")));

  arena_release(a);
  fprintf(stderr, "[h2_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
