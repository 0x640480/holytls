// Live verification that request headers are SENT and RECEIVED in the order we
// declare. We GET the self-hosted TrackMe oracle's /api/all (which decodes the
// HTTP/2 HEADERS frame and echoes the received headers IN ORDER under
// http2.sent_frames[HEADERS].headers), extract the received name sequence, and
// assert it equals the order profile_chrome148() declares (pseudo order +
// non-empty default headers). Independent corroboration that
// build_ordered_headers
// + the H2 submit order land on the wire as intended.
//
// Gated by HOLYTLS_TRACKME (needs the local oracle running).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/base.h"
#include "base/defer.h"
#include "core/client.h"
#include "core/json.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

#define MAX_HDRS 40
#define MAX_NAME 64

typedef struct Ctx Ctx;
struct Ctx {
  B32 got;
  int status;
  B32 found_frame;
  char recv[MAX_HDRS][MAX_NAME];  // received header names, in order
  int recv_count;
};

internal void store_name(Ctx *cx, String8 name) {
  if (cx->recv_count >= MAX_HDRS) return;
  U64 n = name.size < MAX_NAME - 1 ? name.size : MAX_NAME - 1;
  MemoryCopy(cx->recv[cx->recv_count], name.str, n);
  cx->recv[cx->recv_count][n] = 0;
  cx->recv_count += 1;
}

internal void on_response(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  if (!r->ok) {
    fprintf(stderr, "  request FAILED: %s\n", r->error ? r->error : "unknown");
    return;
  }
  cx->got = 1;
  cx->status = r->status;

  Arena *a = arena_alloc();
  yyjson_doc *doc = json_parse(a, str8((U8 *)r->body, r->body_len));
  if (doc) {
    yyjson_val *http2 = yyjson_obj_get(json_root(doc), "http2");
    yyjson_val *frames = yyjson_obj_get(http2, "sent_frames");
    yyjson_val *frame;
    size_t fi, fn;
    yyjson_arr_foreach(frames, fi, fn, frame) {
      yyjson_val *hdrs = yyjson_obj_get(frame, "headers");
      if (!hdrs || !yyjson_is_arr(hdrs) || yyjson_arr_size(hdrs) == 0) continue;
      cx->found_frame = 1;  // the HEADERS frame (the only one carrying headers)
      yyjson_val *h;
      size_t hi, hn;
      yyjson_arr_foreach(hdrs, hi, hn, h) {
        if (!yyjson_is_str(h)) continue;
        // each entry is "name: value"; the name precedes the first ": " (pseudo
        // names start with ':', so split on ": " not the first ':').
        String8 entry = str8((U8 *)yyjson_get_str(h), (U64)yyjson_get_len(h));
        String8 name = str8_chop_by_str(&entry, str8_lit(": "));
        store_name(cx, name);
      }
      break;
    }
  }
  arena_release(a);  // names already copied into cx->recv
}

internal const char *pseudo_name(PseudoId id) {
  switch (id) {
    case Pseudo_Method:
      return ":method";
    case Pseudo_Authority:
      return ":authority";
    case Pseudo_Scheme:
      return ":scheme";
    case Pseudo_Path:
      return ":path";
  }
  return "?";
}

// One GET to the oracle; fills cx->recv with the received header names in
// order.
internal void fetch(EventLoop *loop, Client *c, const char *url, Ctx *cx) {
  MemoryZeroStruct(cx);
  client_get(c, str8_cstring(url), on_response, cx);
  loop_run(loop);
}
// Assert the received name sequence equals `exp`.
internal void check_received(Ctx *cx, const char **exp, int ecount,
                             const char *label) {
  CHECK(cx->got);
  CHECK(cx->found_frame);
  fprintf(stderr, "  [%s] received %d, expected %d\n", label, cx->recv_count,
          ecount);
  CHECK(cx->recv_count == ecount);
  if (cx->recv_count == ecount)
    for (int i = 0; i < ecount; ++i) {
      if (strcmp(cx->recv[i], exp[i]) != 0)
        fprintf(stderr, "    [%2d] got %-28s want %s\n", i, cx->recv[i],
                exp[i]);
      CHECK(strcmp(cx->recv[i], exp[i]) == 0);
    }
}

int main(void) {
  if (!getenv("HOLYTLS_TRACKME")) {
    printf(
        "[header_order_live_test] SKIP (set HOLYTLS_TRACKME=1 + run a local "
        "TrackMe)\n");
    return 0;
  }
  const char *url = getenv("HOLYTLS_TRACKME_URL");
  if (!url) url = "https://localhost:8443/api/all";
  fprintf(stderr, "[header_order_live_test] oracle = %s\n", url);

  const Profile *p = profile_chrome148();
  // Pseudo names (always first, in profile order — not affected by the
  // override), then the non-empty default REGULAR headers (the cookie
  // placeholder is omitted).
  const char *pseudo[8];
  int pn = 0;
  for (U8 i = 0; i < p->h2.pseudo_count; ++i)
    pseudo[pn++] = pseudo_name(p->h2.pseudo_order[i]);
  const char *regs[MAX_HDRS];
  int rn = 0;
  for (U8 i = 0; i < p->default_header_count; ++i)
    if (p->default_headers[i].value && p->default_headers[i].value[0])
      regs[rn++] = p->default_headers[i].name;

  // expected default order = pseudo ++ regs (the profile's order).
  const char *exp_def[MAX_HDRS];
  int en = 0;
  for (int i = 0; i < pn; ++i) exp_def[en++] = pseudo[i];
  for (int i = 0; i < rn; ++i) exp_def[en++] = regs[i];

  EventLoop loop;
  loop_init(&loop);
  defer { loop_shutdown(&loop); };
  Client client;
  client_init(&client, &loop, p, NULL, HttpVersion_H2,
              /*verify=*/0);  // self-signed oracle
  defer { client_cleanup(&client); };
  CHECK(client_ok(&client));

  Ctx cx;

  // 1) Default: the profile's byte-exact order lands on the wire.
  fetch(&loop, &client, url, &cx);
  check_received(&cx, exp_def, en, "default");

  // 2) Custom override: reverse the regular headers. pseudo stays first; the
  //    regulars arrive in our reversed order.
  String8 custom[MAX_HDRS];
  const char *exp_rev[MAX_HDRS];
  int rvn = 0;
  for (int i = 0; i < pn; ++i) exp_rev[rvn++] = pseudo[i];
  for (int i = 0; i < rn; ++i) {
    custom[i] = str8_cstring(regs[rn - 1 - i]);
    exp_rev[rvn++] = regs[rn - 1 - i];
  }
  CHECK(client_set_header_order(&client, custom, (U64)rn));
  fetch(&loop, &client, url, &cx);
  check_received(&cx, exp_rev, rvn, "custom-reversed");

  // 3) Reset (count 0): back to the profile's default order.
  CHECK(client_set_header_order(&client, 0, 0));
  fetch(&loop, &client, url, &cx);
  check_received(&cx, exp_def, en, "reset");

  // 4) Override default headers: ONLY the caller's headers reach the wire, in
  //    array order — no profile defaults (sec-ch-ua / sec-fetch-* / accept-
  //    encoding). Pseudo-headers still come from the profile (unchanged).
  client_override_default_headers(&client, 1);
  Header rawh[] = {
      {str8_lit("user-agent"), str8_lit("custom-agent/1.0"), 0},
      {str8_lit("accept"), str8_lit("*/*"), 0},
      {str8_lit("x-raw"), str8_lit("1"), 0},
  };
  const char *exp_raw[MAX_HDRS];
  int qn = 0;
  for (int i = 0; i < pn; ++i) exp_raw[qn++] = pseudo[i];
  exp_raw[qn++] = "user-agent";
  exp_raw[qn++] = "accept";
  exp_raw[qn++] = "x-raw";
  MemoryZeroStruct(&cx);
  RequestParams params = {.method = Method_GET,
                          .url = str8_cstring(url),
                          .headers = rawh,
                          .header_count = ArrayCount(rawh),
                          .no_redirects = 1};
  client_request(&client, &params, on_response, &cx);
  loop_run(&loop);
  check_received(&cx, exp_raw, qn, "override");

  // 5) Override + explicit order compose: the order override defines the wire
  //    order regardless of the array order (Go's req.Header + HeaderOrderKey).
  String8 ro[] = {str8_lit("x-raw"), str8_lit("user-agent"),
                  str8_lit("accept")};
  CHECK(client_set_header_order(&client, ro, ArrayCount(ro)));
  const char *exp_ro[MAX_HDRS];
  int rqn = 0;
  for (int i = 0; i < pn; ++i) exp_ro[rqn++] = pseudo[i];
  exp_ro[rqn++] = "x-raw";
  exp_ro[rqn++] = "user-agent";
  exp_ro[rqn++] = "accept";
  MemoryZeroStruct(&cx);
  client_request(&client, &params, on_response, &cx);
  loop_run(&loop);
  check_received(&cx, exp_ro, rqn, "override+order");
  client_set_header_order(&client, 0, 0);
  client_override_default_headers(&client, 0);

  fprintf(stderr, "[header_order_live_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
