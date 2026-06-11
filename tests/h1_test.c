// Offline gate for the HTTP/1.1 module: (A) the request serializer emits the exact
// wire bytes (request line, Host first, verbatim wire-cased headers in order, blank
// line, body, no Connection header); (B) the picohttpparser-driven response parser
// handles Content-Length, chunked, close-delimited, 204/304, HEAD and redirects,
// each fed both whole AND one byte at a time (incremental parse + pointer-lifetime).
#include <stdio.h>
#include <string.h>

#include "base/base.h"
#include "base/string8.h"
#include "core/header.h"
#include "h1/h1.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

//- (A) serializer ----------------------------------------------------------

typedef struct Cap Cap;
struct Cap {
  U8 buf[8192];
  U64 len;
};
internal void cap_send(void *user, const U8 *data, U64 len) {
  Cap *c = (Cap *)user;
  if (c->len + len <= sizeof c->buf) {
    MemoryCopy(c->buf + c->len, data, len);
    c->len += len;
  }
}

internal void test_serializer_get(void) {
  Cap cap;
  MemoryZeroStruct(&cap);
  H1Session *s = h1_session_alloc(cap_send, &cap);
  Header hdrs[] = {
      {str8_lit("sec-ch-ua"), str8_lit("\"Chromium\";v=\"148\""), 0},
      {str8_lit("User-Agent"), str8_lit("Mozilla/5.0"), 0},
      {str8_lit("Accept"), str8_lit("*/*"), 0},
      {str8_lit("Accept-Encoding"), str8_lit("gzip, deflate, br, zstd"), 0},
  };
  h1_session_submit_request(s, str8_lit("GET"), str8_lit("tls.browserleaks.com"),
                            str8_lit("/json"), hdrs, 4, 0, 0, /*is_head=*/0, 0,
                            0);
  String8 want = str8_lit(
      "GET /json HTTP/1.1\r\n"
      "Host: tls.browserleaks.com\r\n"
      "sec-ch-ua: \"Chromium\";v=\"148\"\r\n"
      "User-Agent: Mozilla/5.0\r\n"
      "Accept: */*\r\n"
      "Accept-Encoding: gzip, deflate, br, zstd\r\n"
      "\r\n");
  CHECK(str8_match(str8(cap.buf, cap.len), want));
  h1_session_release(s);
}

internal void test_serializer_post(void) {
  Cap cap;
  MemoryZeroStruct(&cap);
  H1Session *s = h1_session_alloc(cap_send, &cap);
  Header hdrs[] = {
      {str8_lit("Content-Type"), str8_lit("text/plain"), 0},
      {str8_lit("Content-Length"), str8_lit("5"), 0},
  };
  h1_session_submit_request(s, str8_lit("POST"), str8_lit("x.com"),
                            str8_lit("/p"), hdrs, 2, (const U8 *)"hello", 5,
                            /*is_head=*/0, 0, 0);
  String8 want = str8_lit(
      "POST /p HTTP/1.1\r\n"
      "Host: x.com\r\n"
      "Content-Type: text/plain\r\n"
      "Content-Length: 5\r\n"
      "\r\n"
      "hello");
  CHECK(str8_match(str8(cap.buf, cap.len), want));
  h1_session_release(s);
}

// A caller-supplied Host / Connection must be dropped (Host is injected; Connection
// omitted) so neither is duplicated or contradicts the Chrome-faithful defaults.
internal void test_serializer_filter(void) {
  Cap cap;
  MemoryZeroStruct(&cap);
  H1Session *s = h1_session_alloc(cap_send, &cap);
  Header hdrs[] = {
      {str8_lit("Host"), str8_lit("evil.com"), 0},
      {str8_lit("Connection"), str8_lit("close"), 0},
      {str8_lit("Accept"), str8_lit("*/*"), 0},
  };
  h1_session_submit_request(s, str8_lit("GET"), str8_lit("good.com"),
                            str8_lit("/"), hdrs, 3, 0, 0, 0, 0, 0);
  String8 want = str8_lit(
      "GET / HTTP/1.1\r\n"
      "Host: good.com\r\n"
      "Accept: */*\r\n"
      "\r\n");
  CHECK(str8_match(str8(cap.buf, cap.len), want));
  h1_session_release(s);
}

//- (B) response parsing ----------------------------------------------------

typedef struct Resp Resp;
struct Resp {
  B32 got;
  int status;
  U64 header_count;
  U64 body_len;
  char body[8192];
  char location[256];  // copy of the Location header value (if any)
  char probe[64];      // copy of x-header-30 (stress test)
};

internal void on_resp(void *user, const H1Response *r) {
  Resp *x = (Resp *)user;
  x->got = 1;
  x->status = r->status;
  x->header_count = r->headers ? r->headers->count : 0;
  x->body_len = r->body_len;
  U64 n = r->body_len < sizeof x->body ? r->body_len : sizeof x->body;
  if (r->body && n) MemoryCopy(x->body, r->body, n);
  if (r->headers) {
    String8 *loc = header_list_get_ci(r->headers, str8_lit("location"));
    if (loc) {
      U64 m = loc->size < sizeof x->location - 1 ? loc->size
                                                 : sizeof x->location - 1;
      MemoryCopy(x->location, loc->str, m);
      x->location[m] = 0;
    }
    String8 *p = header_list_get_ci(r->headers, str8_lit("x-header-30"));
    if (p) {
      U64 m = p->size < sizeof x->probe - 1 ? p->size : sizeof x->probe - 1;
      MemoryCopy(x->probe, p->str, m);
      x->probe[m] = 0;
    }
  }
}

internal void noop_send(void *user, const U8 *data, U64 len) {
  (void)user;
  (void)data;
  (void)len;
}

// Drive one response through the parser. chunked=0: whole; 1: one byte at a time.
// send_eof: signal a clean peer close after the bytes (close-delimited bodies).
internal Resp run_response(String8 method, B32 is_head, String8 raw, int onebyte,
                           B32 send_eof) {
  Resp x;
  MemoryZeroStruct(&x);
  H1Session *s = h1_session_alloc(noop_send, 0);
  h1_session_submit_request(s, method, str8_lit("h"), str8_lit("/"), 0, 0, 0, 0,
                            is_head, on_resp, &x);
  if (onebyte)
    for (U64 i = 0; i < raw.size; ++i) h1_session_recv(s, raw.str + i, 1);
  else
    h1_session_recv(s, raw.str, raw.size);
  if (send_eof) h1_session_eof(s);
  h1_session_release(s);  // on_resp already copied everything out
  return x;
}

internal void test_responses(void) {
  for (int ob = 0; ob <= 1; ++ob) {
    // Content-Length.
    Resp r = run_response(str8_lit("GET"), 0,
                          str8_lit("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
                                   "hello"),
                          ob, 0);
    CHECK(r.got && r.status == 200 && r.body_len == 5 &&
          memcmp(r.body, "hello", 5) == 0);

    // Chunked.
    r = run_response(str8_lit("GET"), 0,
                     str8_lit("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                              "\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
                     ob, 0);
    CHECK(r.got && r.status == 200 && r.body_len == 11 &&
          memcmp(r.body, "hello world", 11) == 0);

    // Chunked with a MULTI-DIGIT chunk size (0x11 = 17): fed 1 byte at a time this
    // splits the "11" across recv calls — the decoder must accumulate the partial
    // hex into its state, not the buffer (refutes the "lost framing bytes" claim).
    r = run_response(str8_lit("GET"), 0,
                     str8_lit("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                              "\r\n11\r\nABCDEFGHIJKLMNOPQ\r\n0\r\n\r\n"),
                     ob, 0);
    CHECK(r.got && r.status == 200 && r.body_len == 17 &&
          memcmp(r.body, "ABCDEFGHIJKLMNOPQ", 17) == 0);

    // Close-delimited (no CL/TE) -> delivered on EOF.
    r = run_response(str8_lit("GET"), 0,
                     str8_lit("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                              "\r\nbodybytes"),
                     ob, /*send_eof=*/1);
    CHECK(r.got && r.status == 200 && r.body_len == 9 &&
          memcmp(r.body, "bodybytes", 9) == 0);

    // 204 / 304: no body, delivered without CL/EOF.
    r = run_response(str8_lit("GET"), 0,
                     str8_lit("HTTP/1.1 204 No Content\r\n\r\n"), ob, 0);
    CHECK(r.got && r.status == 204 && r.body_len == 0);
    r = run_response(str8_lit("GET"), 0,
                     str8_lit("HTTP/1.1 304 Not Modified\r\n\r\n"), ob, 0);
    CHECK(r.got && r.status == 304 && r.body_len == 0);

    // HEAD: no body despite Content-Length.
    r = run_response(str8_lit("HEAD"), /*is_head=*/1,
                     str8_lit("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"),
                     ob, 0);
    CHECK(r.got && r.status == 200 && r.body_len == 0);

    // Redirect 302 with Location.
    r = run_response(str8_lit("GET"), 0,
                     str8_lit("HTTP/1.1 302 Found\r\nLocation: /x\r\n"
                              "Content-Length: 0\r\n\r\n"),
                     ob, 0);
    CHECK(r.got && r.status == 302 && strcmp(r.location, "/x") == 0);
  }

  // Header pointer-lifetime stress: 60 headers fed 1 byte at a time forces the
  // `in` buffer to grow during the incomplete phase; assert a mid header survived
  // the copy-out (and the count).
  char big[8192];
  int off = 0;
  off += snprintf(big + off, sizeof big - off, "HTTP/1.1 200 OK\r\n");
  for (int i = 0; i < 60; ++i)
    off += snprintf(big + off, sizeof big - off, "X-Header-%d: val%d\r\n", i, i);
  off += snprintf(big + off, sizeof big - off, "Content-Length: 0\r\n\r\n");
  Resp r = run_response(str8_lit("GET"), 0, str8((U8 *)big, (U64)off), 1, 0);
  CHECK(r.got && r.status == 200 && r.header_count >= 60 &&
        strcmp(r.probe, "val30") == 0);

  // An overflowing Content-Length must saturate, NOT wrap to a small value (which
  // would falsely complete with a truncated body). It never completes -> on EOF in
  // the length state we deliver nothing.
  Resp ov = run_response(
      str8_lit("GET"), 0,
      str8_lit("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999\r\n"
               "\r\nHello"),
      0, /*send_eof=*/1);
  CHECK(!ov.got);
}

int main(void) {
  test_serializer_get();
  test_serializer_post();
  test_serializer_filter();
  test_responses();
  fprintf(stderr, "[h1_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
