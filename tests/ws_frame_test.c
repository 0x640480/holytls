// Offline RFC 6455 frame-codec tests. The parser consumes SERVER (unmasked)
// frames; ws_frame_build produces CLIENT (masked) frames — so masking is checked
// separately from parsing. The key property is the byte-exact partial-feed
// invariant: a byte stream split at ANY offset must decode identically.
#include <stdio.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/u8buf.h"
#include "ws/ws_frame.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

// Build a SERVER frame (unmasked) — what a client receives.
static void server_frame(U8Buf *out, int op, int fin, const U8 *payload,
                         U64 len) {
  u8buf_push(out, (U8)((fin ? 0x80 : 0) | (op & 0x0f)));
  if (len < 126) {
    u8buf_push(out, (U8)len);
  } else if (len <= 0xffff) {
    u8buf_push(out, 126);
    u8buf_push(out, (U8)(len >> 8));
    u8buf_push(out, (U8)len);
  } else {
    u8buf_push(out, 127);
    for (int i = 7; i >= 0; --i) u8buf_push(out, (U8)(len >> (i * 8)));
  }
  if (len) u8buf_append(out, payload, len);
}

// Event collector.
typedef struct Ev {
  int kind, op, compressed;
  U16 code;
  U64 len;
  U8 data[70000];
} Ev;
global Ev g_evs[64];
global int g_nev;
static void collect(void *user, const WsEvent *ev) {
  (void)user;
  if (g_nev >= 64) return;
  Ev *e = &g_evs[g_nev++];
  e->kind = ev->kind;
  e->op = ev->op;
  e->compressed = ev->compressed;
  e->code = ev->close_code;
  e->len = ev->len;
  if (ev->len && ev->len <= sizeof e->data) MemoryCopy(e->data, ev->data, ev->len);
}

// Feed `buf` through a fresh parser in `step`-byte chunks; collect into g_evs.
// Returns the parser's last feed result (<0 on protocol error).
static S64 feed_in_steps(const U8 *buf, U64 n, U64 step) {
  g_nev = 0;
  WsParser p;
  ws_parser_init(&p, 0);
  S64 rc = 0;
  for (U64 off = 0; off < n; off += step) {
    U64 take = off + step <= n ? step : n - off;
    rc = ws_parser_feed(&p, buf + off, take, collect, 0);
    if (rc < 0) break;
  }
  if (n == 0) rc = ws_parser_feed(&p, buf, 0, collect, 0);
  ws_parser_free(&p);
  return rc;
}

int main(void) {
  Arena *a = arena_alloc();

  // 1) Client build: masking + length encoding.
  {
    U8 key[4] = {0xde, 0xad, 0xbe, 0xef};
    const char *m = "hello world";
    U64 ml = strlen(m);
    U8Buf b;
    u8buf_init(&b, a, 64);
    ws_frame_build(&b, WsOp_Text, 1, 0, (const U8 *)m, ml, key);
    CHECK(b.v[0] == 0x81);                  // FIN + text
    CHECK(b.v[1] == (U8)(0x80 | ml));       // MASK bit + len
    CHECK(memcmp(b.v + 2, key, 4) == 0);    // mask key present
    B32 unmask_ok = 1;
    for (U64 i = 0; i < ml; ++i)
      if ((U8)(b.v[6 + i] ^ key[i & 3]) != (U8)m[i]) unmask_ok = 0;
    CHECK(unmask_ok);  // payload is masked with the key
  }
  // 16-bit length encoding (len=126) and 64-bit (len=70000).
  {
    U8 key[4] = {1, 2, 3, 4};
    U8 *big = (U8 *)arena_push(a, 70000, 1);
    for (U64 i = 0; i < 70000; ++i) big[i] = (U8)i;
    U8Buf b;
    u8buf_init(&b, a, 70016);
    ws_frame_build(&b, WsOp_Binary, 1, 0, big, 126, key);
    CHECK((b.v[1] & 0x7f) == 126 && b.v[2] == 0 && b.v[3] == 126);  // 16-bit
    u8buf_init(&b, a, 70032);
    ws_frame_build(&b, WsOp_Binary, 1, 0, big, 70000, key);
    CHECK((b.v[1] & 0x7f) == 127);  // 64-bit length
  }

  // 2) Parse a simple text + binary message.
  {
    U8Buf s;
    u8buf_init(&s, a, 64);
    server_frame(&s, WsOp_Text, 1, (const U8 *)"hi", 2);
    CHECK(feed_in_steps(s.v, s.len, 1) >= 0);  // 1-byte feeds
    CHECK(g_nev == 1 && g_evs[0].kind == WsEvent_Message &&
          g_evs[0].op == WsOp_Text && g_evs[0].len == 2 &&
          memcmp(g_evs[0].data, "hi", 2) == 0);
  }
  // Empty message + length boundaries (125/126/65535/65536) decode intact.
  {
    U64 lens[] = {0, 125, 126, 65535, 65536};
    for (U64 li = 0; li < ArrayCount(lens); ++li) {
      U64 L = lens[li];
      U8 *pl = (U8 *)arena_push(a, L ? L : 1, 1);
      for (U64 i = 0; i < L; ++i) pl[i] = (U8)(i * 37 + 1);
      U8Buf s;
      u8buf_init(&s, a, L + 16);
      server_frame(&s, WsOp_Binary, 1, pl, L);
      CHECK(feed_in_steps(s.v, s.len, 3) >= 0);
      CHECK(g_nev == 1 && g_evs[0].len == L &&
            (L == 0 || memcmp(g_evs[0].data, pl, L) == 0));
    }
  }

  // 3) Fragmented message (text + continuation) with a ping interleaved.
  {
    U8Buf s;
    u8buf_init(&s, a, 64);
    server_frame(&s, WsOp_Text, 0, (const U8 *)"Hel", 3);          // fin=0
    server_frame(&s, WsOp_Ping, 1, (const U8 *)"pp", 2);           // control between
    server_frame(&s, WsOp_Continuation, 1, (const U8 *)"lo!", 3);  // fin=1
    CHECK(feed_in_steps(s.v, s.len, 1) >= 0);
    CHECK(g_nev == 2);
    CHECK(g_evs[0].kind == WsEvent_Ping && g_evs[0].len == 2);
    CHECK(g_evs[1].kind == WsEvent_Message && g_evs[1].op == WsOp_Text &&
          g_evs[1].len == 6 && memcmp(g_evs[1].data, "Hello!", 6) == 0);
  }

  // 4) Close frame with a 2-byte code + reason.
  {
    U8 cl[5] = {0x03, 0xe8, 'b', 'y', 'e'};  // 1000 + "bye"
    U8Buf s;
    u8buf_init(&s, a, 16);
    server_frame(&s, WsOp_Close, 1, cl, 5);
    CHECK(feed_in_steps(s.v, s.len, 2) >= 0);
    CHECK(g_nev == 1 && g_evs[0].kind == WsEvent_Close &&
          g_evs[0].code == 1000 && g_evs[0].len == 3 &&
          memcmp(g_evs[0].data, "bye", 3) == 0);
  }

  // 5) Protocol violations -> error.
  {
    // a masked server frame (MASK bit set) is illegal
    U8 bad[] = {0x81, 0x82, 0, 0, 0, 0, 'x', 'y'};
    CHECK(feed_in_steps(bad, sizeof bad, 1) < 0);
    // a fragmented control frame (close with fin=0) is illegal
    U8Buf s;
    u8buf_init(&s, a, 16);
    server_frame(&s, WsOp_Close, 0, (const U8 *)"x", 1);
    CHECK(feed_in_steps(s.v, s.len, 1) < 0);
    // an over-long control frame (ping > 125) is illegal
    U8 big[130];
    MemoryZero(big, sizeof big);
    u8buf_init(&s, a, 200);
    server_frame(&s, WsOp_Ping, 1, big, 130);
    CHECK(feed_in_steps(s.v, s.len, 1) < 0);
  }

  // 6) The partial-feed invariant: a multi-frame stream split at EVERY chunk
  //    size 1..len decodes to the identical event sequence.
  {
    U8Buf s;
    u8buf_init(&s, a, 256);
    server_frame(&s, WsOp_Text, 1, (const U8 *)"alpha", 5);
    server_frame(&s, WsOp_Binary, 0, (const U8 *)"\x00\x01\x02", 3);
    server_frame(&s, WsOp_Ping, 1, (const U8 *)"", 0);
    server_frame(&s, WsOp_Continuation, 1, (const U8 *)"\x03\x04", 2);
    server_frame(&s, WsOp_Close, 1, (const U8 *)"\x03\xe9", 2);  // 1001

    // Reference: one-shot feed.
    feed_in_steps(s.v, s.len, s.len);
    int ref_n = g_nev;
    Ev ref[64];
    MemoryCopy(ref, g_evs, sizeof ref);
    CHECK(ref_n == 4);  // 2 messages (alpha; binary+cont) + ping + close

    B32 all_match = 1;
    for (U64 step = 1; step <= s.len; ++step) {
      feed_in_steps(s.v, s.len, step);
      if (g_nev != ref_n) {
        all_match = 0;
        break;
      }
      for (int e = 0; e < g_nev; ++e)
        if (g_evs[e].kind != ref[e].kind || g_evs[e].op != ref[e].op ||
            g_evs[e].len != ref[e].len || g_evs[e].code != ref[e].code ||
            memcmp(g_evs[e].data, ref[e].data, g_evs[e].len) != 0) {
          all_match = 0;
          break;
        }
      if (!all_match) break;
    }
    CHECK(all_match);  // identical decode at every split offset
  }

  // 7) RFC 7692 RSV1 (permessage-deflate compression marker).
  {
    // A data frame's RSV1 bit (0x40) is a protocol error unless compression was
    // negotiated. (0xC1 = FIN|RSV1|Text, len 2, unmasked server frame.)
    U8 rsv1_text[] = {0xC1, 0x02, 'h', 'i'};
    CHECK(feed_in_steps(rsv1_text, sizeof rsv1_text, 1) < 0);  // rejected

    // With compression allowed, RSV1 marks the message compressed; the codec
    // surfaces the flag but does NOT inflate (the WsConn owns zlib). The payload
    // is delivered verbatim.
    g_nev = 0;
    WsParser p;
    ws_parser_init(&p, 0);
    ws_parser_allow_compression(&p);
    CHECK(ws_parser_feed(&p, rsv1_text, sizeof rsv1_text, collect, 0) >= 0);
    ws_parser_free(&p);
    CHECK(g_nev == 1 && g_evs[0].kind == WsEvent_Message &&
          g_evs[0].compressed == 1 && g_evs[0].len == 2 &&
          memcmp(g_evs[0].data, "hi", 2) == 0);

    // A non-compressed message (RSV1 clear) still reports compressed == 0 even
    // when compression is allowed.
    U8 plain[] = {0x81, 0x02, 'y', 'o'};
    g_nev = 0;
    ws_parser_init(&p, 0);
    ws_parser_allow_compression(&p);
    CHECK(ws_parser_feed(&p, plain, sizeof plain, collect, 0) >= 0);
    ws_parser_free(&p);
    CHECK(g_nev == 1 && g_evs[0].compressed == 0);

    // RSV1 on a CONTROL frame (ping) is illegal even with compression allowed.
    U8 rsv1_ping[] = {0xC9, 0x00};  // FIN|RSV1|Ping
    ws_parser_init(&p, 0);
    ws_parser_allow_compression(&p);
    CHECK(ws_parser_feed(&p, rsv1_ping, sizeof rsv1_ping, collect, 0) < 0);
    ws_parser_free(&p);

    // RSV1 on a CONTINUATION frame (only the first fragment may carry it).
    U8 frag[] = {0x41, 0x01, 'a', 0xC0, 0x01, 'b'};  // RSV1|Text fin0, RSV1|cont fin1
    ws_parser_init(&p, 0);
    ws_parser_allow_compression(&p);
    CHECK(ws_parser_feed(&p, frag, sizeof frag, collect, 0) < 0);
    ws_parser_free(&p);
  }

  arena_release(a);
  fprintf(stderr, "[ws_frame_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
