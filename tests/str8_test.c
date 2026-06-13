// Offline gate for the String8 view operations (tsoding sv.h-style): trim, chop
// (by delim / by substring / left / right), take/skip, take-while, index/find/
// contains, ends_with, parse (to_u64 / chop_u64), and the STR8_Fmt/STR8_Arg
// macros. All pure-view (no allocation); exercises empty + boundary inputs.
#include <stdio.h>
#include <string.h>

#include "base/base.h"
#include "base/string8.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })
#define EQ(s, lit) str8_match((s), str8_lit(lit))

internal B32 is_digit(U8 c) { return c >= '0' && c <= '9'; }

internal void test_take_trim(void) {
  CHECK(EQ(str8_prefix(str8_lit("hello"), 3), "hel"));
  CHECK(EQ(str8_prefix(str8_lit("hi"), 9), "hi"));  // clamp
  CHECK(EQ(str8_skip(str8_lit("hello"), 2), "llo"));
  CHECK(EQ(str8_skip(str8_lit("hi"), 9), ""));  // clamp -> empty

  CHECK(EQ(str8_trim_left(str8_lit("  \t x ")), "x "));
  CHECK(EQ(str8_trim_right(str8_lit(" x \n ")), " x"));
  CHECK(EQ(str8_trim(str8_lit("  \tx y\r\n")), "x y"));
  CHECK(EQ(str8_trim(str8_lit("   ")), ""));     // all whitespace
  CHECK(EQ(str8_trim(str8_lit("abc")), "abc"));  // none
}

internal void test_chop_lr(void) {
  String8 s = str8_lit("abcdef");
  CHECK(EQ(str8_chop_left(&s, 2), "ab") && EQ(s, "cdef"));
  CHECK(EQ(str8_chop_right(&s, 2), "ef") && EQ(s, "cd"));
  CHECK(EQ(str8_chop_left(&s, 99), "cd") && s.size == 0);  // clamp
}

internal void test_search(void) {
  U64 idx = 999;
  CHECK(str8_index_of(str8_lit("a,b"), ',', &idx) && idx == 1);
  CHECK(!str8_index_of(str8_lit("abc"), ',', &idx));
  CHECK(str8_index_of(str8_lit("xy"), 'y', 0));  // null out_index ok

  CHECK(str8_find(str8_lit("hello world"), str8_lit("world")) == 6);
  CHECK(str8_find(str8_lit("hello"), str8_lit("xyz")) == -1);
  CHECK(str8_find(str8_lit("hello"), str8_lit("")) == 0);      // empty needle
  CHECK(str8_find(str8_lit("hi"), str8_lit("longer")) == -1);  // needle longer
  CHECK(str8_contains(str8_lit("gzip, chunked"), str8_lit("chunked")));
  CHECK(!str8_contains(str8_lit("gzip"), str8_lit("br")));

  CHECK(str8_ends_with(str8_lit("file.json"), str8_lit(".json")));
  CHECK(!str8_ends_with(str8_lit("file.txt"), str8_lit(".json")));
  CHECK(!str8_ends_with(str8_lit("x"), str8_lit("longer")));
}

internal void test_chop_delim(void) {
  String8 s = str8_lit("a,b,c");
  CHECK(EQ(str8_chop_by_delim(&s, ','), "a") && EQ(s, "b,c"));
  CHECK(EQ(str8_chop_by_delim(&s, ','), "b") && EQ(s, "c"));
  CHECK(EQ(str8_chop_by_delim(&s, ','), "c") && s.size == 0);  // last token
  // delim absent -> whole head, *s empty; delim at start -> empty head.
  s = str8_lit("abc");
  CHECK(EQ(str8_chop_by_delim(&s, ','), "abc") && s.size == 0);
  s = str8_lit(",x");
  CHECK(str8_chop_by_delim(&s, ',').size == 0 && EQ(s, "x"));

  // by substring delim.
  s = str8_lit("aXXbXXc");
  CHECK(EQ(str8_chop_by_str(&s, str8_lit("XX")), "a") && EQ(s, "bXXc"));
  CHECK(EQ(str8_chop_by_str(&s, str8_lit("XX")), "b") && EQ(s, "c"));
  CHECK(EQ(str8_chop_by_str(&s, str8_lit("XX")), "c") && s.size == 0);

  // try_chop: present advances; absent leaves *s unchanged.
  s = str8_lit("k=v");
  String8 out = str8_zero();
  CHECK(str8_try_chop_by_delim(&s, '=', &out) && EQ(out, "k") && EQ(s, "v"));
  CHECK(!str8_try_chop_by_delim(&s, '=', &out) && EQ(s, "v"));
}

internal void test_while_parse(void) {
  CHECK(EQ(str8_take_left_while(str8_lit("123abc"), is_digit), "123"));
  CHECK(str8_take_left_while(str8_lit("abc"), is_digit).size == 0);
  String8 s = str8_lit("123abc");
  CHECK(EQ(str8_chop_left_while(&s, is_digit), "123") && EQ(s, "abc"));

  CHECK(str8_to_u64(str8_lit("42")) == 42);
  CHECK(str8_to_u64(str8_lit("42abc")) == 42);  // stops at non-digit
  CHECK(str8_to_u64(str8_lit("")) == 0);
  CHECK(str8_to_u64(str8_lit("99999999999999999999999999")) ==
        ~(U64)0);  // saturate

  s = str8_lit("2592000; ma=...");
  CHECK(str8_chop_u64(&s) == 2592000 && EQ(s, "; ma=..."));
}

internal void test_fmt(void) {
  char buf[32];
  String8 s = str8_lit("t13d");
  snprintf(buf, sizeof buf, "[" STR8_Fmt "]", STR8_Arg(s));
  CHECK(strcmp(buf, "[t13d]") == 0);
}

internal void test_charclass(void) {
  CHECK(char_is_digit('5') && !char_is_digit('a'));
  CHECK(char_is_alpha('a') && char_is_alpha('Z') && !char_is_alpha('5'));
  CHECK(char_is_alnum('5') && char_is_alnum('q') && !char_is_alnum('-'));
  CHECK(char_is_hex('f') && char_is_hex('F') && char_is_hex('9') &&
        !char_is_hex('g'));
  CHECK(char_is_upper('A') && !char_is_upper('a'));
  CHECK(char_is_lower('z') && !char_is_lower('Z'));
  CHECK(char_to_upper('a') == 'A' && char_to_upper('A') == 'A' &&
        char_to_upper('5') == '5');
  CHECK(char_to_lower('Z') == 'z' && char_to_lower('z') == 'z');
}

internal void test_slice2(void) {
  String8 s = str8_lit("abcdef");
  CHECK(EQ(str8_postfix(s, 2), "ef"));
  CHECK(EQ(str8_postfix(s, 99), "abcdef"));  // clamp
  CHECK(EQ(str8_chop(s, 2), "abcd"));
  CHECK(str8_chop(s, 99).size == 0);  // clamp
  CHECK(EQ(str8_substr(s, 1, 4), "bcd"));
  CHECK(EQ(str8_substr(s, 4, 2), ""));       // max<min -> empty
  CHECK(EQ(str8_substr(s, 2, 99), "cdef"));  // clamp max
}

internal void test_rsearch(void) {
  U64 i = 999;
  CHECK(str8_rindex_of(str8_lit("a,b,c"), ',', &i) && i == 3);
  CHECK(!str8_rindex_of(str8_lit("abc"), ',', &i));
  CHECK(str8_rfind(str8_lit("a.b.c"), str8_lit(".")) == 3);
  CHECK(str8_rfind(str8_lit("hello"), str8_lit("l")) == 3);
  CHECK(str8_rfind(str8_lit("hello"), str8_lit("xyz")) == -1);
  CHECK(str8_find_ci(str8_lit("Gzip, Chunked"), str8_lit("chunked")) == 6);
  CHECK(str8_find_ci(str8_lit("GZIP"), str8_lit("zip")) == 1);
  CHECK(str8_find_ci(str8_lit("abc"), str8_lit("xyz")) == -1);
  CHECK(str8_contains_ci(str8_lit("Transfer: CHUNKED"), str8_lit("chunked")));
  CHECK(!str8_contains_ci(str8_lit("gzip"), str8_lit("br")));
}

internal void test_path(void) {
  CHECK(EQ(str8_skip_last_slash(str8_lit("/a/b/c.json")), "c.json"));
  CHECK(EQ(str8_chop_last_slash(str8_lit("/a/b/c.json")), "/a/b"));
  CHECK(EQ(str8_skip_last_slash(str8_lit("noslash")),
           "noslash"));  // whole if none
  CHECK(EQ(str8_skip_last_dot(str8_lit("file.tar.gz")), "gz"));
  CHECK(EQ(str8_chop_last_dot(str8_lit("file.tar.gz")), "file.tar"));
  CHECK(EQ(str8_skip_last_dot(str8_lit("nodot")), "nodot"));  // whole if none
}

internal void test_split_line(Arena *a) {
  String8List l = str8_split(a, str8_lit("a,b,c"), ',');
  CHECK(l.node_count == 3 && EQ(str8_list_join(a, &l, str8_lit("|")), "a|b|c"));
  l = str8_split(a, str8_lit(",a,,b,"), ',');  // empties dropped
  CHECK(l.node_count == 2 && EQ(str8_list_join(a, &l, str8_lit("|")), "a|b"));
  l = str8_split(a, str8_lit("solo"), ',');
  CHECK(l.node_count == 1 && EQ(l.first->string, "solo"));
  l = str8_split(a, str8_zero(), ',');
  CHECK(l.node_count == 0);

  String8 text = str8_lit("one\r\ntwo\nthree");
  CHECK(EQ(str8_chop_line(&text), "one") && EQ(text, "two\nthree"));
  CHECK(EQ(str8_chop_line(&text), "two") && EQ(text, "three"));
  CHECK(EQ(str8_chop_line(&text), "three") && text.size == 0);
}

internal void test_from_u64(Arena *a) {
  CHECK(EQ(str8_from_u64(a, 0, 10, 0), "0"));
  CHECK(EQ(str8_from_u64(a, 12345, 10, 0), "12345"));
  CHECK(EQ(str8_from_u64(a, 255, 16, 0), "ff"));
  CHECK(EQ(str8_from_u64(a, 255, 16, 4), "00ff"));  // zero-pad
  CHECK(EQ(str8_from_u64(a, 5, 10, 3), "005"));
  CHECK(EQ(str8_from_u64(a, 10, 2, 0), "1010"));  // binary
}

int main(void) {
  Arena *a = arena_alloc();
  test_take_trim();
  test_chop_lr();
  test_search();
  test_chop_delim();
  test_while_parse();
  test_fmt();
  test_charclass();
  test_slice2();
  test_rsearch();
  test_path();
  test_split_line(a);
  test_from_u64(a);
  arena_release(a);
  fprintf(stderr, "[str8_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
