// Base-layer test: arena (push / alignment / pos-pop reuse / oversize /
// scratch) and String8 (copy / cat / match / join / cstr / printf).
#include "base/base.h"

#include "base/arena.h"
#include "base/string8.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

int main(void) {
  //- arena: basic + non-overlap
  Arena *a = arena_alloc_sized(256);
  void *p1 = arena_push(a, 10, 8);
  void *p2 = arena_push(a, 10, 8);
  CHECK(p1 && p2 && p1 != p2);
  CHECK((U64)(uintptr_t)p2 >= (U64)(uintptr_t)p1 + 10);

  //- arena: arbitrary alignment
  arena_push(a, 1, 1);  // misalign
  for (U64 al = 2; al <= 64; al <<= 1) {
    void *p = arena_push(a, 7, al);
    CHECK(((U64)(uintptr_t)p & (al - 1)) == 0);
  }

  //- arena: pos/pop reuses memory
  U64 pos = arena_pos(a);
  void *x = arena_push(a, 64, 16);
  arena_pop_to(a, pos);
  void *y = arena_push(a, 64, 16);
  CHECK(x == y);

  //- arena: oversize allocation gets its own block
  Arena *b = arena_alloc_sized(64);
  U8 *big = (U8 *)arena_push(b, 4096, 1);
  MemoryZero(big, 4096);
  big[4095] = 0xAB;
  CHECK(big[4095] == 0xAB);
  CHECK(arena_push(b, 8, 1) != 0);
  arena_release(b);

  //- arena: zeroing push_array + scratch
  Temp t = scratch_begin(0, 0);
  U8 *s = push_array(t.arena, U8, 100);
  CHECK(s[0] == 0 && s[99] == 0);
  scratch_end(t);

  //- string8: copy / empty / match / starts_with / cstr
  String8 hello = push_str8_copy(a, str8_lit("Hello-World"));
  CHECK(str8_match(hello, str8_lit("Hello-World")));
  CHECK(hello.str != 0);
  String8 empty = push_str8_copy(a, str8_zero());
  CHECK(empty.size == 0 && empty.str != 0);  // non-null zero-length
  CHECK(str8_match_ci(str8_lit("ABC"), str8_lit("abc")));
  CHECK(!str8_match(str8_lit("ABC"), str8_lit("abc")));
  CHECK(
      str8_starts_with(str8_lit("application/json"), str8_lit("application/")));
  char *c = push_str8_cstr(a, str8_lit("h2"));
  CHECK(strcmp(c, "h2") == 0);

  //- string8: cat / list join / printf
  String8 cat = push_str8_cat(a, str8_lit("ab"), str8_lit("cd"));
  CHECK(str8_match(cat, str8_lit("abcd")));
  String8List list = {0};
  str8_list_push(a, &list, str8_lit("a"));
  str8_list_push(a, &list, str8_lit("b"));
  str8_list_push(a, &list, str8_lit("cd"));
  String8 joined = str8_list_join(a, &list, str8_lit("-"));
  CHECK(str8_match(joined, str8_lit("a-b-cd")));
  String8 f = push_str8f(a, "%d-%s", 42, "x");
  CHECK(str8_match(f, str8_lit("42-x")));

  arena_release(a);
  fprintf(stderr, "[base_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
