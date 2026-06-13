// Offline gate for the yyjson wrapper (src/core/json): arena-backed parse +
// String8 field access (object key + JSON pointer), the one-shot copy-out
// helper, edge cases (missing key, non-string field, malformed input,
// non-NUL-terminated buffer), and a build->serialize->reparse round-trip for
// the writer side.
#include "core/json.h"

#include <stdio.h>
#include <string.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal void test_parse(Arena *a) {
  // A browserleaks-shaped body, deliberately NOT NUL-terminated: embed it in a
  // larger buffer and hand json_parse only the JSON slice.
  char buf[256];
  const char *json =
      "{\"ja4\":\"t13d1516h2\",\"n\":5,\"nested\":{\"k\":\"v\"},"
      "\"empty\":\"\",\"num_field\":42}TRAILINGGARBAGE";
  U64 jlen = (U64)(strstr(json, "TRAILING") - json);
  MemoryCopy(buf, json,
             (U64)strlen(json));  // buf is not NUL-terminated at jlen
  String8 body = str8((U8 *)buf, jlen);

  yyjson_doc *doc = json_parse(a, body);
  CHECK(doc != 0);
  yyjson_val *root = json_root(doc);
  CHECK(str8_match(json_obj_str(root, "ja4"), str8_lit("t13d1516h2")));
  // Nested via JSON pointer.
  CHECK(str8_match(json_ptr_str(doc, "/nested/k"), str8_lit("v")));
  // Empty-string field is a string (distinct from missing): str.str != 0, size
  // 0.
  String8 empty = json_obj_str(root, "empty");
  CHECK(empty.str != 0 && empty.size == 0);
  // Missing key / non-string field -> {0,0}.
  CHECK(json_obj_str(root, "absent").str == 0);
  CHECK(json_obj_str(root, "num_field").str == 0);  // a number, not a string
}

internal void test_malformed(Arena *a) {
  CHECK(json_parse(a, str8_lit("{not valid json")) == 0);
  CHECK(json_parse(a, str8_lit("")) == 0);
}

internal void test_get_str(void) {
  String8 body = str8_lit("{\"ja4\":\"abc\",\"akamai_hash\":\"deadbeef\"}");
  char out[64];
  CHECK(json_get_str(body, "ja4", out, sizeof out) && strcmp(out, "abc") == 0);
  CHECK(json_get_str(body, "akamai_hash", out, sizeof out) &&
        strcmp(out, "deadbeef") == 0);
  // Absent -> false, out cleared.
  CHECK(!json_get_str(body, "nope", out, sizeof out) && out[0] == 0);
  // Truncation to cap-1.
  char small[4];
  CHECK(json_get_str(body, "akamai_hash", small, sizeof small) &&
        strcmp(small, "dea") == 0);
}

internal void test_serialize(Arena *a) {
  // Build {"ja4":"abc","n":5}, serialize, reparse, verify.
  yyjson_mut_doc *doc = json_mut(a);
  yyjson_mut_val *root = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, root);
  yyjson_mut_obj_add_strcpy(doc, root, "ja4", "abc");
  yyjson_mut_obj_add_int(doc, root, "n", 5);

  String8 out = json_mut_write(a, doc, /*pretty=*/0);
  CHECK(out.size > 0);
  CHECK(str8_match(out, str8_lit("{\"ja4\":\"abc\",\"n\":5}")));

  yyjson_doc *re = json_parse(a, out);
  CHECK(re != 0);
  CHECK(str8_match(json_obj_str(json_root(re), "ja4"), str8_lit("abc")));
  CHECK(yyjson_get_int(yyjson_obj_get(json_root(re), "n")) == 5);
}

int main(void) {
  Arena *a = arena_alloc();
  test_parse(a);
  test_malformed(a);
  test_get_str();
  test_serialize(a);
  arena_release(a);
  fprintf(stderr, "[json_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
