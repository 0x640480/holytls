// json — the project-wide JSON surface, a thin arena-backed wrapper over yyjson.
// The standard is the arena allocator: every parse/build allocates from an Arena, so
// documents (and the String8 views into them) live until the arena is released — no
// yyjson_doc_free, no per-doc cleanup. Used for response parsing today; the canonical
// place for any JSON the library grows later.
#ifndef HOLYTLS_JSON_H
#define HOLYTLS_JSON_H

#include <yyjson.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

// An arena-backed yyjson allocator: malloc -> arena_push, realloc -> new+copy, free ->
// no-op (bulk-freed with the arena). The project-standard JSON allocator.
yyjson_alc json_arena_alc(Arena *arena);

// Parse a read-only, not-necessarily-NUL-terminated JSON buffer into a doc that lives
// in `arena`. Returns 0 on parse error.
yyjson_doc *json_parse(Arena *arena, String8 src);
internal inline yyjson_val *json_root(yyjson_doc *doc) {
  return yyjson_doc_get_root(doc);
}

// String value of object field `key` (or JSON-pointer `ptr`, e.g. "/a/b") as a String8
// view INTO the doc (valid until the arena releases). {0,0} if missing / not a string.
String8 json_obj_str(yyjson_val *obj, const char *key);
String8 json_ptr_str(yyjson_doc *doc, const char *ptr);

// One-shot: parse `src` (scratch arena) and copy the root object's string field `key`
// into `out` (NUL-terminated, truncated to cap-1). Returns false if absent / not a
// string. The common "extract a field into a fixed buffer" case.
B32 json_get_str(String8 src, const char *key, char *out, U64 cap);

// Serialization (arena-backed): a fresh mutable doc, then write it to an arena String8.
yyjson_mut_doc *json_mut(Arena *arena);
String8 json_mut_write(Arena *arena, yyjson_mut_doc *doc, B32 pretty);

#endif  // HOLYTLS_JSON_H
