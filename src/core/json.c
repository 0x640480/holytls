#include "core/json.h"

// yyjson custom allocator backed by an Arena. yyjson stores no size metadata of its
// own, so realloc allocates fresh and copies the old payload (the arena can't grow in
// place); the old block is abandoned in the arena and reclaimed in bulk on release.
internal void *json_alc_malloc(void *ctx, size_t size) {
  return arena_push((Arena *)ctx, (U64)size, 16);
}
internal void *json_alc_realloc(void *ctx, void *ptr, size_t old_size, size_t size) {
  void *n = arena_push((Arena *)ctx, (U64)size, 16);
  if (ptr && old_size) MemoryCopy(n, ptr, old_size < size ? old_size : size);
  return n;
}
internal void json_alc_free(void *ctx, void *ptr) {
  (void)ctx;
  (void)ptr;
}

yyjson_alc json_arena_alc(Arena *arena) {
  yyjson_alc alc;
  alc.malloc = json_alc_malloc;
  alc.realloc = json_alc_realloc;
  alc.free = json_alc_free;
  alc.ctx = arena;
  return alc;
}

yyjson_doc *json_parse(Arena *arena, String8 src) {
  yyjson_alc alc = json_arena_alc(arena);
  // No INSITU flag -> the input buffer is read, not modified (safe for read-only,
  // non-NUL-terminated HTTP bodies).
  return yyjson_read_opts((char *)src.str, (size_t)src.size, 0, &alc, 0);
}

String8 json_obj_str(yyjson_val *obj, const char *key) {
  yyjson_val *v = yyjson_obj_get(obj, key);
  if (!v || !yyjson_is_str(v)) return str8_zero();
  return str8((U8 *)yyjson_get_str(v), (U64)yyjson_get_len(v));
}

String8 json_ptr_str(yyjson_doc *doc, const char *ptr) {
  yyjson_val *v = yyjson_doc_ptr_get(doc, ptr);
  if (!v || !yyjson_is_str(v)) return str8_zero();
  return str8((U8 *)yyjson_get_str(v), (U64)yyjson_get_len(v));
}

B32 json_get_str(String8 src, const char *key, char *out, U64 cap) {
  if (!out || cap == 0) return 0;
  out[0] = 0;
  Temp scr = scratch_begin(0, 0);
  B32 ok = 0;
  yyjson_doc *doc = json_parse(scr.arena, src);
  if (doc) {
    yyjson_val *v = yyjson_obj_get(yyjson_doc_get_root(doc), key);
    if (v && yyjson_is_str(v)) {
      U64 n = (U64)yyjson_get_len(v);
      if (n > cap - 1) n = cap - 1;
      MemoryCopy(out, yyjson_get_str(v), n);
      out[n] = 0;
      ok = 1;
    }
  }
  scratch_end(scr);
  return ok;
}

yyjson_mut_doc *json_mut(Arena *arena) {
  yyjson_alc alc = json_arena_alc(arena);
  return yyjson_mut_doc_new(&alc);
}

String8 json_mut_write(Arena *arena, yyjson_mut_doc *doc, B32 pretty) {
  yyjson_alc alc = json_arena_alc(arena);
  yyjson_write_flag flag = pretty ? YYJSON_WRITE_PRETTY : YYJSON_WRITE_NOFLAG;
  size_t len = 0;
  char *s = yyjson_mut_write_opts(doc, flag, &alc, &len, 0);
  if (!s) return str8_zero();
  return str8((U8 *)s, (U64)len);
}
