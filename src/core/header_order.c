#include "core/header_order.h"

void build_ordered_headers(Arena *arena, const DefaultHeader *defaults,
                           U64 default_count, const Header *caller,
                           U64 caller_count, HeaderList *out) {
  // 1) Defaults in order; a caller header of the same name overrides the value
  //    in place. Order-only placeholders (empty value, none supplied) drop out.
  for (U64 i = 0; i < default_count; ++i) {
    String8 name = str8_cstring(defaults[i].name);   // static literal (stable)
    String8 value = str8_cstring(defaults[i].value);  // static literal (stable)
    B32 overridden = 0;
    for (U64 j = 0; j < caller_count; ++j)
      if (str8_match_ci(caller[j].name, name)) {
        value = caller[j].value;  // caller's transient bytes
        overridden = 1;
        break;
      }
    if (value.size)
      // The default name is a process-static view (no copy needed); copy the
      // value only when it came from the caller's transient array.
      header_list_push(out, name, overridden ? push_str8_copy(arena, value) : value,
                       0);
  }
  // 2) Caller-only headers (not matching any default name), appended in order.
  //    An empty value omits the header (consistent with the default slots).
  for (U64 j = 0; j < caller_count; ++j) {
    if (caller[j].value.size == 0) continue;
    B32 is_default = 0;
    for (U64 i = 0; i < default_count; ++i)
      if (str8_match_ci(caller[j].name, str8_cstring(defaults[i].name))) {
        is_default = 1;
        break;
      }
    if (!is_default)
      header_list_push(out, push_str8_copy(arena, caller[j].name),
                       push_str8_copy(arena, caller[j].value), 0);
  }
}

void reorder_headers(Arena *arena, HeaderList *list, const String8 *order,
                     U64 order_count) {
  if (order_count == 0 || list->count == 0) return;
  U64 n = list->count;
  Header *out = push_array_no_zero(arena, Header, n);
  B32 *used = push_array(arena, B32, n);  // zeroed
  U64 k = 0;
  // Listed names first, in order; each name claims the first not-yet-placed match.
  for (U64 o = 0; o < order_count; ++o)
    for (U64 i = 0; i < n; ++i)
      if (!used[i] && str8_match_ci(list->v[i].name, order[o])) {
        out[k++] = list->v[i];
        used[i] = 1;
        break;
      }
  // Then everything not named in `order`, keeping its original relative order.
  for (U64 i = 0; i < n; ++i)
    if (!used[i]) out[k++] = list->v[i];
  MemoryCopy(list->v, out, n * sizeof(Header));  // k == n; same backing storage
}
