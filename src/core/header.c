#include "core/header.h"

void header_list_init(HeaderList *list, Arena *arena) {
  list->v = 0;
  list->count = 0;
  list->cap = 0;
  list->arena = arena;
}

void header_list_push(HeaderList *list, String8 name, String8 value, U8 flags) {
  if (list->count == list->cap) {
    U64 newcap = list->cap ? list->cap * 2 : 8;
    Header *nv = push_array_no_zero(list->arena, Header, newcap);
    if (list->count) MemoryCopy(nv, list->v, list->count * sizeof(Header));
    list->v = nv;
    list->cap = newcap;
  }
  list->v[list->count].name = name;
  list->v[list->count].value = value;
  list->v[list->count].flags = flags;
  list->count += 1;
}

String8 *header_list_get_ci(HeaderList *list, String8 name) {
  for (U64 i = 0; i < list->count; ++i)
    if (str8_match_ci(list->v[i].name, name)) return &list->v[i].value;
  return 0;
}

B32 header_list_has_ci(HeaderList *list, String8 name) {
  return header_list_get_ci(list, name) != 0;
}

U64 cookie_crumbs(String8 value, String8 *out, U64 cap) {
  U64 n = 0;
  String8 rest = value;
  for (;;) {
    S64 at = str8_find(rest, str8_lit("; "));
    String8 crumb = (at < 0) ? rest : str8_prefix(rest, (U64)at);
    if (crumb.size) {
      if (n < cap) out[n] = crumb;
      n += 1;
    }
    if (at < 0) break;
    rest = str8_skip(rest, (U64)at + 2);  // past "; "
  }
  return n;
}
