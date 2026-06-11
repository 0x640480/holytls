#include "base/string8.h"

String8 str8_cstring(const char *c) {
  return str8((U8 *)c, c ? (U64)strlen(c) : 0);
}

String8 str8_range(U8 *first, U8 *one_past_last) {
  return str8(first, (U64)(one_past_last - first));
}

char ascii_lower(char c) {
  return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

B32 str8_match(String8 a, String8 b) {
  return a.size == b.size && (a.size == 0 || MemoryCompare(a.str, b.str, a.size) == 0);
}

B32 str8_match_ci(String8 a, String8 b) {
  if (a.size != b.size) return 0;
  for (U64 i = 0; i < a.size; ++i)
    if (ascii_lower((char)a.str[i]) != ascii_lower((char)b.str[i])) return 0;
  return 1;
}

B32 str8_starts_with(String8 s, String8 prefix) {
  return s.size >= prefix.size &&
         MemoryCompare(s.str, prefix.str, prefix.size) == 0;
}

B32 str8_ends_with(String8 s, String8 suffix) {
  return s.size >= suffix.size &&
         MemoryCompare(s.str + (s.size - suffix.size), suffix.str,
                       suffix.size) == 0;
}

//- view operations (tsoding sv.h-style)

S64 str8_find(String8 hay, String8 needle) {
  if (needle.size == 0) return 0;
  if (needle.size > hay.size) return -1;
  for (U64 i = 0; i + needle.size <= hay.size; ++i)
    if (MemoryCompare(hay.str + i, needle.str, needle.size) == 0) return (S64)i;
  return -1;
}

String8 str8_chop_by_delim(String8 *s, U8 delim) {
  U64 i = 0;
  while (i < s->size && s->str[i] != delim) ++i;
  String8 head = str8(s->str, i);
  if (i < s->size) ++i;  // consume the delimiter
  *s = str8(s->str + i, s->size - i);
  return head;
}

String8 str8_chop_by_str(String8 *s, String8 delim) {
  S64 idx = str8_find(*s, delim);
  if (idx < 0) {  // absent: head is everything, *s becomes empty
    String8 head = *s;
    *s = str8(s->str + s->size, 0);
    return head;
  }
  String8 head = str8(s->str, (U64)idx);
  U64 adv = (U64)idx + delim.size;
  *s = str8(s->str + adv, s->size - adv);
  return head;
}

B32 str8_try_chop_by_delim(String8 *s, U8 delim, String8 *out_chunk) {
  U64 idx;
  if (!str8_index_of(*s, delim, &idx)) return 0;
  *out_chunk = str8(s->str, idx);
  *s = str8(s->str + idx + 1, s->size - idx - 1);
  return 1;
}

String8 str8_take_left_while(String8 s, B32 (*pred)(U8)) {
  U64 i = 0;
  while (i < s.size && pred(s.str[i])) ++i;
  return str8(s.str, i);
}

String8 str8_chop_left_while(String8 *s, B32 (*pred)(U8)) {
  String8 head = str8_take_left_while(*s, pred);
  *s = str8(s->str + head.size, s->size - head.size);
  return head;
}

U64 str8_to_u64(String8 s) {
  U64 r = 0;
  for (U64 i = 0; i < s.size; ++i) {
    char c = (char)s.str[i];
    if (c < '0' || c > '9') break;
    U64 d = (U64)(c - '0');
    if (r > (~(U64)0 - d) / 10) return ~(U64)0;  // saturate (no wrap)
    r = r * 10 + d;
  }
  return r;
}

U64 str8_chop_u64(String8 *s) {
  U64 i = 0, r = 0;
  while (i < s->size && s->str[i] >= '0' && s->str[i] <= '9') {
    U64 d = (U64)(s->str[i] - '0');
    r = (r > (~(U64)0 - d) / 10) ? ~(U64)0 : r * 10 + d;
    ++i;
  }
  *s = str8(s->str + i, s->size - i);
  return r;
}

S64 str8_rfind(String8 hay, String8 needle) {
  if (needle.size == 0) return (S64)hay.size;  // empty matches at the end
  if (needle.size > hay.size) return -1;
  for (S64 i = (S64)(hay.size - needle.size); i >= 0; --i)
    if (MemoryCompare(hay.str + i, needle.str, needle.size) == 0) return i;
  return -1;
}

S64 str8_find_ci(String8 hay, String8 needle) {
  if (needle.size == 0) return 0;
  if (needle.size > hay.size) return -1;
  for (U64 i = 0; i + needle.size <= hay.size; ++i) {
    U64 j = 0;
    while (j < needle.size &&
           ascii_lower((char)hay.str[i + j]) == ascii_lower((char)needle.str[j]))
      ++j;
    if (j == needle.size) return (S64)i;
  }
  return -1;
}

String8 str8_from_u64(Arena *arena, U64 value, U32 radix, U8 min_digits) {
  if (radix < 2 || radix > 16) radix = 10;
  char tmp[64];  // u64 in base 2 is at most 64 digits
  U64 n = 0;
  do {
    tmp[n++] = "0123456789abcdef"[value % radix];
    value /= radix;
  } while (value && n < sizeof tmp);
  while (n < min_digits && n < sizeof tmp) tmp[n++] = '0';
  U8 *d = push_array_no_zero(arena, U8, n);
  for (U64 i = 0; i < n; ++i) d[i] = (U8)tmp[n - 1 - i];  // reverse (LSB-first)
  return str8(d, n);
}

String8List str8_split(Arena *arena, String8 s, U8 delim) {
  String8List list = {0};
  String8 rem = s;
  while (rem.size) {
    String8 tok = str8_chop_by_delim(&rem, delim);
    if (tok.size) str8_list_push(arena, &list, tok);  // drop empties
  }
  return list;
}

String8 str8_chop_line(String8 *s) {
  U64 i = 0;
  while (i < s->size && s->str[i] != '\n') ++i;
  String8 line = str8(s->str, i);
  if (line.size && line.str[line.size - 1] == '\r') line.size -= 1;  // CRLF
  if (i < s->size) ++i;  // consume the '\n'
  *s = str8(s->str + i, s->size - i);
  return line;
}

String8 push_str8_copy(Arena *arena, String8 s) {
  // Empty input -> a non-null zero-length view, so consumers that hand the
  // pointer to C APIs (nghttp2 etc.) never see null.
  if (s.size == 0) return str8((U8 *)"", 0);
  U8 *d = push_array_no_zero(arena, U8, s.size);
  MemoryCopy(d, s.str, s.size);
  return str8(d, s.size);
}

String8 push_str8_cat(Arena *arena, String8 a, String8 b) {
  U8 *d = push_array_no_zero(arena, U8, a.size + b.size);
  MemoryCopy(d, a.str, a.size);
  MemoryCopy(d + a.size, b.str, b.size);
  return str8(d, a.size + b.size);
}

char *push_str8_cstr(Arena *arena, String8 s) {
  char *d = push_array_no_zero(arena, char, s.size + 1);
  if (s.size) MemoryCopy(d, s.str, s.size);
  d[s.size] = 0;
  return d;
}

internal String8 push_str8fv(Arena *arena, const char *fmt, va_list args) {
  va_list args2;
  va_copy(args2, args);
  int n = vsnprintf(0, 0, fmt, args);
  String8 r = str8_zero();
  if (n >= 0) {
    U8 *d = push_array_no_zero(arena, U8, (U64)n + 1);
    vsnprintf((char *)d, (size_t)n + 1, fmt, args2);
    r = str8(d, (U64)n);
  }
  va_end(args2);
  return r;
}

String8 push_str8f(Arena *arena, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  String8 r = push_str8fv(arena, fmt, args);
  va_end(args);
  return r;
}

void str8_list_push(Arena *arena, String8List *list, String8 s) {
  String8Node *node = push_struct(arena, String8Node);
  node->string = s;
  SLLQueuePush(list->first, list->last, node);
  list->node_count += 1;
  list->total_size += s.size;
}

void str8_list_pushf(Arena *arena, String8List *list, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  String8 s = push_str8fv(arena, fmt, args);
  va_end(args);
  str8_list_push(arena, list, s);
}

String8 str8_list_join(Arena *arena, String8List *list, String8 sep) {
  U64 sep_total = list->node_count > 1 ? sep.size * (list->node_count - 1) : 0;
  U64 total = list->total_size + sep_total;
  U8 *d = push_array_no_zero(arena, U8, total + 1);  // +1: always NUL-safe
  U64 off = 0;
  for (String8Node *n = list->first; n; n = n->next) {
    if (off != 0 && sep.size) {
      MemoryCopy(d + off, sep.str, sep.size);
      off += sep.size;
    }
    MemoryCopy(d + off, n->string.str, n->string.size);
    off += n->string.size;
  }
  d[total] = 0;
  return str8(d, total);
}
