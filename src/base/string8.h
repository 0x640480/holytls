// String8 — a length + pointer string (NOT NUL-terminated). The holytls string
// type throughout; whether the bytes are "owned" depends on whether the view
// points into an arena (push_str8_copy / push_str8_cat) or borrows external
// memory. String8List is the join-friendly form used by the fingerprint code.
#ifndef HOLYTLS_STRING8_H
#define HOLYTLS_STRING8_H

#include "base/arena.h"
#include "base/base.h"

typedef struct String8 String8;
struct String8 {
  U8 *str;
  U64 size;
};

typedef struct String8Node String8Node;
struct String8Node {
  String8Node *next;
  String8 string;
};

typedef struct String8List String8List;
struct String8List {
  String8Node *first;
  String8Node *last;
  U64 node_count;
  U64 total_size;
};

//- construction
internal inline String8 str8(U8 *str, U64 size) {
  String8 r = {str, size};
  return r;
}
#define str8_lit(s) str8((U8 *)(s), sizeof(s) - 1)
#define str8_zero() str8(0, 0)
String8 str8_cstring(const char *c);
String8 str8_range(U8 *first, U8 *one_past_last);

//- predicates
B32 str8_match(String8 a, String8 b);     // exact
B32 str8_match_ci(String8 a, String8 b);  // ASCII case-insensitive
B32 str8_starts_with(String8 s, String8 prefix);
B32 str8_ends_with(String8 s, String8 suffix);
internal inline B32 ascii_is_space(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' ||
         c == '\f';
}

//- char classification / conversion (ASCII)
internal inline B32 char_is_digit(U8 c) { return c >= '0' && c <= '9'; }
internal inline B32 char_is_upper(U8 c) { return c >= 'A' && c <= 'Z'; }
internal inline B32 char_is_lower(U8 c) { return c >= 'a' && c <= 'z'; }
internal inline B32 char_is_alpha(U8 c) {
  return char_is_upper(c) || char_is_lower(c);
}
internal inline B32 char_is_alnum(U8 c) {
  return char_is_alpha(c) || char_is_digit(c);
}
internal inline B32 char_is_hex(U8 c) {
  return char_is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
internal inline U8 char_to_upper(U8 c) {
  return char_is_lower(c) ? (U8)(c - 32) : c;
}
internal inline U8 char_to_lower(U8 c) {
  return char_is_upper(c) ? (U8)(c + 32) : c;
}
// Lowercase hex digit for the low nibble of `v` (high bits ignored, so callers
// can pass `byte >> 4` / `byte & 0xf` or a `% radix` remainder for radix <=
// 16).
internal inline char hex_digit_lower(U8 v) {
  return "0123456789abcdef"[v & 0xf];
}
// Lowercase-hex-encode `n` bytes into `out`, writing exactly 2*n chars and no
// NUL terminator. Shared by the hash/id formatters (JA4/MD5 digests, session
// ids) that previously hand-rolled this loop.
void hex_encode(U8 *out, const U8 *bytes, U64 n);

//- view operations (tsoding sv.h-style; all non-allocating, return sub-views)

// take/drop the first n bytes (clamped), non-mutating.
internal inline String8 str8_prefix(String8 s, U64 n) {
  return str8(s.str, n < s.size ? n : s.size);
}
internal inline String8 str8_skip(String8 s, U64 n) {
  if (n > s.size) n = s.size;
  return str8(s.str + n, s.size - n);
}
internal inline String8 str8_postfix(String8 s, U64 n) {  // last n (clamped)
  if (n > s.size) n = s.size;
  return str8(s.str + (s.size - n), n);
}
internal inline String8 str8_chop(String8 s,
                                  U64 n) {  // drop last n (non-mutating)
  if (n > s.size) n = s.size;
  return str8(s.str, s.size - n);
}
internal inline String8 str8_substr(String8 s, U64 min,
                                    U64 max) {  // [min, max)
  if (min > s.size) min = s.size;
  if (max > s.size) max = s.size;
  if (max < min) max = min;
  return str8(s.str + min, max - min);
}

// trim ASCII whitespace from the left / right / both.
internal inline String8 str8_trim_left(String8 s) {
  U64 i = 0;
  while (i < s.size && ascii_is_space((char)s.str[i])) ++i;
  return str8(s.str + i, s.size - i);
}
internal inline String8 str8_trim_right(String8 s) {
  U64 n = s.size;
  while (n > 0 && ascii_is_space((char)s.str[n - 1])) --n;
  return str8(s.str, n);
}
internal inline String8 str8_trim(String8 s) {
  return str8_trim_left(str8_trim_right(s));
}

// take the first / last n bytes (clamped) AND advance/shrink *s past them.
internal inline String8 str8_chop_left(String8 *s, U64 n) {
  if (n > s->size) n = s->size;
  String8 head = str8(s->str, n);
  *s = str8(s->str + n, s->size - n);
  return head;
}
internal inline String8 str8_chop_right(String8 *s, U64 n) {
  if (n > s->size) n = s->size;
  String8 tail = str8(s->str + (s->size - n), n);
  *s = str8(s->str, s->size - n);
  return tail;
}

// first byte == c -> true (+ optional index). Substring search (offset / -1).
internal inline B32 str8_index_of(String8 s, U8 c, U64 *out_index) {
  for (U64 i = 0; i < s.size; ++i)
    if (s.str[i] == c) {
      if (out_index) *out_index = i;
      return 1;
    }
  return 0;
}
S64 str8_find(String8 hay, String8 needle);
internal inline B32 str8_contains(String8 hay, String8 needle) {
  return str8_find(hay, needle) >= 0;
}
// last byte == c (+ optional index); last substring (offset / -1);
// case-insensitive substring (offset / -1).
internal inline B32 str8_rindex_of(String8 s, U8 c, U64 *out_index) {
  for (U64 i = s.size; i > 0; --i)
    if (s.str[i - 1] == c) {
      if (out_index) *out_index = i - 1;
      return 1;
    }
  return 0;
}
S64 str8_rfind(String8 hay, String8 needle);
S64 str8_find_ci(String8 hay, String8 needle);
internal inline B32 str8_contains_ci(String8 hay, String8 needle) {
  return str8_find_ci(hay, needle) >= 0;
}

// path-ish helpers: split around the LAST '/' or '.' (whole string if absent).
internal inline String8 str8_skip_last_slash(String8 s) {
  U64 i;
  return str8_rindex_of(s, '/', &i) ? str8_skip(s, i + 1) : s;
}
internal inline String8 str8_chop_last_slash(String8 s) {
  U64 i;
  return str8_rindex_of(s, '/', &i) ? str8_prefix(s, i) : s;
}
internal inline String8 str8_skip_last_dot(String8 s) {
  U64 i;
  return str8_rindex_of(s, '.', &i) ? str8_skip(s, i + 1) : s;
}
internal inline String8 str8_chop_last_dot(String8 s) {
  U64 i;
  return str8_rindex_of(s, '.', &i) ? str8_prefix(s, i) : s;
}

// split off the head up to `delim` (or `delim` substring), advancing *s past
// it. If the delimiter is absent, the head is the whole string and *s becomes
// empty.
String8 str8_chop_by_delim(String8 *s, U8 delim);
String8 str8_chop_by_str(String8 *s, String8 delim);
// like str8_chop_by_delim but only consumes when the delimiter is present.
B32 str8_try_chop_by_delim(String8 *s, U8 delim, String8 *out_chunk);
// longest prefix satisfying pred (non-mutating / mutating-advance forms).
String8 str8_take_left_while(String8 s, B32 (*pred)(U8));
String8 str8_chop_left_while(String8 *s, B32 (*pred)(U8));

// parse leading ASCII digits as a u64 (saturates on overflow). _chop also
// advances *s past the digits consumed.
U64 str8_to_u64(String8 s);
U64 str8_chop_u64(String8 *s);
// format `value` in `radix` (2..16, lowercase hex), zero-padded to
// `min_digits`.
String8 str8_from_u64(Arena *arena, U64 value, U32 radix, U8 min_digits);

// split on `delim` into a String8List of the (non-empty) tokens.
String8List str8_split(Arena *arena, String8 s, U8 delim);
// pop the first line (up to '\n'); strips a trailing '\r'; advances *s past
// '\n'.
String8 str8_chop_line(String8 *s);

// printf integration: printf("ja4=" STR8_Fmt "\n", STR8_Arg(my_str8))
#define STR8_Fmt "%.*s"
#define STR8_Arg(s) (int)(s).size, (s).str

//- arena-owned copies / building
String8 push_str8_copy(Arena *arena, String8 s);
String8 push_str8_cat(Arena *arena, String8 a, String8 b);
String8 push_str8f(Arena *arena, const char *fmt, ...);
char *push_str8_cstr(Arena *arena, String8 s);  // NUL-terminated for C APIs

//- list building + join (fingerprint strings)
void str8_list_push(Arena *arena, String8List *list, String8 s);
void str8_list_pushf(Arena *arena, String8List *list, const char *fmt, ...);
String8 str8_list_join(Arena *arena, String8List *list, String8 sep);

#endif  // HOLYTLS_STRING8_H
