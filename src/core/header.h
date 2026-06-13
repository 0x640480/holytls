// Header — an ordered request/response header. Insertion order and original
// case are part of the fingerprint, so HeaderList is an array (not a hash map);
// lookups are linear (header counts are tiny). Arena-backed, grows by
// reallocate
// + copy (the old storage is abandoned and reclaimed on arena reset/release).
#ifndef HOLYTLS_HEADER_H
#define HOLYTLS_HEADER_H

#include "base/arena.h"
#include "base/string8.h"

typedef struct Header Header;
struct Header {
  String8 name;  // original case preserved
  String8 value;
  U8 flags;
};

// Convenience: a Header from C string literals (flags 0). Block-scope only (the
// String8s are built by the inline str8(), not a constant expression). Works in
// an array initializer or as an argument:
//   Header h[] = { header_lit("accept", "*/*"), header_lit("user-agent", ua) };
#define header_lit(name, value) ((Header){str8_lit(name), str8_lit(value), 0})

typedef struct HeaderList HeaderList;
struct HeaderList {
  Header *v;
  U64 count;
  U64 cap;
  Arena *arena;
};

void header_list_init(HeaderList *list, Arena *arena);
void header_list_push(HeaderList *list, String8 name, String8 value, U8 flags);
// Returns a pointer to the first case-insensitive match's value, or 0.
String8 *header_list_get_ci(HeaderList *list, String8 name);
B32 header_list_has_ci(HeaderList *list, String8 name);

// Split a Cookie header value ("a=1; b=2; c=3") into its crumbs ("a=1","b=2",
// "c=3"), as views into `value`. HTTP/2 and HTTP/3 emit one header field per
// crumb (Chrome's wire framing); HTTP/1.1 keeps the value whole. Writes up to
// `cap` crumbs to `out` and returns the total crumb count (empty crumbs
// skipped). Pass out=0, cap=0 to count only.
U64 cookie_crumbs(String8 value, String8 *out, U64 cap);

#endif  // HOLYTLS_HEADER_H
