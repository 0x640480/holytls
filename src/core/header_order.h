// BuildOrderedHeaders — merge a profile's ordered default header set with the
// caller's headers into one wire-ordered list. Header order + case are part of
// the fingerprint, so this is the single place that bakes the browser's exact
// navigation order. An empty value omits the header (drops order-only
// placeholders, and lets a caller suppress a default).
#ifndef HOLYTLS_HEADER_ORDER_H
#define HOLYTLS_HEADER_ORDER_H

#include "base/arena.h"
#include "core/header.h"
#include "profile/profile.h"

// `out` must be initialised (header_list_init) on the same arena.
void build_ordered_headers(Arena *arena, const DefaultHeader *defaults,
                           U64 default_count, const Header *caller,
                           U64 caller_count, HeaderList *out);

// Reorder `list` in place by `order` (case-insensitive name match): headers named
// in `order` come first, in that sequence; any header not named in `order` follows
// in its original relative order. No header is dropped or duplicated; an order name
// with no matching header is skipped. order_count==0 is a no-op. ADVANCED: this
// deviates from the profile's byte-exact (fingerprinted) header order.
void reorder_headers(Arena *arena, HeaderList *list, const String8 *order,
                     U64 order_count);

#endif  // HOLYTLS_HEADER_ORDER_H
