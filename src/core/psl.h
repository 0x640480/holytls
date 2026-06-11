// Public Suffix List — is a domain a "public suffix" (com, co.uk, github.io,
// ...) under which unrelated parties register names? Backed by an embedded,
// generated copy of the Mozilla PSL (core/psl_data.h, ICANN + PRIVATE
// sections; regenerate with scripts/gen_psl.py). The cookie jar uses this to
// reject a Set-Cookie Domain that would blanket every site under a suffix
// (e.g. evil.co.uk setting Domain=.co.uk).
#ifndef HOLYTLS_PSL_H
#define HOLYTLS_PSL_H

#include "base/base.h"
#include "base/string8.h"

// True if `domain` (ASCII/punycode; case-insensitive; optional trailing dot)
// is a public suffix. Implements the PSL algorithm: exception rules beat
// wildcard/exact rules, `*.parent` covers exactly one extra label, and an
// unlisted single label is a suffix by the default `*` rule.
B32 psl_is_public_suffix(String8 domain);

#endif  // HOLYTLS_PSL_H
