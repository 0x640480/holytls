// Sec-Fetch coherence — compute the Fetch Metadata request headers (Sec-Fetch-
// Site/Mode/Dest/User) to match the request's actual context, instead of the
// profile's static navigation defaults. Sec-Fetch-Site is derived from the
// referer<->URL origin relationship; the mode/dest/user follow the FetchMode.
#ifndef HOLYTLS_SEC_FETCH_H
#define HOLYTLS_SEC_FETCH_H

#include "base/string8.h"
#include "core/header.h"

// The kind of fetch, mapping to coherent Sec-Fetch-Mode/Dest/User values.
typedef enum FetchMode {
  FetchMode_Navigate,    // top-level page load: navigate / document / user ?1
  FetchMode_Cors,        // fetch()/XHR (CORS): cors / empty / (no user)
  FetchMode_NoCors,      // no-cors fetch or subresource: no-cors / empty
  FetchMode_SameOrigin,  // same-origin fetch: same-origin / empty
} FetchMode;

// Append the four coherent Sec-Fetch-* headers for a `mode` request to `url`,
// initiated from `referer` (empty => a direct navigation). An empty Sec-Fetch-
// User value is emitted for non-navigations so build_ordered_headers suppresses
// the header. Static literal values (no allocation); `out`'s arena holds the row.
void sec_fetch_append(HeaderList *out, FetchMode mode, String8 url,
                      String8 referer);

// Build `out` = caller headers followed by the coherent Sec-Fetch-* headers
// (caller-supplied Sec-Fetch-* still win, being first). Referer for Sec-Fetch-
// Site is taken from the caller headers.
void sec_fetch_merge(HeaderList *out, FetchMode mode, String8 url,
                     const Header *headers, U64 header_count);

// On a redirect, recompute Sec-Fetch-Site for the hop to `next_url` from the
// headers carried from the previous hop. The running value lives in the carried
// Sec-Fetch-Site header and the initiator in the carried Referer; this downgrades
// monotonically (same-origin -> same-site -> cross-site, cross-site/none terminal,
// per the Fetch Metadata url-list algorithm). Returns the new value, or
// str8_zero() when there's nothing to recompute (no Sec-Fetch-Site, or no Referer
// — e.g. a "none" user navigation, which the static default keeps as-is).
String8 sec_fetch_site_for_redirect(const Header *headers, U64 header_count,
                                    String8 next_url);

#endif  // HOLYTLS_SEC_FETCH_H
