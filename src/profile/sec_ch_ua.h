// Sec-CH-UA brand-list generation, reproducing Chromium's algorithm exactly
// (components/embedder_support/user_agent_utils.cc: GenerateBrandVersionList +
// GetGreasedUserAgentBrandVersion + ShuffleBrandList/GetRandomOrder).
//
// The GREASE brand token, its version, and the brand ORDER are a PURE FUNCTION
// of the Chrome major version (the GREASE "seed") — no per-request randomness.
// Chrome computes the list once per build and reuses it for every request,
// which is why a profile can carry a static value; these helpers reproduce that
// value for any version (and let a caller mint the high-entropy
// full-version-list header on demand).
#ifndef HOLYTLS_SEC_CH_UA_H
#define HOLYTLS_SEC_CH_UA_H

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

// The short, low-entropy `sec-ch-ua` value for Chrome `major`: the real brands
// ("Chromium", "Google Chrome") carry the bare major ("149"), the GREASE brand
// carries the bare greased digit ("24"). Fully determined by `major`. e.g.
// major=149 -> "Google Chrome";v="149", "Chromium";v="149",
// "Not)A;Brand";v="24"
String8 sec_ch_ua_brands(Arena *arena, U32 major);

// The high-entropy `sec-ch-ua-full-version-list` value. The real brands carry
// `full_version` — the TRUE build (e.g. "149.0.7632.67"), which is NOT
// derivable from the major and so must be supplied; pass str8_zero() to fall
// back to the UA-frozen "<major>.0.0.0". The GREASE brand token, its
// ".0.0.0"-suffixed greased version (e.g. "24.0.0.0"), and the brand order are
// all derived deterministically from `major`, exactly as the short form. The
// caller sets the header explicitly, e.g.:
//   Header h = { str8_lit("sec-ch-ua-full-version-list"),
//                sec_ch_ua_full_version_list(arena, 149,
//                str8_lit("149.0.7632.67")), 0 };
// (a Profile's major version is its `id`, so pass profile->id for `major`).
String8 sec_ch_ua_full_version_list(Arena *arena, U32 major,
                                    String8 full_version);

#endif  // HOLYTLS_SEC_CH_UA_H
