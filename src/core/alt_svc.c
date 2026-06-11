#include "core/alt_svc.h"

AltSvcInfo alt_svc_parse(String8 s) {
  AltSvcInfo r;
  r.h3 = 0;
  r.ma_seconds = 86400;  // 24h default
  // "clear" revokes all advertisements.
  if (str8_contains(s, str8_lit("clear"))) return r;
  // h3 (RFC 9114) or an h3 draft (h3-29 etc.).
  if (str8_contains(s, str8_lit("h3=")) || str8_contains(s, str8_lit("h3-")))
    r.h3 = 1;
  S64 p = str8_find(s, str8_lit("ma="));
  if (p >= 0) {
    String8 after = str8_skip(s, (U64)p + 3);
    if (after.size && after.str[0] >= '0' && after.str[0] <= '9')
      r.ma_seconds = str8_chop_u64(&after);
  }
  return r;
}
