// Minimal Alt-Svc parsing for Chrome-style HTTP/3 discovery. We only care
// whether the origin advertises `h3` and for how long (`ma=`), e.g.
//   alt-svc: h3=":443"; ma=2592000
#ifndef HOLYTLS_ALT_SVC_H
#define HOLYTLS_ALT_SVC_H

#include "base/base.h"
#include "base/string8.h"

typedef struct AltSvcInfo AltSvcInfo;
struct AltSvcInfo {
  B32 h3;
  U64 ma_seconds;  // default 24h if unspecified
};

AltSvcInfo alt_svc_parse(String8 value);

#endif  // HOLYTLS_ALT_SVC_H
