// Shared QPACK request name-value builder for the two HTTP/3 request paths: the
// per-request H3Session (h3_session.c) and the pooled H3 transport (pool.c).
// Both assemble nghttp3_nv arrays to hand to the QPACK encoder; this is the
// trivial String8 -> nghttp3_nv adapter they previously hand-rolled identically
// (as h3_make_nv / pool_h3_nv).
#ifndef HOLYTLS_H3_NV_H
#define HOLYTLS_H3_NV_H

#include <nghttp3/nghttp3.h>

#include "base/base.h"
#include "base/string8.h"

internal inline nghttp3_nv h3_make_nv(String8 n, String8 v) {
  nghttp3_nv nv;
  nv.name = n.str;
  nv.namelen = n.size;
  nv.value = v.str;
  nv.valuelen = v.size;
  nv.flags = NGHTTP3_NV_FLAG_NONE;
  return nv;
}

#endif  // HOLYTLS_H3_NV_H
