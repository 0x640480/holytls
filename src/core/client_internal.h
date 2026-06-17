// Internal client declarations: symbols defined in client.c that are NOT part
// of the public surface but are needed by white-box tests (and kept out of the
// public client.h to keep it clean). Not installed — include only from within
// the library or its own tests.
#ifndef HOLYTLS_CLIENT_INTERNAL_H
#define HOLYTLS_CLIENT_INTERNAL_H

#include "base/base.h"
#include "core/client.h"

// Browser-faithful next method for a `status` redirect of method `m`; sets
// *drop_body when the request body should be dropped. Exposed for testing the
// redirect state machine (tests/core_test.c).
Method redirect_next_method(Method m, int status, B32 *drop_body);

// Assemble the final ordered request headers into `out` (profile defaults merged
// with the caller array, the named-slot content-length fill, accept-encoding +
// content-length framing). Returns the arena-dup'd body view. Exposed for the
// white-box wire-order test (tests/header_order_test.c).
String8 build_request_headers(Arena *arena, const DefaultHeader *defaults,
                              U64 default_count, const Header *caller,
                              U64 caller_count, const U8 *body, U64 body_len,
                              B32 override_defaults, Method method,
                              HeaderList *out);

#endif  // HOLYTLS_CLIENT_INTERNAL_H
