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

#endif  // HOLYTLS_CLIENT_INTERNAL_H
