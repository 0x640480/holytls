// BoringSSL SSL_CTX builder + per-connection SSL configuration for a TLS
// impersonation profile. Default backend = the lexiforest/boringssl fork
// (HOLYTLS_TLS_FORK); knobs stock can't express are reported in `warnings`.
#ifndef HOLYTLS_SSL_CTX_H
#define HOLYTLS_SSL_CTX_H

#include <openssl/ssl.h>

#include "base/base.h"
#include "profile/profile.h"

enum { CTX_MAX_WARNINGS = 24 };

typedef struct CtxResult CtxResult;
struct CtxResult {
  SSL_CTX *ctx;  // caller owns (SSL_CTX_free); NULL on failure
  const char *warnings[CTX_MAX_WARNINGS];
  int warning_count;
};

internal inline B32 ctx_ok(const CtxResult *r) { return r->ctx != 0; }

// Build an SSL_CTX applying every supported TLS knob. `verify` enables peer
// certificate verification (loads system roots).
CtxResult build_ctx(const TlsProfile *p, B32 verify);

// The SSL ex_data index under which a per-connection resumption context is
// stored (so a single SSL_CTX-level new-session callback can route each
// captured ticket to its origin). Lazily registered; stable for the process
// lifetime.
int ssl_resume_ex_index(void);

// Apply per-connection knobs (SNI, ALPN, ALPS, ECH, TLS session resumption) to
// a fresh SSL. `host` is the SNI/verification hostname (NUL-terminated).
// `ech_config_list` (may be 0) is a serialized ECHConfigList (from the host's
// DNS HTTPS RR): when present, real ECH is offered; otherwise ECH-GREASE per
// the profile. `resume_session` (may be 0) is a cached SSL_SESSION offered for
// 1-RTT resumption (caller retains ownership). `resume_ctx` (may be 0) is an
// opaque pointer stashed at `ssl_resume_ex_index()` for the new-session
// callback.
B32 configure_ssl(SSL *ssl, const TlsProfile *p, const char *host,
                  const U8 *ech_config_list, U64 ech_config_list_len,
                  SSL_SESSION *resume_session, void *resume_ctx);

#endif  // HOLYTLS_SSL_CTX_H
