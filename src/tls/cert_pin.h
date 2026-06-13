// cert_pin — HTTP Public Key Pinning (HPKP-style) for outbound connections. A
// pinned host is accepted only if its leaf certificate's SubjectPublicKeyInfo
// SHA-256 matches one of the configured pins. Pinning is the trust decision: a
// pin match overrides the normal CA check (so a pinned self-signed cert is
// accepted), and any non-matching cert — even a CA-valid one — is rejected.
//
// Mechanism: per-connection BoringSSL SSL_set_custom_verify, installed by
// configure_ssl ONLY when the connection's host is pinned. Non-pinned hosts
// keep the library's default certificate verification entirely untouched —
// pinning never weakens the common path.
#ifndef HOLYTLS_CERT_PIN_H
#define HOLYTLS_CERT_PIN_H

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "base/base.h"

enum {
  CERT_PIN_MAX = 32
};  // total pins across all hosts (backup pins included)

typedef struct CertPin CertPin;
struct CertPin {
  char host[256];      // matched case-insensitively
  U8 spki_sha256[32];  // SHA-256 of the DER SubjectPublicKeyInfo
  B32 include_subdomains;
};

typedef struct CertPinStore CertPinStore;
struct CertPinStore {
  CertPin pins[CERT_PIN_MAX];
  int count;
};

// Add a pin: `spki_b64` is base64 of the 32-byte SHA-256 of the leaf's DER SPKI
// (HPKP / Chrome DevTools format). Returns 1 on success; 0 if the base64 does
// not decode to exactly 32 bytes, an argument is null, or the table is full.
B32 cert_pin_add(CertPinStore *s, const char *host, const char *spki_b64,
                 B32 include_subdomains);

// 1 if any pin applies to `host` (exact, or a parent pinned with
// include_subdomains).
B32 cert_pin_host_has(const CertPinStore *s, const char *host);

// 1 if `spki` (32 bytes) matches a pin applicable to `host`.
B32 cert_pin_match(const CertPinStore *s, const char *host, const U8 *spki);

// SHA-256 of `cert`'s DER SubjectPublicKeyInfo into out[32]. 0 on failure.
// Exposed so a caller can derive a pin value from a certificate it holds.
B32 cert_pin_compute_spki_sha256(X509 *cert, U8 out[32]);

// Attach `store` to `ctx` so per-connection verification can find it.
// Idempotent.
void cert_pin_attach_ctx(SSL_CTX *ctx, CertPinStore *store);

// If `host` is pinned on the SSL's CTX store, install a per-connection custom
// verify enforcing the pin (trust-on-pin). Called from configure_ssl; a no-op
// for non-pinned hosts (their verification is left exactly as the default
// path).
void cert_pin_maybe_enable(SSL *ssl, const char *host);

#endif  // HOLYTLS_CERT_PIN_H
