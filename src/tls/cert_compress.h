// Certificate-compression decompressors. Registering a decompressor is what
// makes BoringSSL ADVERTISE that algorithm in the ClientHello (the
// compress_certificate extension — part of the JA4), so this is fingerprint-
// relevant, not just handshake robustness.
#ifndef HOLYTLS_CERT_COMPRESS_H
#define HOLYTLS_CERT_COMPRESS_H

#include <openssl/ssl.h>

#include "base/base.h"

// Register a decompressor for each advertised alg. Returns the count registered;
// names of algs whose codec is unavailable are written to skipped[].
int register_cert_decompressors(SSL_CTX *ctx, const U16 *algs, int count,
                                const char **skipped, int *skipped_n);

#endif  // HOLYTLS_CERT_COMPRESS_H
