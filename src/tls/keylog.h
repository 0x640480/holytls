// keylog — NSS Key Log writer for Wireshark TLS/QUIC decryption. When a key-log
// destination is set (the SSLKEYLOGFILE env var, honored automatically, or
// client_set_key_log_file), BoringSSL exports each TLS 1.3 secret
// (CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_TRAFFIC_SECRET_0, EXPORTER_SECRET, ...)
// through the keylog callback, which appends it in NSS Key Log Format.
//
// A single SSL_CTX callback covers BOTH TLS-over-TCP and QUIC: ngtcp2 derives the
// QUIC keys from these same TLS secrets, and Wireshark reads the identical file to
// decrypt either transport — so no separate ngtcp2 hook is needed.
//
// The destination is process-global (one file, matching SSLKEYLOGFILE semantics);
// writes are mutex-serialized and line-flushed so concurrent clients / loops never
// interleave a line. OFF unless a destination is set, and a no-op observer that
// cannot alter any handshake bytes.
#ifndef HOLYTLS_KEYLOG_H
#define HOLYTLS_KEYLOG_H

#include <openssl/ssl.h>

#include "base/base.h"

// Open the process key-log destination at `path` (append mode). The first
// destination set for the process wins (like SSLKEYLOGFILE: one file per process).
// Returns 1 if a destination is now open. Thread-safe; idempotent.
B32 keylog_open(const char *path);

// Open from $SSLKEYLOGFILE if set (no-op otherwise). Idempotent; build_ctx calls it.
void keylog_init_from_env(void);

// 1 if a key-log destination is open.
B32 keylog_enabled(void);

// The BoringSSL keylog callback (pass to SSL_CTX_set_keylog_callback). Appends
// `line` + '\n' under the write lock; a no-op when disabled.
void keylog_callback(const SSL *ssl, const char *line);

#endif  // HOLYTLS_KEYLOG_H
