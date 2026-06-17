// TlsStream — a raw TLS byte stream over holytls's transport, for non-HTTP
// protocols (IMAP, SMTP, ...). It reuses the client's TLS stack (ciphers,
// curves, extensions) but offers NO ALPN — a plain encrypted byte pipe, like a
// mail client. One TlsStream is a single long-lived connection driven
// blocking-style: each call runs the loop until its event (connect / data /
// close). A sibling of WsConn (ws/ws.h), minus the RFC 6455 codec — and simpler,
// since conn_read_plaintext IS the read (BoringSSL buffers decrypted bytes).
#ifndef HOLYTLS_TLS_STREAM_H
#define HOLYTLS_TLS_STREAM_H

#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"

typedef struct TlsStream TlsStream;

// Blocking: open a TLS connection to host:port over `client`'s TLS profile (with
// NO ALPN). `timeout_ms` bounds the connect (0 => the client's configured
// timeout, then no limit). Returns a handle (NULL only on allocation failure); a
// connect FAILURE leaves tls_stream_error() non-NULL — check it before using the
// stream. The client is borrowed (its loop/profile/ctx) and must outlive the
// stream; drive one stream from the client's loop thread, serially.
TlsStream *tls_stream_connect(Client *client, String8 host, U16 port,
                              U64 timeout_ms);

// Write `len` plaintext bytes: encrypted + queued to the socket (flushed on the
// next read / loop turn). Returns 1, or 0 if the stream is closed/failed.
B32 tls_stream_write(TlsStream *s, const U8 *data, U64 len);

// Blocking: read up to `cap` decrypted bytes into `buf`. Returns the byte count
// (>0); 0 on a clean close (peer EOF / TLS close_notify); -1 on error; -2 if
// `timeout_ms` elapsed with no data (the stream stays usable). 0 timeout blocks
// indefinitely.
int tls_stream_read(TlsStream *s, U8 *buf, U64 cap, U64 timeout_ms);

// Close the connection and free the handle (drives the loop until the transport
// is fully closed). The handle is invalid afterward. NULL-safe.
void tls_stream_free(TlsStream *s);

// The failure reason, or 0 when the stream is healthy.
const char *tls_stream_error(TlsStream *s);

#endif  // HOLYTLS_TLS_STREAM_H
