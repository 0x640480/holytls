// SslPump — drives a client-side BoringSSL connection over two memory BIOs. It
// does no socket I/O: the caller feeds received ciphertext in and pulls
// ciphertext-to-send out, so the same engine sits under libuv or a test
// harness.
//
//   socket recv -> ssl_pump_feed_ciphertext -> [rbio] -> SSL_* -> plaintext
//   socket send <- ssl_pump_read_output      <- [wbio] <- SSL_*
#ifndef HOLYTLS_SSL_CONN_H
#define HOLYTLS_SSL_CONN_H

#include <openssl/ssl.h>

#include "base/base.h"
#include "profile/profile.h"

typedef struct SslPump SslPump;
struct SslPump {
  SSL *ssl;
  BIO *rbio;  // caller writes incoming ciphertext here
  BIO *wbio;  // SSL writes outgoing ciphertext here
  B32 established;
  unsigned long last_err;
};

// HsStatus_EarlyData: the ClientHello was sent and the connection is in the
// 0-RTT window (SSL_in_early_data) — the caller may now SSL_write early data.
// HsStatus_EarlyRejected: the server rejected the offered early data
// (SSL_ERROR_EARLY_DATA_REJECTED); the caller must retry on a fresh, non-0-RTT
// connection (the request bytes already written as early data are discarded).
typedef enum HsStatus {
  HsStatus_WantIo,
  HsStatus_Done,
  HsStatus_Error,
  HsStatus_EarlyData,
  HsStatus_EarlyRejected,
} HsStatus;

void ssl_pump_init(SslPump *pump, SSL_CTX *ctx);
void ssl_pump_cleanup(SslPump *pump);
internal inline B32 ssl_pump_valid(SslPump *pump) { return pump->ssl != 0; }
B32 ssl_pump_configure(SslPump *pump, const TlsProfile *p, const char *host,
                       const U8 *ech_config_list, U64 ech_config_list_len,
                       SSL_SESSION *resume_session, void *resume_ctx);

// True once the handshake completed via an abbreviated (resumed) handshake.
B32 ssl_pump_resumed(SslPump *pump);

// Enable TLS 1.3 early data (0-RTT) on this pump before the handshake.
// `session` is the cached SSL_SESSION about to be offered; early data is only
// enabled when it is 0-RTT-capable (SSL_SESSION_early_data_capable). Returns 1
// if enabled.
B32 ssl_pump_enable_early_data(SslPump *pump, SSL_SESSION *session);

// True while the pump is in the 0-RTT window (ClientHello sent, handshake not
// yet complete): SSL_write writes early data.
B32 ssl_pump_in_early_data(SslPump *pump);

// True once the completed handshake confirmed the server accepted the early
// data.
B32 ssl_pump_early_accepted(SslPump *pump);

void ssl_pump_feed_ciphertext(SslPump *pump, const U8 *data, U64 len);
B32 ssl_pump_has_output(SslPump *pump);
int ssl_pump_read_output(SslPump *pump, U8 *buf, U64 cap);

HsStatus ssl_pump_do_handshake(SslPump *pump);
void ssl_pump_alpn(SslPump *pump, const U8 **out, unsigned *len);

int ssl_pump_read_plaintext(SslPump *pump, U8 *buf, U64 cap);  // >=0/-1/-2
int ssl_pump_write_plaintext(SslPump *pump, const U8 *buf, U64 len);

#endif  // HOLYTLS_SSL_CONN_H
