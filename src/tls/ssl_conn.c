#include "tls/ssl_conn.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include "tls/ssl_ctx.h"

void ssl_pump_init(SslPump *pump, SSL_CTX *ctx) {
  MemoryZeroStruct(pump);
  if (!ctx) return;
  pump->ssl = SSL_new(ctx);
  if (!pump->ssl) return;
  pump->rbio = BIO_new(BIO_s_mem());
  pump->wbio = BIO_new(BIO_s_mem());
  // An empty memory rbio must signal "want read", not EOF.
  BIO_set_mem_eof_return(pump->rbio, -1);
  BIO_set_mem_eof_return(pump->wbio, -1);
  SSL_set_bio(pump->ssl, pump->rbio, pump->wbio);  // takes ownership of both
  SSL_set_connect_state(pump->ssl);
}

void ssl_pump_cleanup(SslPump *pump) {
  if (pump->ssl) SSL_free(pump->ssl);  // also frees rbio/wbio
  MemoryZeroStruct(pump);
}

B32 ssl_pump_configure(SslPump *pump, const TlsProfile *p, const char *host,
                       const U8 *ech_config_list, U64 ech_config_list_len,
                       SSL_SESSION *resume_session, void *resume_ctx) {
  return pump->ssl && configure_ssl(pump->ssl, p, host, ech_config_list,
                                    ech_config_list_len, resume_session,
                                    resume_ctx);
}

B32 ssl_pump_resumed(SslPump *pump) {
  return pump->ssl ? (B32)SSL_session_reused(pump->ssl) : 0;
}

B32 ssl_pump_enable_early_data(SslPump *pump, SSL_SESSION *session) {
  if (!pump->ssl || !session || !SSL_SESSION_early_data_capable(session))
    return 0;
  SSL_set_early_data_enabled(pump->ssl, 1);
  return 1;
}

B32 ssl_pump_in_early_data(SslPump *pump) {
  return pump->ssl ? (B32)SSL_in_early_data(pump->ssl) : 0;
}

B32 ssl_pump_early_accepted(SslPump *pump) {
  return pump->ssl ? (B32)SSL_early_data_accepted(pump->ssl) : 0;
}

void ssl_pump_feed_ciphertext(SslPump *pump, const U8 *data, U64 len) {
  if (pump->ssl && len) BIO_write(pump->rbio, data, (int)len);
}

B32 ssl_pump_has_output(SslPump *pump) {
  return pump->ssl && BIO_pending(pump->wbio) > 0;
}

int ssl_pump_read_output(SslPump *pump, U8 *buf, U64 cap) {
  if (!pump->ssl) return 0;
  int n = BIO_read(pump->wbio, buf, (int)cap);
  return n > 0 ? n : 0;
}

HsStatus ssl_pump_do_handshake(SslPump *pump) {
  if (!pump->ssl) return HsStatus_Error;
  ERR_clear_error();
  int r = SSL_do_handshake(pump->ssl);
  if (r == 1) {
    pump->established = 1;
    return HsStatus_Done;
  }
  int e = SSL_get_error(pump->ssl, r);
  // The server rejected our 0-RTT early data: surface a distinct status so the
  // connection retries the request on a fresh, non-0-RTT connection.
  if (e == SSL_ERROR_EARLY_DATA_REJECTED) {
    pump->last_err = ERR_peek_last_error();
    return HsStatus_EarlyRejected;
  }
  if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
    // With early data enabled, SSL_do_handshake returns want-IO after sending the
    // ClientHello while the 0-RTT window is open — distinguish it so the caller
    // can write the request as early data before the handshake completes.
    if (SSL_in_early_data(pump->ssl)) return HsStatus_EarlyData;
    return HsStatus_WantIo;
  }
  pump->last_err = ERR_peek_last_error();
  // A 0-RTT ClientHello answered with a sub-TLS-1.3 version fails with
  // SSL_R_WRONG_VERSION_ON_EARLY_DATA (SSL_ERROR_SSL, not EARLY_DATA_REJECTED).
  // RFC 8446 D.3 says to retry on a fresh non-0-RTT connection — route it through
  // the same early-rejected fallback.
  if (ERR_GET_LIB(pump->last_err) == ERR_LIB_SSL &&
      ERR_GET_REASON(pump->last_err) == SSL_R_WRONG_VERSION_ON_EARLY_DATA)
    return HsStatus_EarlyRejected;
  return HsStatus_Error;
}

void ssl_pump_alpn(SslPump *pump, const U8 **out, unsigned *len) {
  *out = 0;
  *len = 0;
  if (pump->ssl) SSL_get0_alpn_selected(pump->ssl, out, len);
}

int ssl_pump_read_plaintext(SslPump *pump, U8 *buf, U64 cap) {
  if (!pump->ssl) return -2;
  ERR_clear_error();
  int r = SSL_read(pump->ssl, buf, (int)cap);
  if (r > 0) return r;
  int e = SSL_get_error(pump->ssl, r);
  if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return -1;
  if (e == SSL_ERROR_ZERO_RETURN) return -2;  // peer closed cleanly
  pump->last_err = ERR_peek_last_error();
  return -2;
}

int ssl_pump_write_plaintext(SslPump *pump, const U8 *buf, U64 len) {
  if (!pump->ssl) return -2;
  if (len == 0) return 0;
  ERR_clear_error();
  int r = SSL_write(pump->ssl, buf, (int)len);
  if (r > 0) return r;
  int e = SSL_get_error(pump->ssl, r);
  if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return -1;
  pump->last_err = ERR_peek_last_error();
  return -2;
}
