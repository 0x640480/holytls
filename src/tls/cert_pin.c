#include "tls/cert_pin.h"

#include <openssl/mem.h>
#include <openssl/sha.h>
#include <string.h>

#include "base/arena.h"
#include "base/base64.h"
#include "base/string8.h"

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------
// True if pin `p` covers `host` (exact, or a parent domain when
// include_subdomains).
internal B32 pin_host_applies(const CertPin *p, String8 host) {
  String8 ph = str8_cstring(p->host);
  if (str8_match_ci(host, ph)) return 1;
  if (!p->include_subdomains || host.size <= ph.size) return 0;
  String8 tail = str8_skip(host, host.size - ph.size);
  if (!str8_match_ci(tail, ph)) return 0;
  return host.str[host.size - ph.size - 1] == '.';  // a real label boundary
}

B32 cert_pin_add(CertPinStore *s, const char *host, const char *spki_b64,
                 B32 include_subdomains) {
  if (!s || !host || !spki_b64 || s->count >= CERT_PIN_MAX) return 0;
  Temp scr = scratch_begin(0, 0);
  String8 raw = base64_decode(scr.arena, str8_cstring(spki_b64));
  B32 ok = (raw.size == 32);  // a SHA-256 SPKI pin is exactly 32 bytes
  if (ok) {
    CertPin *p = &s->pins[s->count++];
    U64 n = strlen(host);
    if (n > sizeof p->host - 1) n = sizeof p->host - 1;
    MemoryCopy(p->host, host, n);
    p->host[n] = 0;
    MemoryCopy(p->spki_sha256, raw.str, 32);
    p->include_subdomains = include_subdomains;
  }
  scratch_end(scr);
  return ok;
}

B32 cert_pin_host_has(const CertPinStore *s, const char *host) {
  if (!s || !host) return 0;
  String8 h = str8_cstring(host);
  for (int i = 0; i < s->count; ++i)
    if (pin_host_applies(&s->pins[i], h)) return 1;
  return 0;
}

B32 cert_pin_match(const CertPinStore *s, const char *host, const U8 *spki) {
  if (!s || !host || !spki) return 0;
  String8 h = str8_cstring(host);
  for (int i = 0; i < s->count; ++i)
    if (pin_host_applies(&s->pins[i], h) &&
        memcmp(s->pins[i].spki_sha256, spki, 32) == 0)
      return 1;
  return 0;
}

B32 cert_pin_compute_spki_sha256(X509 *cert, U8 out[32]) {
  if (!cert) return 0;
  X509_PUBKEY *pk =
      X509_get_X509_PUBKEY(cert);  // internal pointer; do not free
  if (!pk) return 0;
  U8 *der = 0;
  int len = i2d_X509_PUBKEY(pk, &der);
  if (len <= 0 || !der) return 0;
  SHA256(der, (size_t)len, out);
  OPENSSL_free(der);
  return 1;
}

// ---------------------------------------------------------------------------
// per-connection verification
// ---------------------------------------------------------------------------
// SSL_CTX ex_data slot for the CertPinStore; SSL ex_data slot for the host
// string.
internal int cert_pin_store_ex_index(void) {
  static int i = -1;
  if (i < 0) i = SSL_CTX_get_ex_new_index(0, 0, 0, 0, 0);
  return i;
}
internal int cert_pin_host_ex_index(void) {
  static int i = -1;
  if (i < 0) i = SSL_get_ex_new_index(0, 0, 0, 0, 0);
  return i;
}

// Trust-on-pin: accept iff the leaf SPKI matches a pin for the host; else
// reject.
internal enum ssl_verify_result_t cert_pin_verify_cb(SSL *ssl,
                                                     uint8_t *out_alert) {
  const char *host =
      (const char *)SSL_get_ex_data(ssl, cert_pin_host_ex_index());
  CertPinStore *s = (CertPinStore *)SSL_CTX_get_ex_data(
      SSL_get_SSL_CTX(ssl), cert_pin_store_ex_index());
  if (!host || !s) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    return ssl_verify_invalid;
  }
  X509 *leaf = SSL_get_peer_certificate(ssl);  // +1 ref
  if (!leaf) {
    *out_alert = SSL_AD_BAD_CERTIFICATE;
    return ssl_verify_invalid;
  }
  U8 spki[32];
  B32 ok =
      cert_pin_compute_spki_sha256(leaf, spki) && cert_pin_match(s, host, spki);
  X509_free(leaf);
  if (ok) return ssl_verify_ok;
  *out_alert = SSL_AD_BAD_CERTIFICATE;
  return ssl_verify_invalid;
}

void cert_pin_attach_ctx(SSL_CTX *ctx, CertPinStore *store) {
  if (ctx) SSL_CTX_set_ex_data(ctx, cert_pin_store_ex_index(), store);
}

void cert_pin_maybe_enable(SSL *ssl, const char *host) {
  if (!host || !*host) return;
  CertPinStore *s = (CertPinStore *)SSL_CTX_get_ex_data(
      SSL_get_SSL_CTX(ssl), cert_pin_store_ex_index());
  if (!s || !cert_pin_host_has(s, host)) return;  // not pinned -> leave default
  // `host` points at the connection's stable host buffer, valid through the
  // handshake (where the callback fires). Trust-on-pin overrides the CTX's
  // default verification for this one connection only.
  SSL_set_ex_data(ssl, cert_pin_host_ex_index(), (void *)host);
  SSL_set_custom_verify(ssl, SSL_VERIFY_PEER, cert_pin_verify_cb);
}
