#include "tls/ssl_ctx.h"

#include <openssl/x509.h>

#include "tls/cert_compress.h"
#include "tls/cert_pin.h"
#include "tls/keylog.h"

internal void warn(CtxResult *r, const char *msg) {
  if (r->warning_count < CTX_MAX_WARNINGS) r->warnings[r->warning_count++] = msg;
}

// Common Linux system CA bundle locations (BoringSSL ships no default bundle).
global const char *k_ca_bundles[] = {
    "/etc/ssl/certs/ca-certificates.crt",  // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",    // Fedora/RHEL
    "/etc/ssl/cert.pem",                   // Alpine/macOS
};

CtxResult build_ctx(const TlsProfile *p, B32 verify) {
  CtxResult r;
  MemoryZeroStruct(&r);
  SSL_CTX *c = SSL_CTX_new(TLS_method());
  if (!c) {
    warn(&r, "SSL_CTX_new failed");
    return r;
  }

  if (!SSL_CTX_set_min_proto_version(c, p->min_version))
    warn(&r, "set_min_proto_version failed");
  if (!SSL_CTX_set_max_proto_version(c, p->max_version))
    warn(&r, "set_max_proto_version failed");

  if (p->cipher_list && !SSL_CTX_set_cipher_list(c, p->cipher_list))
    warn(&r, "set_cipher_list rejected");
  if (p->curves_list && !SSL_CTX_set1_curves_list(c, p->curves_list))
    warn(&r, "set1_curves_list rejected");
  if (p->sigalgs_list && !SSL_CTX_set1_sigalgs_list(c, p->sigalgs_list))
    warn(&r, "set1_sigalgs_list rejected");

  SSL_CTX_set_grease_enabled(c, p->grease ? 1 : 0);
  SSL_CTX_set_permute_extensions(c, p->permute_extensions ? 1 : 0);
  if (p->enable_ocsp_stapling) SSL_CTX_enable_ocsp_stapling(c);
  if (p->enable_signed_cert_timestamps) SSL_CTX_enable_signed_cert_timestamps(c);
  if (!p->session_tickets) SSL_CTX_set_options(c, SSL_OP_NO_TICKET);

  // Certificate compression (advertise zlib/brotli/zstd with real decoders).
  {
    const char *skipped[8];
    int skipped_n = 0;
    int reg = register_cert_decompressors(c, p->cert_compress_algs,
                                          p->cert_compress_count, skipped,
                                          &skipped_n);
    if (reg == 0) warn(&r, "no cert-compression codec available");
    for (int i = 0; i < skipped_n; ++i)
      warn(&r, "cert-compression codec unavailable (not advertised)");
  }

#ifdef HOLYTLS_TLS_FORK
  // Fork-only knobs (lexiforest/boringssl) — emit the two extensions stock
  // can't, plus exact key-share count and extension order. Return conventions
  // vary, so we don't check; ja4_test validates the resulting ClientHello.
  if (p->record_size_limit) SSL_CTX_set_record_size_limit(c, p->record_size_limit);
  if (p->delegated_credentials)
    SSL_CTX_set_delegated_credentials(c, p->delegated_credentials);
  if (p->key_shares_limit) SSL_CTX_set_key_shares_limit(c, p->key_shares_limit);
  if (p->extension_order)
    SSL_CTX_set_extension_order(c, (char *)p->extension_order);
#else
  if (p->record_size_limit) warn(&r, "record_size_limit unsupported");
  if (p->delegated_credentials) warn(&r, "delegated_credential unsupported");
#endif

  if (verify) {
    B32 loaded = 0;
    for (U64 i = 0; i < ArrayCount(k_ca_bundles); ++i) {
      if (SSL_CTX_load_verify_locations(c, k_ca_bundles[i], 0)) {
        loaded = 1;
        break;
      }
    }
    if (!loaded && !SSL_CTX_set_default_verify_paths(c)) warn(&r, "no CA roots");
    SSL_CTX_set_verify(c, SSL_VERIFY_PEER, 0);
  } else {
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, 0);
  }

  // TLS/QUIC key logging (Wireshark). Observer only — never alters wire bytes.
  // Auto-enabled from $SSLKEYLOGFILE; client_set_key_log_file can also register it.
  keylog_init_from_env();
  if (keylog_enabled()) SSL_CTX_set_keylog_callback(c, keylog_callback);

  r.ctx = c;
  return r;
}

int ssl_resume_ex_index(void) {
  static int idx = -1;
  if (idx < 0) idx = SSL_get_ex_new_index(0, 0, 0, 0, 0);
  return idx;
}

B32 configure_ssl(SSL *ssl, const TlsProfile *p, const char *host,
                  const U8 *ech_config_list, U64 ech_config_list_len,
                  SSL_SESSION *resume_session, void *resume_ctx) {
  if (host && *host) {
    SSL_set_tlsext_host_name(ssl, host);
    X509_VERIFY_PARAM *vp = SSL_get0_param(ssl);
    // BoringSSL rejects namelen==0, so pass the real length.
    if (vp) X509_VERIFY_PARAM_set1_host(vp, host, strlen(host));
  }

  if (p->alpn_wire && p->alpn_wire_len) {
    if (SSL_set_alpn_protos(ssl, p->alpn_wire, p->alpn_wire_len) != 0) return 0;
  }

  // ALPS: advertise application settings for each protocol (empty settings).
  for (U8 i = 0; i < p->alps_count; ++i) {
    const char *proto = p->alps_protocols[i];
    SSL_add_application_settings(ssl, (const U8 *)proto, strlen(proto), 0, 0);
  }
  if (p->alps_count)
    SSL_set_alps_use_new_codepoint(ssl, p->alps_new_codepoint ? 1 : 0);

  // Real ECH when we have the host's ECHConfigList (from its DNS HTTPS RR);
  // BoringSSL then encrypts the inner ClientHello + sends the config's
  // public_name as the outer SNI. Falls back to ECH-GREASE otherwise.
  if (ech_config_list && ech_config_list_len)
    SSL_set1_ech_config_list(ssl, ech_config_list, (size_t)ech_config_list_len);
  SSL_set_enable_ech_grease(ssl, p->enable_ech_grease ? 1 : 0);

  // TLS 1.3 ticket resumption (opt-in). Offering a cached session adds the
  // pre_shared_key / psk_key_exchange_modes extensions to the ClientHello (the
  // resumed-handshake fingerprint, exactly as a real browser on a repeat visit),
  // so this path is only taken when the client has a cached ticket for the
  // origin. `resume_ctx` is always set when resumption is enabled so the
  // new-session callback can route freshly issued tickets back to their origin.
  if (resume_ctx) SSL_set_ex_data(ssl, ssl_resume_ex_index(), resume_ctx);
  if (resume_session) SSL_set_session(ssl, resume_session);

  // Certificate pinning (opt-in): if `host` is pinned on this SSL's CTX, override
  // verification for this connection with a trust-on-pin check. No-op otherwise,
  // so non-pinned connections keep the default certificate verification.
  cert_pin_maybe_enable(ssl, host);
  return 1;
}
