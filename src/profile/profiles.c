#include "profile/profile.h"

// Profile core: the cross-family registry (the single source of truth for which
// browser profiles exist), the wreq `template` profile that doubles as the
// new-browser scaffold, and the shared default-header accessors. Each browser
// FAMILY lives in its own self-contained file (chrome.c, future firefox.c …)
// #included into the unity build; this file just lists them in the registry.

//- the template profile (and the scaffold for a new browser family) ----------
// Every field a new family must consider is shown here in designated form; copy
// this shape into <family>.c and fill in the captured fingerprint values. (The
// values below are wreq's generic template, not a real browser.)

global const char k_cipher_list[] =
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
    "TLS_RSA_WITH_AES_128_GCM_SHA256:"
    "TLS_RSA_WITH_AES_256_GCM_SHA384:"
    "TLS_RSA_WITH_AES_128_CBC_SHA:"
    "TLS_RSA_WITH_AES_256_CBC_SHA";
global const char k_curves_list[] = "X25519MLKEM768:X25519:P-256:P-384:P-521";
global const char k_sigalgs_list[] =
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:"
    "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:"
    "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:"
    "rsa_pkcs1_sha1";
global const U8 k_alpn_wire[] = {2,   'h', '2', 8,   'h', 't',
                                 't', 'p', '/', '1', '.', '1'};
global const U16 k_cert_compress[] = {CertCompress_Zlib, CertCompress_Brotli,
                                      CertCompress_Zstd};
global const char k_delegated_creds[] =
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:"
    "ecdsa_sha1";
global const char k_extension_order[] =
    "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037";
global const H2Setting k_h2_settings[] = {
    {H2Setting_HeaderTableSize, 65536},
    {H2Setting_EnablePush, 0},
    {H2Setting_InitialWindowSize, 131072},
    {H2Setting_MaxFrameSize, 16384},
};
// :method :path :authority :scheme
global const PseudoId k_pseudo_order[] = {Pseudo_Method, Pseudo_Path,
                                          Pseudo_Authority, Pseudo_Scheme};

global const Profile k_template = {
    .name = "wreq-template",
    .id = 1,
    .tls =
        {
            .cipher_list = k_cipher_list,
            .curves_list = k_curves_list,
            .sigalgs_list = k_sigalgs_list,
            .min_version = TlsVersion_1_2,
            .max_version = TlsVersion_1_3,
            .alpn_wire = k_alpn_wire,
            .alpn_wire_len = sizeof k_alpn_wire,
            .cert_compress_algs = k_cert_compress,
            .cert_compress_count = 3,
            .grease = 1,
            .enable_ocsp_stapling = 1,
            .enable_signed_cert_timestamps = 1,
            .enable_ech_grease = 1,
            .session_tickets = 1,
            .aes_hw_override = 1,
            .aes_hw_override_value = 1,
            .random_aes_hw_override = 1,
            .record_size_limit = 0x4001,
            .delegated_credentials = k_delegated_creds,
            .key_shares_limit = 3,
            .extension_order = k_extension_order,
        },
    .h2 =
        {
            .settings = k_h2_settings,
            .settings_count = 4,
            .connection_window_increment = 12517377,
            .use_priority = 1,
            .priority_weight = 41,
            .pseudo_order = k_pseudo_order,
            .pseudo_count = 4,
        },
    // No default_headers/fetch_order — the template ships none.
};

const Profile *profile_template(void) { return &k_template; }

//- registry: every browser profile that exists ------------------------------
// entry[0] is the default ("newest"). Add a browser family here (one row) after
// dropping its <family>.c data file in and #including it from src/holytls.c.

global const ProfileEntry k_profile_registry[] = {
    {149, "chrome149", profile_chrome149, profile_chrome149_h3},  // [0] default
    {148, "chrome148", profile_chrome148, profile_chrome148_h3},
    {151, "firefox151", profile_firefox151, profile_firefox151_h3},
};

const ProfileEntry *profile_registry(U64 *count) {
  if (count) *count = ArrayCount(k_profile_registry);
  return k_profile_registry;
}
const Profile *profile_by_name(String8 name) {
  for (U64 i = 0; i < ArrayCount(k_profile_registry); ++i)
    if (str8_match_ci(name, str8_cstring(k_profile_registry[i].name)))
      return k_profile_registry[i].h2();
  return 0;
}
const QuicProfile *profile_quic_by_name(String8 name) {
  for (U64 i = 0; i < ArrayCount(k_profile_registry); ++i)
    if (str8_match_ci(name, str8_cstring(k_profile_registry[i].name)))
      return k_profile_registry[i].h3();
  return 0;
}

//- default-header accessors --------------------------------------------------

String8 profile_default_header(const DefaultHeader *defaults, U8 count,
                               String8 name) {
  for (U8 i = 0; i < count; ++i)
    if (str8_match_ci(str8_cstring(defaults[i].name), name))
      return str8_cstring(defaults[i].value);
  return str8_zero();
}

internal String8 profile_hdr(const Profile *p, const char *name) {
  return profile_default_header(p->default_headers, p->default_header_count,
                                str8_cstring(name));
}

String8 profile_user_agent(const Profile *p) {
  return profile_hdr(p, "user-agent");
}
String8 profile_sec_ch_ua(const Profile *p) {
  return profile_hdr(p, "sec-ch-ua");
}
String8 profile_sec_ch_ua_mobile(const Profile *p) {
  return profile_hdr(p, "sec-ch-ua-mobile");
}
String8 profile_sec_ch_ua_platform(const Profile *p) {
  return profile_hdr(p, "sec-ch-ua-platform");
}
String8 profile_accept(const Profile *p) { return profile_hdr(p, "accept"); }
String8 profile_accept_language(const Profile *p) {
  return profile_hdr(p, "accept-language");
}
String8 profile_accept_encoding(const Profile *p) {
  return profile_hdr(p, "accept-encoding");
}
