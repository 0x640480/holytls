// Firefox emulation profiles (TCP/H2 + QUIC/H3). Self-contained, same shape as
// chrome.c. Built from real Firefox 151 captures (powhttp/browserleaks/peet):
// H2 JA4 t13d1617h2_86a278354501_3cbfd9057e0d, QUIC JA4 q13d0315h3_55b375c5d22e
// _dc5437974b47, h3_hash d50d4e585c22bb92b6c86b592aa2d586. Firefox differs from
// Chrome in big ways: NO GREASE, NO sec-ch-ua/client-hints, FFDHE groups, a
// TLS1.3 cipher order of AES128/CHACHA20/AES256 (the fork's kCiphersFirefox path,
// triggered by the cipher_list's TLS1.3 prefix), and a fixed extension order.
#include "profile/profile.h"

//- Firefox shared wire constants --------------------------------------------

// The cipher_list MUST start with the 3 TLS1.3 suites in Firefox order
// (AES128,CHACHA20,AES256) so the lexiforest fork selects kCiphersFirefox for the
// TLS1.3 ClientHello ciphers; the rest are Firefox's 13 TLS1.2 suites.
global const char k_firefox_cipher_list[] =
    "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:"
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
    "TLS_RSA_WITH_AES_128_GCM_SHA256:"
    "TLS_RSA_WITH_AES_256_GCM_SHA384:"
    "TLS_RSA_WITH_AES_128_CBC_SHA:"
    "TLS_RSA_WITH_AES_256_CBC_SHA";
// The QUIC ClientHello sets no cipher_list: BoringSSL's default TLS1.3 cipher
// order (1301,1302,1303) already matches Firefox (and hashes to the same
// q-JA4 cipher field as Chrome, 55b375c5d22e).

// Supported groups: the TCP/H2 ClientHello includes the FFDHE groups (Chrome
// does not); the QUIC/H3 ClientHello drops them (per the captures).
global const char k_firefox_curves[] =
    "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072";
global const char k_firefox_curves_h3[] =
    "X25519MLKEM768:X25519:P-256:P-384:P-521";
// 11 signature algorithms. Same SET for H2 + H3 but a DIFFERENT order: the
// TCP/H2 stack lists ecdsa_sha1(0203) second-to-last; the QUIC/H3 stack groups
// it with the other ECDSA algs in 4th position. (Both verified against real
// Firefox 151 ja4_r — the JA4_c hash is order-sensitive on sigalgs.)
global const char k_firefox_sigalgs[] =
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:"
    "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:"
    "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:"
    "rsa_pkcs1_sha1";
global const char k_firefox_sigalgs_h3[] =
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:"
    "ecdsa_sha1:"
    "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:"
    "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:"
    "rsa_pkcs1_sha1";
global const char k_firefox_delegated_creds[] =
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:"
    "ecdsa_sha1";
// Fixed extension order (Firefox does not permute).
global const char k_firefox_extension_order[] =
    "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037";

global const U8 k_firefox_alpn_h2[] = {2,   'h', '2', 8,   'h', 't',
                                       't', 'p', '/', '1', '.', '1'};
global const U8 k_firefox_alpn_h3[] = {2, 'h', '3'};
global const U16 k_firefox_cert_compress[] = {
    CertCompress_Zlib, CertCompress_Brotli, CertCompress_Zstd};

global const H2Setting k_firefox_h2_settings[] = {
    {H2Setting_HeaderTableSize, 65536},
    {H2Setting_EnablePush, 0},
    {H2Setting_InitialWindowSize, 131072},
    {H2Setting_MaxFrameSize, 16384},
};
// H2 pseudo order: :method :path :authority :scheme (m,p,a,s).
global const PseudoId k_firefox_h2_pseudo[] = {Pseudo_Method, Pseudo_Path,
                                               Pseudo_Authority, Pseudo_Scheme};

global const H3Setting k_firefox_h3_settings[] = {
    {0x01, 65536},      // QPACK_MAX_TABLE_CAPACITY
    {0x07, 20},         // QPACK_BLOCKED_STREAMS
    {727725890, 0},     // WEBTRANS_DRAFT00 (Firefox draft setting)
    {16765559, 1},      // H3_DATAGRAM_DRAFT04 (Firefox draft setting)
    {0x33, 1},          // H3_DATAGRAM
    {0x08, 1},          // ENABLE_CONNECT_PROTOCOL
};
// H3 pseudo order: :method :scheme :authority :path (m,s,a,p) — differs from H2.
global const PseudoId k_firefox_h3_pseudo[] = {Pseudo_Method, Pseudo_Scheme,
                                               Pseudo_Authority, Pseudo_Path};

//- Firefox fingerprint, expressed once --------------------------------------

#define FIREFOX_TLS_H2                          \
  .cipher_list = k_firefox_cipher_list,         \
  .curves_list = k_firefox_curves,              \
  .sigalgs_list = k_firefox_sigalgs,            \
  .min_version = TlsVersion_1_2,                \
  .max_version = TlsVersion_1_3,                \
  .alpn_wire = k_firefox_alpn_h2,               \
  .alpn_wire_len = sizeof k_firefox_alpn_h2,    \
  .cert_compress_algs = k_firefox_cert_compress, .cert_compress_count = 3, \
  .enable_ocsp_stapling = 1, .enable_signed_cert_timestamps = 1,           \
  .enable_ech_grease = 1, .session_tickets = 1,                            \
  .record_size_limit = 0x4001,                                            \
  .delegated_credentials = k_firefox_delegated_creds,                     \
  .key_shares_limit = 3,                                                  \
  .extension_order = k_firefox_extension_order
/* grease=0, permute_extensions=0, alps_count=0 — all default-zero (Firefox). */

// The QUIC ClientHello drops the FFDHE groups, the session_ticket + SCT
// extensions, and uses the default extension order (no custom order); it keeps
// status_request (OCSP), record_size_limit, delegated_credentials, ECH, and
// compress_certificate. ngtcp2 adds quic_transport_parameters.
#define FIREFOX_TLS_H3                          \
  .curves_list = k_firefox_curves_h3,           \
  .sigalgs_list = k_firefox_sigalgs_h3,         \
  .min_version = TlsVersion_1_3,                \
  .max_version = TlsVersion_1_3,                \
  .alpn_wire = k_firefox_alpn_h3,               \
  .alpn_wire_len = sizeof k_firefox_alpn_h3,    \
  .cert_compress_algs = k_firefox_cert_compress, .cert_compress_count = 3, \
  .enable_ocsp_stapling = 1, .enable_ech_grease = 1,                      \
  .record_size_limit = 0x4001,                                            \
  .delegated_credentials = k_firefox_delegated_creds,                     \
  .key_shares_limit = 3,                                                  \
  .force_tls13_legacy_ext = 1
/* Firefox uniquely sends EMS + renegotiation_info in its TLS1.3-only QUIC
   ClientHello; the fork knob re-enables them (gated off for TLS1.3 by stock). */

#define FIREFOX_H2_FP                            \
  .settings = k_firefox_h2_settings,             \
  .settings_count = 4,                           \
  .connection_window_increment = 12517377,       \
  .use_priority = 1,                             \
  .priority_weight = 42,                         \
  .pseudo_order = k_firefox_h2_pseudo,           \
  .pseudo_count = 4

#define FIREFOX_H3_FP                                  \
  .initial_max_data = 25165824,                        \
  .initial_max_stream_data_bidi_local = 12582912,      \
  .initial_max_stream_data_bidi_remote = 1048576,      \
  .initial_max_stream_data_uni = 1048576,              \
  .initial_max_streams_bidi = 100,                     \
  .initial_max_streams_uni = 100,                      \
  .max_idle_timeout_ms = 30000,                        \
  .max_datagram_frame_size = 65535,                    \
  .settings = k_firefox_h3_settings,                   \
  .settings_count = 6,                                 \
  .send_grease_frame = 1,                              \
  .pseudo_order = k_firefox_h3_pseudo,                 \
  .pseudo_count = 4

// Navigation request headers in wire order. Firefox sends NO sec-ch-ua /
// client-hints. referer/cookie/te are order-only (emitted when the caller adds
// them). Per the Firefox 151 capture.
#define FIREFOX_NAV_HEADERS                                                  \
  {"user-agent",                                                             \
   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 "     \
   "Firefox/151.0",                                                          \
   "User-Agent"},                                                            \
  {"accept",                                                                 \
   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",         \
   "Accept"},                                                                \
  {"accept-language", "en-US,en;q=0.9", "Accept-Language"},                 \
  {"accept-encoding", "gzip, deflate, br, zstd", "Accept-Encoding"},        \
  {"referer", "", "Referer"},                                              \
  {"cookie", "", "Cookie"},                                                 \
  {"upgrade-insecure-requests", "1", "Upgrade-Insecure-Requests"},          \
  {"sec-fetch-dest", "document", "Sec-Fetch-Dest"},                         \
  {"sec-fetch-mode", "navigate", "Sec-Fetch-Mode"},                         \
  {"sec-fetch-site", "none", "Sec-Fetch-Site"},                            \
  {"sec-fetch-user", "?1", "Sec-Fetch-User"},                              \
  {"priority", "u=0, i", "Priority"},                                      \
  {"te", "", "TE"}

global const DefaultHeader k_firefox_headers[] = {FIREFOX_NAV_HEADERS};

//- Firefox 151 --------------------------------------------------------------

global const Profile k_firefox151 = {
    .name = "firefox151",
    .id = 151,
    .tls = {FIREFOX_TLS_H2},
    .h2 = {FIREFOX_H2_FP},
    .default_headers = k_firefox_headers,
    .default_header_count = ArrayCount(k_firefox_headers),
};
global const QuicProfile k_firefox151_h3 = {
    .name = "firefox151-h3",
    .id = 151,
    .tls = {FIREFOX_TLS_H3},
    .h3 = {FIREFOX_H3_FP},
    .default_headers = k_firefox_headers,
    .default_header_count = ArrayCount(k_firefox_headers),
};

const Profile *profile_firefox151(void) { return &k_firefox151; }
const QuicProfile *profile_firefox151_h3(void) { return &k_firefox151_h3; }
