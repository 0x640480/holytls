// Chrome emulation profiles (TCP/H2 + QUIC/H3). Self-contained: every wire
// constant Chrome needs lives here, so adding the next browser family is a new
// sibling file (firefox.c / safari.c) with no cross-file coupling. The shared
// per-version fingerprint is expressed ONCE via the CHROME_* designated-init
// macros; a new Chrome version then differs only in its header table + name/id.
// Live-verified byte-exact (JA4/Akamai/h3_hash/QUIC-JA4) — see
// ja4_test/h2_test/ profile_test (offline) and fingerprint_h3_test (live).
#include "profile/profile.h"

//- Chrome shared wire constants ---------------------------------------------

// TLS 1.2 cipher suites (TCP/H2 ClientHello; capture order).
global const char k_chrome_cipher_list[] =
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
    "TLS_RSA_WITH_AES_128_GCM_SHA256:"
    "TLS_RSA_WITH_AES_256_GCM_SHA384:"
    "TLS_RSA_WITH_AES_128_CBC_SHA:"
    "TLS_RSA_WITH_AES_256_CBC_SHA";

// Supported groups (shared by H2 + H3).
global const char k_chrome_curves[] = "X25519MLKEM768:X25519:P-256:P-384";

// Signature algorithms: H2 has 8 (no rsa_pkcs1_sha1); H3 adds it (9).
global const char k_chrome_sigalgs[] =
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
    "rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
global const char k_chrome_h3_sigalgs[] =
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
    "rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1";

// ALPN wire (RFC 7301): H2 offers [h2, http/1.1]; H3 offers [h3].
global const U8 k_chrome_alpn_h2[] = {2,   'h', '2', 8,   'h', 't',
                                      't', 'p', '/', '1', '.', '1'};
global const U8 k_chrome_alpn_h3[] = {2, 'h', '3'};
global const char *const k_chrome_alps_h2[] = {"h2"};
global const char *const k_chrome_alps_h3[] = {"h3"};

global const U16 k_chrome_cert_compress[] = {
    CertCompress_Brotli};  // brotli only

global const H2Setting k_chrome_h2_settings[] = {
    {H2Setting_HeaderTableSize, 65536},
    {H2Setting_EnablePush, 0},
    {H2Setting_InitialWindowSize, 6291456},
    {H2Setting_MaxHeaderListSize, 262144},
};
global const H3Setting k_chrome_h3_settings[] = {
    {0x01, 65536},   // QPACK_MAX_TABLE_CAPACITY
    {0x06, 262144},  // MAX_FIELD_SECTION_SIZE
    {0x07, 100},     // QPACK_BLOCKED_STREAMS
    {0x33, 1},       // H3_DATAGRAM
};
// :method :authority :scheme :path (Chrome order, both H2 and H3).
global const PseudoId k_chrome_pseudo[] = {Pseudo_Method, Pseudo_Authority,
                                           Pseudo_Scheme, Pseudo_Path};

// Header order for fetch/XHR (non-navigation) requests — stable across Chrome
// versions. Differs from navigation: client-hint block reordered,
// content-length first, origin after accept + referer after sec-fetch-dest, no
// UIR/sec-fetch-user.
global const char *const k_chrome_fetch_order[] = {
    "content-length",   "sec-ch-ua-platform",
    "user-agent",       "sec-ch-ua",
    "sec-ch-ua-mobile", "accept",
    "origin",           "sec-fetch-site",
    "sec-fetch-mode",   "sec-fetch-dest",
    "referer",          "accept-encoding",
    "accept-language",  "cookie",
    "priority",
};

//- Chrome shared fingerprint, expressed once -------------------------------
// Designated-init macros: a new Chrome version reuses these verbatim. Every
// non-zero field is listed (omitted designated fields zero-fill — the offline
// fingerprint tests catch any miss).

#define CHROME_TLS_H2                                                    \
  .cipher_list = k_chrome_cipher_list, .curves_list = k_chrome_curves,   \
  .sigalgs_list = k_chrome_sigalgs, .min_version = TlsVersion_1_2,       \
  .max_version = TlsVersion_1_3, .alpn_wire = k_chrome_alpn_h2,          \
  .alpn_wire_len = sizeof k_chrome_alpn_h2,                              \
  .alps_protocols = k_chrome_alps_h2, .alps_count = 1,                   \
  .alps_new_codepoint = 1, .cert_compress_algs = k_chrome_cert_compress, \
  .cert_compress_count = 1, .grease = 1, .permute_extensions = 1,        \
  .enable_ocsp_stapling = 1, .enable_signed_cert_timestamps = 1,         \
  .enable_ech_grease = 1, .session_tickets = 1, .key_shares_limit = 2

// H3: TLS1.3-only (no cipher_list), h3 ALPN, h3 sig-algs, no permute/ocsp/sct.
#define CHROME_TLS_H3                                                      \
  .curves_list = k_chrome_curves, .sigalgs_list = k_chrome_h3_sigalgs,     \
  .min_version = TlsVersion_1_3, .max_version = TlsVersion_1_3,            \
  .alpn_wire = k_chrome_alpn_h3, .alpn_wire_len = sizeof k_chrome_alpn_h3, \
  .alps_protocols = k_chrome_alps_h3, .alps_count = 1,                     \
  .alps_new_codepoint = 1, .cert_compress_algs = k_chrome_cert_compress,   \
  .cert_compress_count = 1, .grease = 1, .enable_ech_grease = 1,           \
  .session_tickets = 1, .key_shares_limit = 2

#define CHROME_H2_FP                                          \
  .settings = k_chrome_h2_settings, .settings_count = 4,      \
  .connection_window_increment = 15663105, .use_priority = 1, \
  .priority_weight = 256, .priority_exclusive = 1,            \
  .pseudo_order = k_chrome_pseudo, .pseudo_count = 4

#define CHROME_H3_FP                                                           \
  .initial_max_data = 15728640, .initial_max_stream_data_bidi_local = 6291456, \
  .initial_max_stream_data_bidi_remote = 6291456,                              \
  .initial_max_stream_data_uni = 6291456, .initial_max_streams_bidi = 100,     \
  .initial_max_streams_uni = 103, .max_idle_timeout_ms = 30000,                \
  .max_udp_payload_size = 1472, .max_datagram_frame_size = 65536,              \
  .settings = k_chrome_h3_settings, .settings_count = 4, .settings_grease = 1, \
  .send_grease_frame = 1, .send_priority_update = 1,                           \
  .pseudo_order = k_chrome_pseudo, .pseudo_count = 4

// Navigation request headers in wire order. The two version-specific values
// (sec-ch-ua, user-agent) are parameters; the other 12 rows are stable. The 3rd
// field is the exact HTTP/1.1 wire casing (h2/h3 use the lowercase name).
#define CHROME_NAV_HEADERS(SEC_CH_UA, UA)                                  \
  {"sec-ch-ua", SEC_CH_UA, "sec-ch-ua"},                                   \
      {"sec-ch-ua-mobile", "?0", "sec-ch-ua-mobile"},                      \
      {"sec-ch-ua-platform", "\"Windows\"", "sec-ch-ua-platform"},         \
      {"upgrade-insecure-requests", "1", "Upgrade-Insecure-Requests"},     \
      {"user-agent", UA, "User-Agent"},                                    \
      {"accept",                                                           \
       "text/html,application/xhtml+xml,application/xml;q=0.9,image/"      \
       "avif,image/"                                                       \
       "webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", \
       "Accept"},                                                          \
      {"sec-fetch-site", "none", "Sec-Fetch-Site"},                        \
      {"sec-fetch-mode", "navigate", "Sec-Fetch-Mode"},                    \
      {"sec-fetch-user", "?1", "Sec-Fetch-User"},                          \
      {"sec-fetch-dest", "document", "Sec-Fetch-Dest"},                    \
      {"accept-encoding", "gzip, deflate, br, zstd", "Accept-Encoding"},   \
      {"accept-language", "en-US,en;q=0.9", "Accept-Language"},            \
      {"cookie", "", "Cookie"}, {"priority", "u=0, i", "Priority"}

#define K_CHROME_UA(V)                                                    \
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, " \
  "like Gecko) Chrome/" V ".0.0.0 Safari/537.36"

//- Chrome 148 ---------------------------------------------------------------

global const DefaultHeader k_chrome148_headers[] = {
    CHROME_NAV_HEADERS("\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", "
                       "\"Not/A)Brand\";v=\"99\"",
                       K_CHROME_UA("148"))};

global const Profile k_chrome148 = {
    .name = "chrome148",
    .id = 148,
    .tls = {CHROME_TLS_H2},
    .h2 = {CHROME_H2_FP},
    .default_headers = k_chrome148_headers,
    .default_header_count = ArrayCount(k_chrome148_headers),
    .fetch_order = k_chrome_fetch_order,
    .fetch_order_count = ArrayCount(k_chrome_fetch_order),
};
global const QuicProfile k_chrome148_h3 = {
    .name = "chrome148-h3",
    .id = 148,
    .tls = {CHROME_TLS_H3},
    .h3 = {CHROME_H3_FP},
    .default_headers = k_chrome148_headers,
    .default_header_count = ArrayCount(k_chrome148_headers),
    .fetch_order = k_chrome_fetch_order,
    .fetch_order_count = ArrayCount(k_chrome_fetch_order),
};

//- Chrome 149 ---------------------------------------------------------------
// Wire-identical to 148; only the version strings differ. NOTE the sec-ch-ua is
// not a plain bump: Chrome 149 rotated the GREASE brand token
// ("Not/A)Brand";v="99" -> "Not)A;Brand";v="24") and flipped the brand order —
// copied verbatim from the 149 capture.

global const DefaultHeader k_chrome149_headers[] = {
    CHROME_NAV_HEADERS("\"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", "
                       "\"Not)A;Brand\";v=\"24\"",
                       K_CHROME_UA("149"))};

global const Profile k_chrome149 = {
    .name = "chrome149",
    .id = 149,
    .tls = {CHROME_TLS_H2},
    .h2 = {CHROME_H2_FP},
    .default_headers = k_chrome149_headers,
    .default_header_count = ArrayCount(k_chrome149_headers),
    .fetch_order = k_chrome_fetch_order,
    .fetch_order_count = ArrayCount(k_chrome_fetch_order),
};
global const QuicProfile k_chrome149_h3 = {
    .name = "chrome149-h3",
    .id = 149,
    .tls = {CHROME_TLS_H3},
    .h3 = {CHROME_H3_FP},
    .default_headers = k_chrome149_headers,
    .default_header_count = ArrayCount(k_chrome149_headers),
    .fetch_order = k_chrome_fetch_order,
    .fetch_order_count = ArrayCount(k_chrome_fetch_order),
};

const Profile *profile_chrome148(void) { return &k_chrome148; }
const QuicProfile *profile_chrome148_h3(void) { return &k_chrome148_h3; }
const Profile *profile_chrome149(void) { return &k_chrome149; }
const QuicProfile *profile_chrome149_h3(void) { return &k_chrome149_h3; }
