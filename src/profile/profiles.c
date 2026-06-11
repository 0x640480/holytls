#include "profile/profile.h"

//- wreq template TLS lists (from wreq emulate.rs tls_options_template) --------

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

// ALPN wire form for [h2, http/1.1].
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
    "wreq-template",
    1,
    {
        k_cipher_list, k_curves_list, k_sigalgs_list, TlsVersion_1_2,
        TlsVersion_1_3, k_alpn_wire, sizeof(k_alpn_wire), 0 /*alps*/, 0, 0,
        k_cert_compress, 3, 1 /*grease*/, 0 /*permute*/, 1 /*ocsp*/, 1 /*sct*/,
        1 /*ech_grease*/, 1 /*tickets*/, 1 /*aes_hw*/, 1, 1 /*rand_aes*/,
        0x4001 /*record_size_limit*/, k_delegated_creds, 3 /*key_shares*/,
        k_extension_order,
    },
    {
        k_h2_settings, 4, 12517377, 1 /*priority*/, 0, 41, 0 /*non-excl*/,
        k_pseudo_order, 4,
    },
    0,
    0,
};

//- Chrome 148 shared TLS lists ----------------------------------------------

global const char k_quic_curves[] = "X25519MLKEM768:X25519:P-256:P-384";
global const char k_quic_sigalgs[] =
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
    "rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1";
global const U8 k_alpn_wire_h3[] = {2, 'h', '3'};
global const char *const k_alps_h3[] = {"h3"};
global const char *const k_alps_h2[] = {"h2"};
global const U16 k_quic_cert_compress[] = {CertCompress_Brotli};  // brotli only

//- Chrome 148 HTTP/3 (QUIC) -------------------------------------------------

global const H3Setting k_quic_h3_settings[] = {
    {0x01, 65536},   // QPACK_MAX_TABLE_CAPACITY
    {0x06, 262144},  // MAX_FIELD_SECTION_SIZE
    {0x07, 100},     // QPACK_BLOCKED_STREAMS
    {0x33, 1},       // H3_DATAGRAM
};
global const PseudoId k_quic_pseudo_order[] = {Pseudo_Method, Pseudo_Authority,
                                               Pseudo_Scheme, Pseudo_Path};

// Chrome 148 default request headers, navigation order (from
// fingerprints/browserleaks-*.json). "cookie" is an order-only placeholder.
// The 3rd field is the exact HTTP/1.1 wire casing (mirrors wreq's per-header
// original-case preservation): Chrome sends the sec-ch-ua* client hints lowercase
// but the rest Title-Case. h2/h3 ignore it and use the lowercase `name`.
global const DefaultHeader k_chrome148_headers[] = {
    {"sec-ch-ua",
     "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", "
     "\"Not/A)Brand\";v=\"99\"",
     "sec-ch-ua"},
    {"sec-ch-ua-mobile", "?0", "sec-ch-ua-mobile"},
    {"sec-ch-ua-platform", "\"Windows\"", "sec-ch-ua-platform"},
    {"upgrade-insecure-requests", "1", "Upgrade-Insecure-Requests"},
    {"user-agent",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
     "like Gecko) Chrome/148.0.0.0 Safari/537.36",
     "User-Agent"},
    {"accept",
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/"
     "webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
     "Accept"},
    {"sec-fetch-site", "none", "Sec-Fetch-Site"},
    {"sec-fetch-mode", "navigate", "Sec-Fetch-Mode"},
    {"sec-fetch-user", "?1", "Sec-Fetch-User"},
    {"sec-fetch-dest", "document", "Sec-Fetch-Dest"},
    {"accept-encoding", "gzip, deflate, br, zstd", "Accept-Encoding"},
    {"accept-language", "en-US,en;q=0.9", "Accept-Language"},
    {"cookie", "", "Cookie"},
    {"priority", "u=0, i", "Priority"},
};
#define K_CHROME148_HEADER_COUNT ArrayCount(k_chrome148_headers)

global const QuicProfile k_chrome148_h3 = {
    "chrome148-h3",
    148,
    {
        0 /*cipher_list: TLS1.3-only*/, k_quic_curves, k_quic_sigalgs,
        TlsVersion_1_3, TlsVersion_1_3, k_alpn_wire_h3, sizeof(k_alpn_wire_h3),
        k_alps_h3, 1, 1 /*alps_new*/, k_quic_cert_compress, 1, 1 /*grease*/,
        0 /*permute*/, 0 /*ocsp*/, 0 /*sct*/, 1 /*ech_grease*/, 1 /*tickets*/,
        0, 0, 0, 0 /*record_size_limit*/, 0 /*delegated*/, 2 /*key_shares*/,
        0 /*ext_order*/,
    },
    {
        15728640, 6291456, 6291456, 6291456, 100, 103, 30000, 1472, 65536,
        k_quic_h3_settings, 4, 1 /*settings_grease*/, 1 /*grease_frame*/,
        1 /*priority_update*/, k_quic_pseudo_order, 4,
    },
    k_chrome148_headers,
    K_CHROME148_HEADER_COUNT,
};

//- Chrome 148 HTTP/2 (TCP) --------------------------------------------------

global const char k_chrome_cipher_list[] =  // 12 TLS1.2 suites (capture order)
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
global const char k_chrome_sigalgs[] =  // 8 (no rsa_pkcs1_sha1)
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
    "rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

global const H2Setting k_chrome_h2_settings[] = {
    {H2Setting_HeaderTableSize, 65536},
    {H2Setting_EnablePush, 0},
    {H2Setting_InitialWindowSize, 6291456},
    {H2Setting_MaxHeaderListSize, 262144},
};

global const Profile k_chrome148 = {
    "chrome148",
    148,
    {
        k_chrome_cipher_list, k_quic_curves /*shared*/, k_chrome_sigalgs,
        TlsVersion_1_2, TlsVersion_1_3, k_alpn_wire, sizeof(k_alpn_wire),
        k_alps_h2, 1, 1 /*alps_new*/, k_quic_cert_compress /*brotli*/, 1,
        1 /*grease*/, 1 /*permute*/, 1 /*ocsp*/, 1 /*sct*/, 1 /*ech_grease*/,
        1 /*tickets*/, 0, 0, 0, 0 /*record_size_limit*/, 0 /*delegated*/,
        2 /*key_shares*/, 0 /*ext_order*/,
    },
    {
        k_chrome_h2_settings, 4, 15663105, 1 /*priority*/, 0, 220,
        1 /*exclusive*/, k_quic_pseudo_order /*m,a,s,p*/, 4,
    },
    k_chrome148_headers,
    K_CHROME148_HEADER_COUNT,
};

//- Chrome 149 -------------------------------------------------------------
// Live-verified (2026-06-10) byte-identical to Chrome 148 on every wire field
// across BOTH transports: TCP/H2 ClientHello (powhttp raw capture) and QUIC/H3
// ClientHello + transport params + H3 SETTINGS (browserleaks). The ONLY delta
// is the version strings, so 149 reuses every 148 TLS/H2/H3 constant and only
// swaps the header table. NOTE the sec-ch-ua change is NOT a plain 148->149
// bump: Chrome rotated the GREASE brand token ("Not/A)Brand";v="99" ->
// "Not)A;Brand";v="24") and flipped the brand order — copied verbatim from the
// 149 capture. (The two Google-only QUIC transport params Chrome 149 also sends,
// google_connection_options + initial_rtt, are not modeled — they are invisible
// to JA4/Akamai/h3_hash/QUIC-JA4, which do not hash transport-param contents.)

global const DefaultHeader k_chrome149_headers[] = {
    {"sec-ch-ua",
     "\"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", "
     "\"Not)A;Brand\";v=\"24\"",
     "sec-ch-ua"},
    {"sec-ch-ua-mobile", "?0", "sec-ch-ua-mobile"},
    {"sec-ch-ua-platform", "\"Windows\"", "sec-ch-ua-platform"},
    {"upgrade-insecure-requests", "1", "Upgrade-Insecure-Requests"},
    {"user-agent",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
     "like Gecko) Chrome/149.0.0.0 Safari/537.36",
     "User-Agent"},
    {"accept",
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/"
     "webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
     "Accept"},
    {"sec-fetch-site", "none", "Sec-Fetch-Site"},
    {"sec-fetch-mode", "navigate", "Sec-Fetch-Mode"},
    {"sec-fetch-user", "?1", "Sec-Fetch-User"},
    {"sec-fetch-dest", "document", "Sec-Fetch-Dest"},
    {"accept-encoding", "gzip, deflate, br, zstd", "Accept-Encoding"},
    {"accept-language", "en-US,en;q=0.9", "Accept-Language"},
    {"cookie", "", "Cookie"},
    {"priority", "u=0, i", "Priority"},
};
#define K_CHROME149_HEADER_COUNT ArrayCount(k_chrome149_headers)

// QUIC/H3 — identical TLS+H3 tables to chrome148_h3, only the headers differ.
global const QuicProfile k_chrome149_h3 = {
    "chrome149-h3",
    149,
    {
        0 /*cipher_list: TLS1.3-only*/, k_quic_curves, k_quic_sigalgs,
        TlsVersion_1_3, TlsVersion_1_3, k_alpn_wire_h3, sizeof(k_alpn_wire_h3),
        k_alps_h3, 1, 1 /*alps_new*/, k_quic_cert_compress, 1, 1 /*grease*/,
        0 /*permute*/, 0 /*ocsp*/, 0 /*sct*/, 1 /*ech_grease*/, 1 /*tickets*/,
        0, 0, 0, 0 /*record_size_limit*/, 0 /*delegated*/, 2 /*key_shares*/,
        0 /*ext_order*/,
    },
    {
        15728640, 6291456, 6291456, 6291456, 100, 103, 30000, 1472, 65536,
        k_quic_h3_settings, 4, 1 /*settings_grease*/, 1 /*grease_frame*/,
        1 /*priority_update*/, k_quic_pseudo_order, 4,
    },
    k_chrome149_headers,
    K_CHROME149_HEADER_COUNT,
};

// TCP/H2 — identical TLS+H2 tables to chrome148, only the headers differ.
global const Profile k_chrome149 = {
    "chrome149",
    149,
    {
        k_chrome_cipher_list, k_quic_curves /*shared*/, k_chrome_sigalgs,
        TlsVersion_1_2, TlsVersion_1_3, k_alpn_wire, sizeof(k_alpn_wire),
        k_alps_h2, 1, 1 /*alps_new*/, k_quic_cert_compress /*brotli*/, 1,
        1 /*grease*/, 1 /*permute*/, 1 /*ocsp*/, 1 /*sct*/, 1 /*ech_grease*/,
        1 /*tickets*/, 0, 0, 0, 0 /*record_size_limit*/, 0 /*delegated*/,
        2 /*key_shares*/, 0 /*ext_order*/,
    },
    {
        k_chrome_h2_settings, 4, 15663105, 1 /*priority*/, 0, 220,
        1 /*exclusive*/, k_quic_pseudo_order /*m,a,s,p*/, 4,
    },
    k_chrome149_headers,
    K_CHROME149_HEADER_COUNT,
};

const Profile *profile_template(void) { return &k_template; }
const Profile *profile_chrome148(void) { return &k_chrome148; }
const QuicProfile *profile_chrome148_h3(void) { return &k_chrome148_h3; }
const Profile *profile_chrome149(void) { return &k_chrome149; }
const QuicProfile *profile_chrome149_h3(void) { return &k_chrome149_h3; }

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
