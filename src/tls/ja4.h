// Offline JA3 / JA4 computation from raw ClientHello bytes. Used to measure the
// fingerprint a profile actually produces and diff it against the goldens. The
// parsed ClientHello fields are bounded inline arrays (no allocation in the hot
// parse path); compute() builds the fingerprint strings on a caller arena.
#ifndef HOLYTLS_JA4_H
#define HOLYTLS_JA4_H

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

enum {
  JA4_MAX_CIPHERS = 128,
  JA4_MAX_EXTS = 128,
  JA4_MAX_GROUPS = 64,
  JA4_MAX_ECPF = 32,
  JA4_MAX_SV = 32,
  JA4_MAX_SIGALGS = 64,
  JA4_MAX_ALPN = 32,
};

typedef struct ClientHelloInfo ClientHelloInfo;
struct ClientHelloInfo {
  B32 ok;
  char transport;  // 't' = TCP/TLS, 'q' = QUIC (JA4 first char)
  U16 legacy_version;
  U16 cipher_suites[JA4_MAX_CIPHERS];  // wire order (GREASE included)
  U64 cipher_count;
  U16 extensions[JA4_MAX_EXTS];  // wire order
  U64 ext_count;
  U16 supported_groups[JA4_MAX_GROUPS];  // ext 0x000a
  U64 group_count;
  U8 ec_point_formats[JA4_MAX_ECPF];  // ext 0x000b
  U64 ecpf_count;
  U16 supported_versions[JA4_MAX_SV];  // ext 0x002b
  U64 sv_count;
  U16 sig_algs[JA4_MAX_SIGALGS];  // ext 0x000d (order preserved)
  U64 sig_count;
  B32 has_sni;                       // ext 0x0000
  char alpn_first[JA4_MAX_ALPN];     // first protocol in ext 0x0010
  U64 alpn_len;
};

// Parse a TLS record carrying a ClientHello (TCP), or a raw handshake message
// (QUIC, no record header). Returns ok=false on malformed input.
ClientHelloInfo ja4_parse_record(const U8 *rec, U64 len);
ClientHelloInfo ja4_parse_handshake(const U8 *hs_msg, U64 len);

typedef struct Fingerprints Fingerprints;
struct Fingerprints {
  String8 ja4;      // e.g. t13d1717h2_5b57614c22b0_3cbfd9057e0d
  String8 ja4_r;    // raw pre-hash form
  String8 ja3;      // md5 hex
  String8 ja3_str;  // raw JA3 string
};
Fingerprints ja4_compute(Arena *arena, const ClientHelloInfo *in);

B32 ja4_is_grease(U16 v);
String8 ja4_sha256_hex(Arena *arena, String8 s, U64 hex_chars);

#endif  // HOLYTLS_JA4_H
