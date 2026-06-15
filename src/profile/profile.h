// Emulation profile model — static, immutable tables that reproduce a browser's
// TLS + HTTP/2 + HTTP/3 fingerprint. Plain C data; the TLS-list strings are
// NUL-terminated literals (fed straight to BoringSSL's string-list setters).
#ifndef HOLYTLS_PROFILE_H
#define HOLYTLS_PROFILE_H

#include "base/base.h"
#include "base/string8.h"

//- TLS ----------------------------------------------------------------------

// Certificate-compression algorithm IDs (RFC 8879 / IANA).
enum {
  CertCompress_Zlib = 0x0001,
  CertCompress_Brotli = 0x0002,
  CertCompress_Zstd = 0x0004,
};

// TLS protocol versions (BoringSSL TLS1_2_VERSION / TLS1_3_VERSION literals, so
// this header needs no openssl include).
enum {
  TlsVersion_1_2 = 0x0303,
  TlsVersion_1_3 = 0x0304,
};

typedef struct TlsProfile TlsProfile;
struct TlsProfile {
  const char *cipher_list;   // ":"-joined TLS1.2 cipher names
  const char *curves_list;   // ":"-joined supported groups
  const char *sigalgs_list;  // ":"-joined signature algorithms
  S32 min_version;
  S32 max_version;
  const U8 *alpn_wire;  // length-prefixed protocol strings (RFC 7301)
  U16 alpn_wire_len;
  const char *const *alps_protocols;  // ALPS protocol names (NUL-terminated)
  U8 alps_count;
  B32 alps_new_codepoint;
  const U16 *cert_compress_algs;
  U8 cert_compress_count;
  B32 grease;
  B32 permute_extensions;
  B32 enable_ocsp_stapling;
  B32 enable_signed_cert_timestamps;
  B32 enable_ech_grease;
  B32 session_tickets;
  B32 aes_hw_override;
  B32 aes_hw_override_value;
  B32 random_aes_hw_override;
  // Fork-backend knobs (lexiforest/boringssl).
  U16 record_size_limit;              // ext 0x1c (0 = unset)
  const char *delegated_credentials;  // ext 0x22 (NULL = unset)
  U8 key_shares_limit;
  const char
      *extension_order;  // dash-separated decimal ext IDs (NULL = default)
  // Emit the legacy extended_master_secret(0x17) + renegotiation_info(0xff01)
  // extensions even in a TLS1.3-only ClientHello (Firefox does this in QUIC,
  // where TLS1.2 can't be offered). BoringSSL suppresses both otherwise.
  B32 force_tls13_legacy_ext;
};

//- HTTP/2 -------------------------------------------------------------------

enum {
  H2Setting_HeaderTableSize = 0x1,
  H2Setting_EnablePush = 0x2,
  H2Setting_MaxConcurrentStreams = 0x3,
  H2Setting_InitialWindowSize = 0x4,
  H2Setting_MaxFrameSize = 0x5,
  H2Setting_MaxHeaderListSize = 0x6,
  H2Setting_EnableConnectProtocol = 0x8,
  H2Setting_NoRfc7540Priorities = 0x9,
};

typedef struct H2Setting H2Setting;
struct H2Setting {
  U16 id;
  U32 value;
};

typedef enum PseudoId {
  Pseudo_Method,
  Pseudo_Scheme,
  Pseudo_Authority,
  Pseudo_Path,
} PseudoId;

typedef struct Http2Profile Http2Profile;
struct Http2Profile {
  const H2Setting *settings;  // in transmission order
  U8 settings_count;
  U32 connection_window_increment;  // stream-0 WINDOW_UPDATE after preface
  B32 use_priority;                 // HEADERS-frame priority
  U32 priority_dep_stream;
  U8 priority_weight;  // 1..256 (nghttp2 convention)
  B32 priority_exclusive;
  const PseudoId *pseudo_order;
  U8 pseudo_count;
};

//- default request headers --------------------------------------------------

// A default header a browser sends, in wire order. An empty value is an
// order-only placeholder (e.g. "cookie") emitted only when the caller fills it.
typedef struct DefaultHeader DefaultHeader;
struct DefaultHeader {
  const char *name;   // lowercase (HTTP/2 + HTTP/3 wire + lookup)
  const char *value;  // "" = order-only placeholder
  const char
      *wire_name;  // exact HTTP/1.1 wire casing; NULL -> title-case `name`
};

//- HTTP/3 -------------------------------------------------------------------

typedef struct H3Setting H3Setting;
struct H3Setting {
  U64 id;
  U64 value;
};

typedef struct Http3Profile Http3Profile;
struct Http3Profile {
  U64 initial_max_data;
  U64 initial_max_stream_data_bidi_local;
  U64 initial_max_stream_data_bidi_remote;
  U64 initial_max_stream_data_uni;
  U64 initial_max_streams_bidi;
  U64 initial_max_streams_uni;
  U64 max_idle_timeout_ms;
  U64 max_udp_payload_size;
  U64 max_datagram_frame_size;
  const H3Setting *settings;
  U8 settings_count;
  B32 settings_grease;
  B32 send_grease_frame;
  B32 send_priority_update;
  const PseudoId *pseudo_order;
  U8 pseudo_count;
};

//- combined profiles --------------------------------------------------------

// Header order for fetch/XHR (non-navigation) requests, which a browser orders
// differently from navigations (client-hint block reordered, content-length
// first, origin/referer in fixed mid-list slots, no UIR/sec-fetch-user). Names
// absent from a given request are skipped. fetch_order == 0 => reuse the
// navigation order (default_headers).
typedef struct Profile Profile;
struct Profile {
  const char *name;
  U32 id;
  TlsProfile tls;
  Http2Profile h2;
  const DefaultHeader *default_headers;
  U8 default_header_count;
  const char *const *fetch_order;
  U8 fetch_order_count;
};

typedef struct QuicProfile QuicProfile;
struct QuicProfile {
  const char *name;
  U32 id;
  TlsProfile tls;
  Http3Profile h3;
  const DefaultHeader *default_headers;
  U8 default_header_count;
  const char *const *fetch_order;
  U8 fetch_order_count;
};

const Profile *profile_template(void);
// Chrome — defined in src/profile/chrome.c. 149 is wire-identical to 148 except
// the version strings (live-verified byte-exact JA4/Akamai/h3_hash/QUIC-JA4).
const Profile *profile_chrome148(void);
const QuicProfile *profile_chrome148_h3(void);
const Profile *profile_chrome149(void);
const QuicProfile *profile_chrome149_h3(void);
// Firefox — defined in src/profile/firefox.c.
const Profile *profile_firefox151(void);
const QuicProfile *profile_firefox151_h3(void);

//- profile registry ---------------------------------------------------------
// The single source of truth for which browser profiles exist. Each entry pairs
// a stable name + id with the TCP/H2 and QUIC/H3 accessors; entry[0] is the
// default ("newest"). Adding a browser = one new row (in src/profile/profiles.c)
// + its data file. Selection is by name (the capi / Python layers resolve here).
typedef struct ProfileEntry ProfileEntry;
struct ProfileEntry {
  U32 id;
  const char *name;                // canonical, e.g. "chrome149"
  const Profile *(*h2)(void);      // TCP/H2 accessor
  const QuicProfile *(*h3)(void);  // QUIC/H3 accessor
};
const ProfileEntry *profile_registry(U64 *count);       // entry[0] = default
const Profile *profile_by_name(String8 name);           // 0 if unknown
const QuicProfile *profile_quic_by_name(String8 name);  // 0 if unknown

//- default-header accessors -------------------------------------------------
// First-class access to a profile's static request-header values (the bytes the
// profile ships in its default_headers table). Each returns a view into the
// static literal, or str8_zero() if the profile doesn't declare that header.

// Generic by (case-insensitive) name. Works for a Profile or a QuicProfile
// table (both expose default_headers/default_header_count) and any other
// DefaultHeader array, e.g. profile_default_header(qp->default_headers,
// qp->default_header_count, str8_lit("user-agent")).
String8 profile_default_header(const DefaultHeader *defaults, U8 count,
                               String8 name);

// Typed convenience over a Profile's common headers. (Chrome's H2 and H3
// profiles share one header table, so these read the same on either transport.)
String8 profile_user_agent(const Profile *p);
String8 profile_sec_ch_ua(const Profile *p);
String8 profile_sec_ch_ua_mobile(const Profile *p);
String8 profile_sec_ch_ua_platform(const Profile *p);
String8 profile_accept(const Profile *p);
String8 profile_accept_language(const Profile *p);
String8 profile_accept_encoding(const Profile *p);

#endif  // HOLYTLS_PROFILE_H
