// Proxy support — config + wire framing for routing requests through a forward
// proxy. holytls always speaks TLS to the origin, so a proxy is a transport-layer
// concern: connect to the proxy, negotiate a tunnel (HTTP CONNECT or SOCKS5),
// then run the normal byte-exact target-TLS handshake over that tunnel. This
// header is the pure (no I/O) layer: parsing a proxy URL and building/parsing the
// negotiation bytes. net/connection.c drives the async exchange.
#ifndef HOLYTLS_PROXY_H
#define HOLYTLS_PROXY_H

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

typedef enum ProxyType {
  ProxyType_None,
  ProxyType_Http,    // plaintext TCP to the proxy, then a CONNECT tunnel
  ProxyType_Https,   // TLS to the proxy, then CONNECT inside it (nested TLS)
  ProxyType_Socks5,  // SOCKS5 (RFC 1928); proxy-side DNS (ATYP=DOMAINNAME)
} ProxyType;

typedef struct ProxyConfig ProxyConfig;
struct ProxyConfig {
  ProxyType type;
  char host[256];
  U16 port;
  char user[128];  // empty (user[0]==0) => no authentication
  char pass[128];
};

// Parse "scheme://[user:pass@]host[:port]" into *out (zeroed first). Schemes:
// http, https, socks5, socks5h (socks5h == socks5 here — both proxy-side DNS).
// Default ports: http=80, https=443, socks5=1080. IPv6 hosts must be bracketed
// ("[::1]"). Returns 0 on a malformed URL or unknown scheme.
B32 proxy_parse(String8 url, ProxyConfig *out);

// Reconstruct a proxy URL "scheme://[user:pass@]host:port" from `p` into `arena`
// (the inverse of proxy_parse; credentials included). {0,0} for ProxyType_None.
String8 proxy_to_url(Arena *arena, const ProxyConfig *p);

// --- HTTP(S) CONNECT framing (RFC 9110 §9.3.6) ------------------------------
// Build the CONNECT request (arena-allocated):
//   CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n
//   [Proxy-Authorization: Basic <base64(user:pass)>\r\n]\r\n
String8 proxy_http_connect_request(Arena *arena, const ProxyConfig *p,
                                   String8 target_host, U16 target_port);
// Scan an accumulating CONNECT response. When the header terminator (\r\n\r\n) is
// present, sets *complete=1 and *status to the parsed HTTP status; returns the
// number of header bytes consumed (so the caller can detect trailing data).
// Until then sets *complete=0, *status=0 and returns 0.
U64 proxy_http_response_status(const U8 *buf, U64 len, B32 *complete, int *status);

// --- SOCKS5 framing (RFC 1928 + RFC 1929 user/pass) -------------------------
// Greeting: 05, nmethods, methods (00 no-auth, +02 user/pass when creds set).
U64 proxy_socks5_greeting(const ProxyConfig *p, U8 *out, U64 cap);
// Method-selection reply (2 bytes): *method <- server choice. Returns 1 if parsed.
B32 proxy_socks5_parse_method(const U8 *buf, U64 len, U8 *method);
// Username/password sub-negotiation request: 01, ulen, user, plen, pass.
U64 proxy_socks5_userpass(const ProxyConfig *p, U8 *out, U64 cap);
// User/pass auth reply (2 bytes): *ok <- (status==0). Returns 1 if parsed.
B32 proxy_socks5_parse_userpass_reply(const U8 *buf, U64 len, B32 *ok);
// CONNECT request, ATYP=DOMAINNAME (the proxy resolves the target):
//   05 01 00 03 len host... port_hi port_lo
U64 proxy_socks5_connect_request(String8 target_host, U16 target_port, U8 *out,
                                 U64 cap);
// Parse the variable-length SOCKS5 reply (CONNECT or UDP ASSOCIATE). *complete=1
// once the whole reply is present (BND.ADDR length depends on its ATYP); *ok <-
// (REP==0). When non-null, *bnd_atyp / *bnd_addr / *bnd_port surface the bound
// endpoint (the UDP relay for an ASSOCIATE reply); *bnd_addr points into `buf`.
// Returns the reply length when complete, else 0.
U64 proxy_socks5_parse_reply(const U8 *buf, U64 len, B32 *complete, B32 *ok,
                             U8 *bnd_atyp, const U8 **bnd_addr, U16 *bnd_port);

// --- SOCKS5 UDP ASSOCIATE (RFC 1928 §7), for tunneling QUIC ------------------
// UDP ASSOCIATE request over the TCP control channel: 05 03 00 01 0.0.0.0 :0
// (CMD=UDP ASSOCIATE, ATYP=IPv4, DST=0.0.0.0:0 — "any" source). 10 bytes.
U64 proxy_socks5_udp_associate_request(U8 *out, U64 cap);
// Per-datagram UDP request header that prefixes each tunneled packet:
//   RSV(00 00) FRAG(00) ATYP ADDR PORT. `atyp` is 0x01 (IPv4, addrlen 4) or 0x04
// (IPv6, addrlen 16); `addr` is the target's resolved address bytes. Returns the
// header length written, 0 if it doesn't fit.
U64 proxy_socks5_udp_request_header(U8 *out, U64 cap, U8 atyp, const U8 *addr,
                                    U64 addrlen, U16 port);
// Length of the SOCKS5 UDP header at the front of an inbound relayed datagram
// (so the caller can strip it before the payload). 0 if malformed/too short.
U64 proxy_socks5_udp_header_len(const U8 *buf, U64 len);

#endif  // HOLYTLS_PROXY_H
