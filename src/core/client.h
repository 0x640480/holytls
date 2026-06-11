// Client — the holytls public surface. Issues async HTTPS requests on a libuv
// loop using an emulation profile, reproducing that profile's TLS + HTTP/2 (and,
// in dual-transport mode, HTTP/3) fingerprint. Chrome-style: requests go over H2
// first; when an origin advertises HTTP/3 via `alt-svc`, later requests to that
// origin use QUIC.
#ifndef HOLYTLS_CLIENT_H
#define HOLYTLS_CLIENT_H

#include "base/base.h"
#include "base/string8.h"
#include "core/header.h"
#include "core/sec_fetch.h"
#include "net/dns_cache.h"
#include "net/loop.h"
#include "net/proxy.h"
#include "profile/profile.h"
#include "tls/cert_pin.h"
#include "tls/ssl_ctx.h"

typedef struct yyjson_doc yyjson_doc;  // core/json.h (for response_json)

typedef enum Method {
  Method_GET,
  Method_POST,
  Method_PUT,
  Method_DELETE,
  Method_HEAD,
  Method_PATCH,
  Method_OPTIONS,
} Method;

// Wire-protocol selection (see client_set_http_version). Forced modes are strict
// (no fallback); Auto is the Chrome-faithful default.
typedef enum HttpVersion {
  HttpVersion_Auto,  // default: H2 first, then QUIC once an origin advertises
                     // alt-svc: h3 (exactly what Chrome does; never cold-starts H3)
  HttpVersion_H1,    // force HTTP/1.1: advertise http/1.1-only ALPN. NOTE: this
                     // changes the ClientHello (ALPN + drops the h2-only ALPS ext),
                     // so the fingerprint is NOT Chrome's h2 fingerprint.
  HttpVersion_H2,    // force HTTP/2 over TCP (never H3); ClientHello unchanged.
  HttpVersion_H3,    // force HTTP/3/QUIC on the first request (no alt-svc warmup).
                     // Requires a dual client (client_init_dual); else requests error.
} HttpVersion;

// Per-request timing breakdown (milliseconds). For HTTP/3, tcp_ms is 0 and tls_ms
// covers the combined QUIC handshake. Connection-setup phases (dns/tcp/tls) are 0
// when the request reused a warm pooled connection (no setup performed). total_ms
// spans the whole request — the entire redirect chain when redirects are followed.
typedef struct Timing Timing;
struct Timing {
  U64 dns_ms;    // DNS resolution
  U64 tcp_ms;    // TCP connect (0 for HTTP/3)
  U64 tls_ms;    // TLS handshake (HTTP/3: the combined QUIC handshake)
  U64 total_ms;  // request start -> response delivered
};

typedef struct Response Response;
struct Response {
  B32 ok;               // transport/TLS/HTTP success (NOT the HTTP status)
  const char *error;    // set when !ok
  int status;           // HTTP status code
  const Header *headers;  // valid only during the callback
  U64 header_count;
  const U8 *body;  // valid only during the callback
  U64 body_len;
  String8 alpn;       // negotiated ALPN ("h2" / "h3")
  B32 resumed;        // the TLS handshake resumed a cached session (1-RTT)
  B32 early_data;     // the request was sent + accepted as 0-RTT early data
  String8 final_url;  // URL that produced this response (after any redirects)
  Timing timing;      // where the request spent its time (ms)
};

typedef void (*ResponseFn)(void *user, const Response *resp);

// --- Response convenience accessors (call within the response callback) -------
// The raw body as a String8 view (bytes == text); valid only during the callback.
String8 response_text(const Response *r);
// Case-insensitive lookup of a response header value; {0,0} if absent.
String8 response_get_header(const Response *r, String8 name);
// True if the request succeeded transport-wise AND the status is 2xx.
B32 response_is_success(const Response *r);
// True if the status is a 3xx redirect.
B32 response_is_redirect(const Response *r);
// Parse the body as JSON into `arena` (0 on empty / parse error); navigate the
// result with core/json.h. Equivalent to json_parse(arena, response_text(r)).
yyjson_doc *response_json(const Response *r, Arena *arena);

// Request/response middleware (set once on the Client; see client_set_pre_hook /
// client_set_post_hook). Both fire on the loop thread, once per WIRE request /
// response (each redirect or session hop included).
typedef struct HookRequest HookRequest;
struct HookRequest {
  Method method;        // read-only
  String8 url;          // read-only
  HeaderList *headers;  // mutate only via hook_request_set_header
};
// Pre-request hook: fires after all fingerprint-driven headers are assembled,
// just before the request is written. Add/modify headers via
// hook_request_set_header. The return value is reserved (return 0); the URL is
// read-only.
typedef int (*PreRequestHook)(HookRequest *req, void *user);
// Post-response hook: fires with the fully-assembled Response (status, headers,
// body) just before the caller's ResponseFn. headers/body are valid only for the
// duration of the call (same contract as ResponseFn). May post-process in place.
typedef void (*PostResponseHook)(Response *resp, void *user);

typedef struct AltSvcEntry AltSvcEntry;
struct AltSvcEntry {
  char origin[256];  // host:port
  B32 h3;
  U64 expiry_ms;
};

// Per-origin ECH config cache (mirrors AltSvcEntry). config_len==0 means the
// origin publishes no ECH config (we cached the negative result -> use GREASE).
typedef struct EchConfigEntry EchConfigEntry;
struct EchConfigEntry {
  char origin[256];  // host:port
  U8 config[512];    // serialized ECHConfigList
  U64 config_len;
  U64 expiry_ms;
};

// Per-origin TLS session (ticket) cache for 1-RTT resumption. Holds the most
// recent SSL_SESSION the origin issued; the client owns its reference and frees
// it (SSL_SESSION_free) on replacement or client_cleanup.
typedef struct ResumeCacheEntry ResumeCacheEntry;
struct ResumeCacheEntry {
  char origin[256];      // host:port
  SSL_SESSION *session;  // owned; offered via SSL_set_session on reconnect
  U8 zrtt_tp[256];       // ngtcp2-encoded 0-RTT transport params (QUIC), paired
  U64 zrtt_tp_len;       // with `session`; 0 = none cached
  U64 last_used_ms;      // uv_now stamp; LRU eviction when the cache is full
};

// Connection-pool reuse counters (a test/observability signal).
typedef struct PoolStats PoolStats;
struct PoolStats {
  U64 conns_created;  // pooled connections whose handshake was started
  U64 requests;       // requests dispatched through the pool
  U64 reuses;         // requests submitted onto an already-established conn
};

typedef struct ConnPool ConnPool;  // defined in core/pool.h

#define CLIENT_HEADER_ORDER_MAX 32  // header-order override capacity

typedef struct Client Client;
struct Client {
  EventLoop *loop;
  const Profile *profile;
  const QuicProfile *h3_profile;  // 0 in H2-only mode
  CtxResult ctx;                  // H2/TCP
  CtxResult h3_ctx;               // QUIC (built only in dual-transport mode)
  AltSvcEntry alt_svc[32];
  int alt_svc_count;
  EchConfigEntry ech_cache[32];  // per-origin ECHConfigList cache (real ECH)
  int ech_cache_count;
  B32 ech_enabled;    // fetch + offer real ECH (off by default)
  U64 max_redirects;  // 0 = don't follow 3xx (default); else follow up to this many
  U64 timeout_ms;     // whole-operation request timeout; 0 = off (default)

  ResumeCacheEntry resume_cache[64];  // per-origin TLS ticket cache (resumption)
  int resume_cache_count;
  B32 resume_enabled;      // offer cached tickets for 1-RTT resumption (off by default)
  B32 early_data_enabled;  // attempt 0-RTT early data for idempotent requests (off)

  // Connection pooling (opt-in; all zero/off after client_init).
  ConnPool *pool;             // 0 = pooling OFF (lazily allocated by the setter)
  U64 max_conns_per_origin;   // 0 = OFF; Chrome-like = 1 (one multiplexed conn)
  U64 pool_idle_timeout_ms;   // 0 = default (5000)
  PoolStats pool_stats;       // reuse counters (see client_pool_stats)

  CertPinStore pin_store;     // certificate pins (opt-in; empty = no pinning)

  // Request/response middleware (opt-in; null = no hook, zero overhead).
  PreRequestHook pre_hook;
  void *pre_hook_user;
  PostResponseHook post_hook;
  void *post_hook_user;

  DnsCache dns_cache;  // in-memory host->address cache (on by default; see setter)

  HttpVersion http_version;  // wire-protocol selection (Auto by default)
  TlsProfile h1_tls;         // profile->tls with http/1.1-only ALPN (built when H1)

  // Forward proxy (opt-in; ProxyType_None = direct). proxy_ctx/proxy_tls are
  // built only for an HTTPS proxy (the outer TLS handshake to the proxy itself).
  ProxyConfig proxy;
  CtxResult proxy_ctx;
  TlsProfile proxy_tls;

  // Header-order override (advanced; count 0 => the profile's default order). The
  // name bytes live in header_order_buf; header_order[] are views into it.
  String8 header_order[CLIENT_HEADER_ORDER_MAX];
  char header_order_buf[CLIENT_HEADER_ORDER_MAX][64];
  U8 header_order_count;

  B32 override_default_headers;  // send only the caller's headers (no profile
                                 // defaults / accept-encoding); order via
                                 // header_order

  int in_callback;  // depth of user response callbacks on the stack; guards
                    // against client_cleanup from inside a callback (a UAF)
};

// HTTP/2-only client (the profile's TLS+H2 fingerprint over TCP).
void client_init(Client *c, EventLoop *loop, const Profile *profile, B32 verify);
// Chrome-style dual-transport client (H2 first, QUIC after alt-svc discovery).
void client_init_dual(Client *c, EventLoop *loop, const Profile *h2,
                      const QuicProfile *h3, B32 verify);
// Tear the client down. Re-entrancy contract: a Client (like everything here)
// is single-threaded — drive it only from its loop's thread — and a response
// callback may issue NEW requests on the client but must NOT call
// client_cleanup (the delivery path still touches client state after the
// callback returns; debug builds assert). Tear down after loop_run returns, or
// defer it past the callback (e.g. uv_timer with 0 timeout).
void client_cleanup(Client *c);
B32 client_ok(Client *c);

// Follow up to `max` 3xx redirects (browser-faithful: 301/302 POST->GET, 303->GET,
// 307/308 preserve method+body; cross-origin drops Authorization). 0 disables
// (the default). Response.final_url reports where the chain ended.
void client_set_max_redirects(Client *c, U64 max);

// Set a whole-operation request timeout in milliseconds (0 = off, the default). A
// request that doesn't fully complete within `ms` — covering DNS + connect + TLS +
// the response body AND the entire redirect chain — fails with an error
// ("timeout") and its connection is torn down. The budget is a single deadline for
// the whole call (not per-redirect-hop).
void client_set_timeout_ms(Client *c, U64 ms);
U64 client_get_timeout_ms(Client *c);

// (internal) Single wire request carrying an absolute deadline (uv_hrtime ns; 0 =
// none). The Session layer uses this so one chain-wide deadline spans every hop.
void client_send_deadline(Client *c, Method m, String8 url, const Header *headers,
                          U64 header_count, const U8 *body, U64 body_len,
                          ResponseFn cb, void *user, U64 deadline_ns);

// Enable real ECH (Encrypted Client Hello). Before connecting to a new origin the
// client fetches its ECHConfigList from DNS (HTTPS RR, type 65, via DoH over
// dns.google), caches it, and offers real ECH — encrypting the inner ClientHello
// and sending the config's public_name as the outer SNI. Falls back to ECH-GREASE
// (Chrome's default) for origins that publish no config. OFF by default: it adds
// one DNS-over-HTTPS round-trip per new origin.
void client_set_ech_enabled(Client *c, B32 on);

// Enable TLS 1.3 session resumption (ticket reuse). The client caches the
// SSL_SESSION each origin issues (its NewSessionTicket) and, on the next
// connection to that origin, offers it for an abbreviated 1-RTT handshake —
// skipping the full key-exchange + certificate verification, exactly as a real
// browser does on a repeat visit. The first connection to an origin is always a
// fresh full handshake (byte-exact fingerprint); only reconnects resume, where
// the ClientHello carries pre_shared_key/psk_key_exchange_modes (the resumed-
// handshake fingerprint). Response.resumed reports whether a request resumed. OFF
// by default so the default path stays a byte-exact fresh handshake every time.
void client_set_resumption_enabled(Client *c, B32 on);

// Enable TLS 1.3 0-RTT early data. When a cached ticket is 0-RTT-capable, an
// idempotent bodyless request (GET/HEAD) is written as early data DURING the
// handshake, saving a full round-trip. Requires resumption to also be enabled
// (0-RTT needs a cached session). Replay safety: only GET/HEAD with no body are
// ever sent as early data; if the server rejects 0-RTT the request is retried on
// a fresh 1-RTT connection. The 0-RTT ClientHello carries the early_data
// extension (a distinct fingerprint from fresh/1-RTT-resumed), so this is OFF by
// default. Response.early_data reports whether 0-RTT was accepted.
void client_set_early_data_enabled(Client *c, B32 on);

// Set the in-memory DNS cache TTL in milliseconds; 0 disables caching. Repeat
// connections to a host within the TTL skip the DNS lookup (fingerprint-neutral —
// the cached address is what getaddrinfo would return). On by default
// (DNS_CACHE_DEFAULT_TTL_MS ~= 60s).
void client_set_dns_cache_ttl_ms(Client *c, U64 ms);

// Pin the wire protocol (default HttpVersion_Auto). HttpVersion_H3 requires a
// dual-transport client (client_init_dual); forcing it on an H2-only client makes
// requests fail with an error. Forced modes do not fall back. See HttpVersion.
void client_set_http_version(Client *c, HttpVersion v);

// Override the wire header ORDER for outgoing requests (advanced). `names` lists
// header names (matched case-insensitively) in the desired order; any header that
// would be sent and is named here is emitted in that position, and headers not
// named follow in their default order (none are dropped). `count == 0` resets to
// the profile's default order. Names are copied (the caller need not keep them).
// Returns 1, or 0 if `count` exceeds CLIENT_HEADER_ORDER_MAX. WARNING: a custom
// order deviates from the byte-exact Chrome header-order fingerprint.
B32 client_set_header_order(Client *c, const String8 *names, U64 count);

// Convenience form: header names as one comma- and/or whitespace-separated string
// (e.g. "accept, accept-language, user-agent"). An empty string resets to the
// profile order. Same semantics + return as client_set_header_order.
B32 client_set_header_order_str(Client *c, const char *names);

// The current header order: the override if one is set, else the profile's default
// header names in order. Fills up to `cap` entries (views valid while the Client
// lives); returns the total count (which may exceed `cap`).
U64 client_get_header_order(Client *c, String8 *out, U64 cap);

// Override the profile's default request headers (advanced; off by default). When
// on, holytls sends EXACTLY the per-request `headers` array and drops every profile
// default (sec-ch-ua, sec-fetch-*, accept, accept-encoding, …); only
// Content-Length is still auto-added for a request body. The wire order is the
// array order, but client_set_header_order still applies if set — the two
// compose, so you can specify the header SET via the array and the ORDER via
// client_set_header_order (the equivalent of Go bogdanfinn's req.Header +
// http.HeaderOrderKey). WARNING: this abandons the byte-exact Chrome header
// fingerprint — the TLS/H2/H3 fingerprint is unchanged, but the request header
// set + order are whatever you pass.
void client_override_default_headers(Client *c, B32 on);
B32 client_get_override_default_headers(Client *c);

// Route every request through a forward proxy, parsed from `proxy_url`:
//   http://, https://, socks5://, socks5h://, with optional user:pass@ for auth.
// http/socks5 negotiate in plaintext then run the target TLS over the tunnel; an
// https proxy adds an outer TLS handshake to the proxy first (verify_proxy gates
// its certificate check). The target's TLS fingerprint is unchanged either way.
// A proxy forces the TCP path (H2/H1) — HTTP/3 is not proxied. Returns 1 on a
// valid URL, 0 on a malformed one (leaving the client direct). Off by default.
B32 client_set_proxy(Client *c, String8 proxy_url, B32 verify_proxy);

// The current proxy as a URL ("scheme://[user:pass@]host:port") in `arena`, or
// {0,0} when direct (no proxy). holytls uses a single proxy config — a SOCKS5
// proxy serves both TCP (H1/H2) and UDP (H3); HTTP/HTTPS proxies serve TCP only.
String8 client_get_proxy(Client *c, Arena *arena);

// Trust an extra CA certificate file (PEM) for server verification, on top of the
// system roots (applies to both the H2 and H3 contexts). Returns 1 on success, 0
// if the file can't be read/parsed. Only effective on a verify=1 client. Primary
// use: a MITM debugging proxy (powhttp / mitmproxy / Burp) whose root CA signs the
// per-host certs it presents — adding that root lets the proxied (decrypted, then
// re-encrypted) connection still verify, so you can inspect the exact wire bytes
// holytls sends without turning verification off. Pair with client_set_proxy; call
// after client_init / client_init_dual.
B32 client_add_ca_file(Client *c, const char *path);

// Pin the server certificate for `hostname`: a connection to it is accepted only
// if the leaf certificate's SubjectPublicKeyInfo SHA-256 matches `sha256_b64`
// (base64, HPKP / Chrome DevTools format). Multiple pins per host are allowed
// (any match accepts — use this for backup pins). With include_subdomains the pin
// also covers subdomains of `hostname`. A pin match is the trust decision: it
// overrides the normal CA check (a pinned self-signed cert is accepted), and any
// other certificate — even a CA-valid one — is rejected. Non-pinned hosts keep
// normal verification. Returns 1 if the pin was added, 0 on a bad base64 hash
// (must decode to 32 bytes) or a full pin table. Pin before connecting.
B32 client_pin_certificate(Client *c, const char *hostname,
                           const char *sha256_b64, B32 include_subdomains);

// Write this client's TLS (and QUIC) session secrets to `path` in NSS Key Log
// Format so its traffic can be decrypted in Wireshark. One file decrypts both
// HTTPS and QUIC (QUIC keys derive from the same TLS 1.3 secrets). Equivalent to
// setting the SSLKEYLOGFILE environment variable, which is honored automatically.
// For debugging only; OFF by default. Process-global: the first destination set
// for the process wins (matching SSLKEYLOGFILE). Safe to call after client_init.
void client_set_key_log_file(Client *c, const char *path);

// Install request/response middleware (set once; fn=0 disables). The pre-hook
// runs after the profile's fingerprint headers are assembled, before each wire
// request; the post-hook runs with each response, before the per-request
// callback. Both fire on the loop thread, once per wire hop. See PreRequestHook /
// PostResponseHook. Off by default (zero overhead when unset).
void client_set_pre_hook(Client *c, PreRequestHook fn, void *user);
void client_set_post_hook(Client *c, PostResponseHook fn, void *user);

// From a pre-hook: add `name: value`, or override the value if `name` already
// exists (case-insensitive). Refuses the fingerprint-controlled headers
// (User-Agent, Accept-Encoding, Sec-Fetch-*, Sec-Ch-Ua-*) — returns 1 if set, 0
// if refused. The name/value bytes are copied into the request's arena.
B32 hook_request_set_header(HookRequest *req, String8 name, String8 value);

void client_request(Client *c, Method m, String8 url, const Header *headers,
                    U64 header_count, const U8 *body, U64 body_len,
                    ResponseFn cb, void *user);
void client_get(Client *c, String8 url, ResponseFn cb, void *user);

// Single request, no redirect following (regardless of the client's
// max_redirects). The caller handles redirects. Used by the Session layer, which
// runs its own cookie-aware redirect loop on a shared client.
void client_send(Client *c, Method m, String8 url, const Header *headers,
                 U64 header_count, const U8 *body, U64 body_len, ResponseFn cb,
                 void *user);

// Like client_request, but attaches Sec-Fetch-* headers coherent with `mode` and
// the request's context (Sec-Fetch-Site is computed from a Referer header if
// present), instead of the profile's static navigation defaults. Use
// FetchMode_Cors for API/XHR requests, FetchMode_Navigate for page loads.
void client_fetch(Client *c, FetchMode mode, Method m, String8 url,
                  const Header *headers, U64 header_count, const U8 *body,
                  U64 body_len, ResponseFn cb, void *user);

// True if `origin` ("host:port") is known (via alt-svc) to support live HTTP/3.
B32 client_h3_available(Client *c, String8 origin);

// (exposed for testing) browser-faithful next method for a `status` redirect of
// method `m`; sets *drop_body when the request body should be dropped.
Method redirect_next_method(Method m, int status, B32 *drop_body);

// --- Connection pooling (opt-in; default OFF) -------------------------------
// Reuse + multiplex H2/H3 connections per origin. `max`==0 disables pooling (the
// default: every request takes the legacy per-request path, byte-for-byte
// identical). Chrome-like value is 1 (one multiplexed connection per origin; a
// 2nd only when the server's MAX_CONCURRENT_STREAMS is hit). H1 origins are never
// pooled (they fall back to the per-request path transparently).
void client_set_max_conns_per_origin(Client *c, U64 max);
// Idle pooled conns past `ms` are swept + closed. 0 = default (5000 ms).
void client_set_pool_idle_timeout_ms(Client *c, U64 ms);
// Reuse counters (conns_created / requests / reuses). Zero when pooling is off.
PoolStats client_pool_stats(Client *c);
// Begin closing all pooled connections (e.g. before tearing down the loop).
// client_cleanup calls this automatically.
void client_pool_drain(Client *c);

#endif  // HOLYTLS_CLIENT_H
