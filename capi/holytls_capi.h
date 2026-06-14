// holytls_capi — a flat, FFI-stable C ABI over the holytls client. This is the
// surface language bindings (Python/cffi, Go/cgo, Node, …) bind against: plain
// `stdint` scalars, NUL-terminated `char *`, length-carrying byte buffers, and
// opaque handles — none of holytls's internal types (String8, Arena, Header,
// the async ResponseFn callback) cross this boundary.
//
// The hard problem this layer solves: holytls is ASYNC and single-threaded
// around one libuv loop — there is no blocking `client.Do()`. A binding wants a
// synchronous call. So the shim owns the loop and drives it: holytls_perform()
// submits one request, runs the loop until that single response lands, copies
// the response out of holytls's "valid only during the callback" views into
// heap memory the caller owns, and returns it. holytls_perform_many() submits N
// requests onto the SAME loop and runs it once until all complete — the native,
// zero-thread concurrency that is the whole point of an event-loop client.
//
// Ownership: every holytls_response* this returns is heap-allocated and owned by
// the caller — free it with holytls_response_free(). A holytls_client/_session
// is created explicitly and freed with its _free(). Strings the caller passes in
// (url, header names/values, proxy URL, …) are copied as needed during the
// call; the caller may free them immediately after the call returns.
//
// Threading: a holytls_client owns its own loop + transport and is NOT
// internally locked — drive one client from one thread at a time. For
// concurrency, either submit a batch (holytls_perform_many, one loop, many
// in-flight requests) or use one client per thread (each fully independent).
#ifndef HOLYTLS_CAPI_H
#define HOLYTLS_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Enums (mirror the holytls public enums; mapped explicitly in the impl so a
// reordering on either side is a compile-time fix, not silent breakage).
// ---------------------------------------------------------------------------

typedef enum holytls_method {
  HOLYTLS_GET = 0,
  HOLYTLS_POST,
  HOLYTLS_PUT,
  HOLYTLS_DELETE,
  HOLYTLS_HEAD,
  HOLYTLS_PATCH,
  HOLYTLS_OPTIONS,
} holytls_method;

// Wire-protocol selection (see holytls_client_set_http_version). Auto is the
// Chrome-faithful default (H2, then H3 once an origin advertises alt-svc: h3).
typedef enum holytls_http_version {
  HOLYTLS_HTTP_AUTO = 0,
  HOLYTLS_HTTP_1,
  HOLYTLS_HTTP_2,
  HOLYTLS_HTTP_3,  // requires a dual client (holytls_client_new(.., dual=1, ..))
} holytls_http_version;

// Fetch Metadata context. DEFAULT keeps the profile's static navigation
// Sec-Fetch-* headers; any other value emits Sec-Fetch-* coherent with it.
typedef enum holytls_fetch_mode {
  HOLYTLS_FETCH_DEFAULT = 0,
  HOLYTLS_FETCH_NAVIGATE,
  HOLYTLS_FETCH_CORS,
  HOLYTLS_FETCH_NO_CORS,
  HOLYTLS_FETCH_SAME_ORIGIN,
} holytls_fetch_mode;

// Emulation profile. Selects the TLS+H2(+H3) fingerprint the client reproduces.
typedef enum holytls_profile_id {
  HOLYTLS_PROFILE_CHROME = 0,     // newest Chrome (currently 149)
  HOLYTLS_PROFILE_CHROME_149 = 1,
  HOLYTLS_PROFILE_CHROME_148 = 2,
} holytls_profile_id;

// ---------------------------------------------------------------------------
// Plain data carried across the boundary.
// ---------------------------------------------------------------------------

// One request/response header. For a request, `name`/`value` are NUL-terminated
// C strings the caller owns. For a response, they are heap copies owned by the
// holytls_response and freed by holytls_response_free().
typedef struct holytls_header {
  const char *name;
  const char *value;
} holytls_header;

// A request descriptor. Zero-initialize (e.g. `holytls_request r = {0};`) and
// fill what you need: only `url` is required, and a zeroed request is a
// redirect-following GET with the profile's default headers. Mirrors the native
// RequestParams, but flat: body is an explicit pointer+length (binary-safe;
// NULL/0 = no body), headers an explicit array.
typedef struct holytls_request {
  holytls_method method;          // default HOLYTLS_GET (the zero value)
  const char *url;                // required: absolute https:// URL
  const holytls_header *headers;  // optional explicit headers, in wire order
  size_t header_count;
  const uint8_t *body;  // optional request body bytes (NULL/0 = none)
  size_t body_len;
  holytls_fetch_mode fetch_mode;  // HOLYTLS_FETCH_DEFAULT keeps the profile's
                                  // static Sec-Fetch-* navigation headers
  int no_redirects;   // 1 = single hop, ignore the client's max_redirects
  const char *proxy;  // optional per-request proxy URL (NULL = client default);
                      // overrides the client's pool/single proxy for this
                      // request, sticky across its redirect chain
} holytls_request;

// A fully-buffered, caller-owned response. Every pointer here is a heap copy
// (the body is binary-safe via body_len; it is also NUL-terminated for
// convenience). `ok` is TRANSPORT success (TLS/HTTP framing), NOT the HTTP
// status — a 404 has ok=1, status=404. On !ok, `error` is a message and the
// other fields are empty. Free the whole thing with holytls_response_free().
typedef struct holytls_response {
  int ok;             // 1 = the request completed at the transport level
  const char *error;  // NUL-terminated message when !ok, else NULL
  int status;         // HTTP status code (0 when !ok)

  const holytls_header *headers;  // response headers, in received order
  size_t header_count;

  const uint8_t *body;  // response body bytes (decompressed); NUL-terminated
  size_t body_len;      // body length in bytes (authoritative; body may hold NULs)

  const char *final_url;  // URL that produced this response (after redirects)
  const char *alpn;       // negotiated ALPN ("h2" / "h3" / "")
  int resumed;            // the TLS handshake resumed a cached session (1-RTT)
  int early_data;         // the request was sent + accepted as 0-RTT early data

  uint64_t dns_ms;    // timing breakdown (ms); setup phases are 0 on reuse
  uint64_t tcp_ms;
  uint64_t tls_ms;
  uint64_t total_ms;  // whole request, spanning the full redirect chain
} holytls_response;

// ---------------------------------------------------------------------------
// Client lifecycle + configuration.
// ---------------------------------------------------------------------------

typedef struct holytls_client holytls_client;

// Create a client impersonating `profile`. dual=1 builds a Chrome-style
// dual-transport client (H2 first, QUIC/H3 after alt-svc discovery; required to
// force HTTP/3). verify=1 validates server certificates as a browser does.
// Returns NULL only on allocation failure.
holytls_client *holytls_client_new(holytls_profile_id profile, int dual,
                                   int verify);
void holytls_client_free(holytls_client *c);

// Configuration (thin pass-throughs to the native client_set_* functions; see
// core/client.h for the full contract of each). Call before issuing requests.
void holytls_client_set_max_redirects(holytls_client *c, uint64_t max);
void holytls_client_set_timeout_ms(holytls_client *c, uint64_t ms);
void holytls_client_set_http_version(holytls_client *c, holytls_http_version v);
void holytls_client_set_ech_enabled(holytls_client *c, int on);
void holytls_client_set_resumption_enabled(holytls_client *c, int on);
void holytls_client_set_early_data_enabled(holytls_client *c, int on);
void holytls_client_set_max_conns_per_origin(holytls_client *c, uint64_t max);
void holytls_client_set_dns_cache_ttl_ms(holytls_client *c, uint64_t ms);
void holytls_client_override_default_headers(holytls_client *c, int on);
// Header-order override: comma/whitespace-separated names (""=profile default).
int holytls_client_set_header_order(holytls_client *c, const char *csv);
// Route through a forward proxy (http/https/socks5[h]). Returns 1 on a valid
// URL, 0 on a malformed one (client stays direct).
int holytls_client_set_proxy(holytls_client *c, const char *proxy_url,
                             int verify_proxy);
// Add a proxy to the rotation pool (round-robin per non-pooled request,
// overriding the single proxy; a per-request proxy overrides the pool). Returns
// 1 if added, 0 on a malformed URL or full pool. Off by default.
int holytls_client_add_proxy(holytls_client *c, const char *proxy_url,
                             int verify_proxy);
// Bind every outgoing connection (TCP + QUIC) to source IP `ip` (IPv4/IPv6
// literal) for egress-address selection; "" clears it. Returns 1 if parsed, 0
// on a bad literal. Off by default.
int holytls_client_set_local_address(holytls_client *c, const char *ip);
// Trust an extra PEM CA file (for a MITM debug proxy). Returns 1 on success.
int holytls_client_add_ca_file(holytls_client *c, const char *path);
// Pin a leaf SPKI SHA-256 (base64) for `hostname`. Returns 1 if the pin took.
int holytls_client_pin_certificate(holytls_client *c, const char *hostname,
                                   const char *sha256_b64,
                                   int include_subdomains);
// Write TLS/QUIC secrets to `path` (NSS key-log format) for Wireshark.
void holytls_client_set_key_log_file(holytls_client *c, const char *path);

// ---------------------------------------------------------------------------
// Requests (blocking — they drive the loop internally and return when done).
// ---------------------------------------------------------------------------

// Perform one request, blocking until the response (or error) is in hand.
// Returns a heap-allocated holytls_response the caller must free with
// holytls_response_free(). Returns NULL only on catastrophic allocation
// failure — an HTTP error or transport failure comes back AS a response (with
// status set, or ok=0 + error). The request struct and the strings it points to
// need only live for the duration of this call.
holytls_response *holytls_perform(holytls_client *c, const holytls_request *req);

// Perform `count` requests CONCURRENTLY on the client's single loop: all are
// submitted, then the loop runs once until every one completes. This is the
// event-loop client's native concurrency — many in-flight requests, one thread,
// no locks. Writes `count` response pointers into `out_responses` (caller-
// provided array of length `count`); each is independently owned and must be
// freed with holytls_response_free(). A slot is never NULL on success (a failed
// request yields an ok=0 response). Returns the number of responses written
// (== count), or 0 on a catastrophic setup failure. Set a timeout
// (holytls_client_set_timeout_ms) so a stuck request can't hang the batch.
size_t holytls_perform_many(holytls_client *c, const holytls_request *reqs,
                            size_t count, holytls_response **out_responses);

// Like holytls_perform, but STREAMS the (decoded) response body: `on_chunk`
// fires with each decoded chunk as it arrives (the chunk bytes are valid only
// for that call) instead of buffering, and the returned holytls_response carries
// an empty body. Bounded memory over HTTP/2; H1/H3 deliver the whole body in one
// `on_chunk` call (v1). Forces a single hop (no redirects) and the non-pooled
// path. A NULL `on_chunk` behaves like holytls_perform.
holytls_response *holytls_perform_stream(
    holytls_client *c, const holytls_request *req,
    void (*on_chunk)(void *user, const uint8_t *data, uint64_t len), void *user);

void holytls_response_free(holytls_response *r);

// ---------------------------------------------------------------------------
// Session — a cookie jar + per-hop redirect identity layered on a client. The
// transport (and its fingerprint) is the passed-in client; the session adds
// matching cookies per request, absorbs Set-Cookie, and follows redirects with
// the jar applied at each hop. One session is a single browser-like identity;
// run it serially (its jar is not locked). For many identities, make many
// sessions.
// ---------------------------------------------------------------------------

typedef struct holytls_session holytls_session;

holytls_session *holytls_session_new(int cookies_enabled,
                                     uint64_t max_redirects);
void holytls_session_free(holytls_session *s);

// Perform one request on `c` with `s`'s cookies + its own redirect loop.
// Ownership/return identical to holytls_perform(). `req->no_redirects` is
// ignored (the session always runs its cookie-aware redirect loop).
holytls_response *holytls_session_perform(holytls_session *s, holytls_client *c,
                                          const holytls_request *req);

// ---------------------------------------------------------------------------
// WebSocket (RFC 6455 over the client's fingerprinted TLS). Blocking, like the
// rest of this ABI: each call drives the client's loop until its event. A
// holytls_ws is a single long-lived bidirectional connection — drive it from
// one thread, and not concurrently with that client's other calls. Over h2 the
// connection uses RFC 8441 Extended CONNECT; otherwise the HTTP/1.1 Upgrade.
// ---------------------------------------------------------------------------

typedef struct holytls_ws holytls_ws;

// One received WebSocket message (or the peer's Close). `data` is owned by the
// holytls_ws and valid only until the next holytls_ws_* call — copy it out.
typedef struct holytls_ws_message {
  int is_text;          // 1 = text frame, 0 = binary
  const uint8_t *data;  // payload bytes (binary-safe; may hold NULs)
  size_t len;
  uint16_t close_code;  // set when holytls_ws_recv returns 0 (the peer Close)
} holytls_ws_message;

// Open a WebSocket to `url` (wss://… ; ws://… and https://… accepted) with
// optional extra handshake headers. Returns NULL only on a NULL client/url; on
// a failed handshake it returns a handle whose holytls_ws_error() is set (free
// it normally).
holytls_ws *holytls_ws_connect(holytls_client *c, const char *url,
                               const holytls_header *headers,
                               size_t header_count);

// Send a text / binary message (one frame). Returns 1 on success, 0 if the
// connection is closed or failed.
int holytls_ws_send_text(holytls_ws *ws, const char *text, size_t len);
int holytls_ws_send_binary(holytls_ws *ws, const uint8_t *data, size_t len);

// Receive the next message (auto-answers pings). Returns 1 and fills *out with a
// message; 0 and fills *out with the peer's Close (close_code); -1 on error / a
// dead connection; -2 if `timeout_ms` elapsed with no message (the connection
// stays usable; 0 = block indefinitely). *out->data is valid until the next
// holytls_ws_* call.
int holytls_ws_recv(holytls_ws *ws, holytls_ws_message *out,
                    uint64_t timeout_ms);

// Send a Close (code + optional reason, NULL = none) and complete teardown.
void holytls_ws_close(holytls_ws *ws, uint16_t code, const char *reason);
void holytls_ws_free(holytls_ws *ws);

// Negotiated transport: 1 = HTTP/1.1 Upgrade, 2 = HTTP/2 Extended CONNECT, 0 =
// none (failed). And the last error message, or NULL when there is none.
int holytls_ws_transport(holytls_ws *ws);
const char *holytls_ws_error(holytls_ws *ws);

// ---------------------------------------------------------------------------
// Misc.
// ---------------------------------------------------------------------------

// A short version/identity string for the native library (static; do not free).
const char *holytls_version(void);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // HOLYTLS_CAPI_H
