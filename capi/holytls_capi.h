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

// Wire-protocol selection. This is the single knob for HTTP/3: the client builds
// the QUIC transport automatically iff the chosen mode can use H3 (AUTO or H3).
// Passed to holytls_client_new[_named] at construction and to
// holytls_client_set_http_version at runtime (the latter can only narrow within
// the capability the constructor built — it can't add QUIC after the fact).
typedef enum holytls_http_version {
  HOLYTLS_HTTP_AUTO = 0,  // Chrome-faithful: H2, then H3 once an origin
                          // advertises alt-svc: h3 (builds QUIC).
  HOLYTLS_HTTP_1,         // force HTTP/1.1 (changes the ALPN/fingerprint).
  HOLYTLS_HTTP_2,         // force HTTP/2 over TCP, never H3 (no QUIC built).
  HOLYTLS_HTTP_3,         // force HTTP/3/QUIC on the first request (builds QUIC).
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
  HOLYTLS_PROFILE_FIREFOX_151 = 3,
  HOLYTLS_PROFILE_FIREFOX = 3,    // newest Firefox (currently 151)
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
  const char *header_order;  // optional per-request wire header order: a comma/
                             // whitespace-separated name list (NULL = the
                             // client-level order). When set it REPLACES the
                             // client-level order for this request and every
                             // redirect hop; applies on pooled and non-pooled
                             // paths. See holytls_client_set_header_order.
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

// Create a client impersonating `profile`. `mode` is the wire protocol (see
// holytls_http_version): HOLYTLS_HTTP_2 is H2-only; HOLYTLS_HTTP_AUTO is the
// Chrome-faithful H2->H3 path; both AUTO and HOLYTLS_HTTP_3 build the QUIC
// transport automatically. verify=1 validates server certificates as a browser
// does. Returns NULL only on allocation failure.
// NOTE: `mode` replaced the old `int dual`; the numeric value 0 now means
// HOLYTLS_HTTP_AUTO (builds QUIC), not the old dual=0 (H2-only).
holytls_client *holytls_client_new(holytls_profile_id profile,
                                   holytls_http_version mode, int verify);

// Create a client by profile NAME, resolved from the profile registry (e.g.
// "chrome149", "chrome148", "firefox151"; NULL/"" = the newest). This is the
// forward-looking selector — a profile added to the native registry is usable
// here with no enum change. `mode` as in holytls_client_new. Returns NULL on
// allocation failure OR an unknown name.
holytls_client *holytls_client_new_named(const char *profile_name,
                                         holytls_http_version mode, int verify);

// Enumerate the registered profiles (index 0 = the default/newest).
// holytls_profile_name returns a static string (do not free) or NULL if out of
// range.
size_t holytls_profile_count(void);
const char *holytls_profile_name(size_t index);

void holytls_client_free(holytls_client *c);

// Configuration (thin pass-throughs to the native client_set_* functions; see
// core/client.h for the full contract of each). Call before issuing requests.
void holytls_client_set_max_redirects(holytls_client *c, uint64_t max);
void holytls_client_set_timeout_ms(holytls_client *c, uint64_t ms);
// Override the wire protocol at runtime. Can only narrow within the capability
// the constructor built: switching to HOLYTLS_HTTP_3 only works if the client
// was created with a mode that built QUIC (AUTO or HTTP_3); otherwise forced-H3
// requests fail. Construct with the right `mode` to decide whether QUIC exists.
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
// Present a client certificate for mutual TLS. `cert_path` is a PEM cert chain,
// `key_path` its private key (may equal cert_path for a combined PEM),
// `passphrase` decrypts an encrypted key (NULL/"" if none). Fingerprint-neutral.
// Returns 1 on success, 0 if a file can't be read or the key doesn't match.
int holytls_client_set_client_cert(holytls_client *c, const char *cert_path,
                                   const char *key_path,
                                   const char *passphrase);
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
// Async client — a non-blocking variant for foreign event loops (e.g. Python
// asyncio). Unlike holytls_client (which OWNS its loop and drives it to
// completion on each blocking call), the async client's loop runs on a
// dedicated thread the caller spawns (calling holytls_async_run), and requests
// are submitted without blocking; each completion fires on that loop thread.
// All client state is touched ONLY on the loop thread — the submit/stop calls
// are the sole thread-safe entry points (a mutex'd queue + uv_async wakeup).
// ---------------------------------------------------------------------------

typedef struct holytls_async_client holytls_async_client;

// Request completion. Fires ON THE LOOP THREAD (the holytls_async_run thread)
// when the request finishes. `req_id` echoes the id passed to submit, so the
// caller can correlate. OWNERSHIP of `resp` transfers to the callback — it must
// be freed with holytls_response_free() (typically after marshalling). `resp` is
// never NULL: a transport failure is an ok=0 response; only catastrophic OOM
// would be, and the trampoline substitutes an error response.
typedef void (*holytls_async_complete_fn)(void *user, uint64_t req_id,
                                           holytls_response *resp);

// Create an async client (same profile/mode/verify matrix as
// holytls_client_new_named). The loop is NOT running yet — start it by calling
// holytls_async_run on a dedicated thread. Returns NULL on alloc failure or an
// unknown profile name.
holytls_async_client *holytls_async_client_new_named(const char *profile_name,
                                                     holytls_http_version mode,
                                                     int verify);

// Borrow the inner client for CONFIGURATION ONLY (the holytls_client_set_*
// functions), and ONLY before the loop thread is started — config touches client
// state and is not thread-safe. Do NOT issue requests on the returned handle.
holytls_client *holytls_async_client_base(holytls_async_client *ac);

// Submit one request WITHOUT blocking. Thread-safe — callable from any thread
// (typically the asyncio thread). Deep-copies everything it needs out of `req`
// (url, headers, body, proxy) synchronously, so `req` and its strings need only
// live for the duration of THIS call. When the response lands, `cb(user,
// req_id, resp)` fires on the loop thread. Returns 1 on success, 0 if the client
// is stopping or on allocation failure (in which case `cb` is never called).
int holytls_async_submit(holytls_async_client *ac, const holytls_request *req,
                         uint64_t req_id, holytls_async_complete_fn cb,
                         void *user);

// Submit N requests as ONE batch WITHOUT blocking. Thread-safe. Deep-copies
// each request synchronously (like holytls_async_submit), splices the whole
// batch onto the queue under ONE lock, and issues ONE uv_async_send —
// collapsing the N per-request FFI/lock/wakeup costs of an asyncio.gather.
// `reqs` is `count` flat requests; `req_ids[i]` correlates reqs[i]'s
// completion; all share `cb`/`user`. All-or-nothing: returns 1 iff ALL N were
// queued (cb fires for each); returns 0 and queues NOTHING (cb fires for none)
// if the client is stopping or any copy fails — the caller must then fail all N
// awaiters. count==0 returns 1 (no-op).
int holytls_async_submit_many(holytls_async_client *ac,
                              const holytls_request *reqs, size_t count,
                              const uint64_t *req_ids,
                              holytls_async_complete_fn cb, void *user);

// Run the loop until holytls_async_stop is observed. BLOCKS — call it on a
// dedicated thread. A persistent uv_async keeps the loop alive across idle
// periods (no requests in flight), so this does not return prematurely. All
// submitted requests are driven on this thread.
void holytls_async_run(holytls_async_client *ac);

// Ask the loop thread to exit holytls_async_run. Thread-safe and idempotent.
// Stops accepting new submits; any still-queued (not yet dispatched) submit is
// completed with an ok=0 "client closing" response so awaiters never hang.
void holytls_async_stop(holytls_async_client *ac);

// Free the async client. PRECONDITION: holytls_async_run has returned and its
// thread has been JOINED (no thread is touching the client). Tears down the
// client, loop, and async machinery.
void holytls_async_client_free(holytls_async_client *ac);

// ---------------------------------------------------------------------------
// Session — a cookie jar + per-hop redirect identity layered on a client. The
// transport (and its fingerprint) is the passed-in client; the session adds
// matching cookies per request, absorbs Set-Cookie, and follows redirects with
// the jar applied at each hop. One session is a single browser-like identity;
// run it serially (its jar is not locked). For many identities, make many
// sessions.
// ---------------------------------------------------------------------------

typedef struct holytls_session holytls_session;

// `follow_redirects` 0 => the session never follows 3xx (single hop), decoupled
// from `max_redirects`. `max_redirects` is honored verbatim (0 also yields a
// single hop). Pass follow_redirects=1, max_redirects=10 for browser defaults.
holytls_session *holytls_session_new(int cookies_enabled, int follow_redirects,
                                     uint64_t max_redirects);
void holytls_session_free(holytls_session *s);

// Perform one request on `c` with `s`'s cookies + its own redirect loop.
// Ownership/return identical to holytls_perform(). `req->no_redirects` is
// ignored (the session runs its own redirect loop, gated by follow_redirects).
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
