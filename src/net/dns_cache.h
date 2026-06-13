// dns_cache — a per-Client in-memory DNS cache (host -> resolved address) that
// lets repeat connections to a host skip uv_getaddrinfo. Fingerprint-neutral:
// the cached address is exactly what getaddrinfo would have returned, so only
// the lookup latency is saved. Single-threaded (driven on the owning loop
// thread, like the rest of the Client) — no locking. Fixed-array + linear scan,
// matching the other per-origin caches; DNS lookups are per-connection, so
// capacity (not lookup speed) is what this trades off.
#ifndef HOLYTLS_DNS_CACHE_H
#define HOLYTLS_DNS_CACHE_H

#include <uv.h>  // struct sockaddr_storage / sockaddr, socklen_t

#include "base/base.h"

enum { DNS_CACHE_CAP = 256 };
#define DNS_CACHE_DEFAULT_TTL_MS 60000  // 60s (Chrome-like minimum)

typedef struct DnsCacheEntry DnsCacheEntry;
struct DnsCacheEntry {
  char host[256];  // resolve node (no port); slot empty when expiry==0
  struct sockaddr_storage addr;  // resolved address; the port is reset on use
  socklen_t addr_len;
  U64 expiry_ms;  // 0 = empty slot
};

// Keyed by host (DNS is host->IP; port is orthogonal): one entry serves any
// port, and the caller resets the port via dns_sockaddr_set_port on a hit.
// ttl_ms == 0 disables the cache (every lookup misses, every store is a no-op).
typedef struct DnsCache DnsCache;
struct DnsCache {
  DnsCacheEntry v[DNS_CACHE_CAP];
  U64 ttl_ms;
};

void dns_cache_init(DnsCache *dc, U64 ttl_ms);

// On a live (unexpired) hit, copy the address into *out / *out_len and
// return 1. Miss / disabled / expired -> 0 (an expired entry is freed in
// passing).
B32 dns_cache_get(DnsCache *dc, const char *host, U64 now_ms,
                  struct sockaddr_storage *out, socklen_t *out_len);

// Store host -> addr with the configured TTL (no-op when disabled). Replaces an
// existing entry for the host; when full, reuses an expired slot, else evicts
// the soonest-expiring entry.
void dns_cache_put(DnsCache *dc, const char *host, const struct sockaddr *addr,
                   socklen_t len, U64 now_ms);

// Drop any entry for `host` (e.g. after a connect failure to a stale address).
void dns_cache_evict(DnsCache *dc, const char *host);

// Overwrite the port of a v4/v6 sockaddr_storage (host-keyed entries carry an
// arbitrary port; the caller sets the request's actual port before connecting).
void dns_sockaddr_set_port(struct sockaddr_storage *ss, U16 port);

#endif  // HOLYTLS_DNS_CACHE_H
