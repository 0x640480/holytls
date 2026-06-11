#include "net/dns_cache.h"

#include <arpa/inet.h>   // htons
#include <netinet/in.h>  // sockaddr_in / sockaddr_in6, AF_INET*

#include "base/string8.h"

void dns_cache_init(DnsCache *dc, U64 ttl_ms) {
  MemoryZeroStruct(dc);
  dc->ttl_ms = ttl_ms;
}

internal B32 dns_host_eq(const char *a, const char *b) {
  return str8_match_ci(str8_cstring(a), str8_cstring(b));  // DNS is case-insensitive
}

B32 dns_cache_get(DnsCache *dc, const char *host, U64 now_ms,
                  struct sockaddr_storage *out, socklen_t *out_len) {
  if (!dc || dc->ttl_ms == 0 || !host) return 0;
  for (U64 i = 0; i < DNS_CACHE_CAP; ++i) {
    DnsCacheEntry *e = &dc->v[i];
    if (e->expiry_ms == 0 || !dns_host_eq(e->host, host)) continue;
    if (now_ms >= e->expiry_ms) {  // expired -> free the slot and miss
      e->expiry_ms = 0;
      return 0;
    }
    MemoryCopy(out, &e->addr, sizeof e->addr);
    *out_len = e->addr_len;
    return 1;
  }
  return 0;
}

void dns_cache_put(DnsCache *dc, const char *host, const struct sockaddr *addr,
                   socklen_t len, U64 now_ms) {
  if (!dc || dc->ttl_ms == 0 || !host || !addr || len == 0 ||
      (U64)len > sizeof(struct sockaddr_storage))
    return;

  DnsCacheEntry *slot = 0;
  for (U64 i = 0; i < DNS_CACHE_CAP; ++i)  // existing entry for the host?
    if (dc->v[i].expiry_ms != 0 && dns_host_eq(dc->v[i].host, host)) {
      slot = &dc->v[i];
      break;
    }
  if (!slot)
    for (U64 i = 0; i < DNS_CACHE_CAP; ++i)  // a free / expired slot?
      if (dc->v[i].expiry_ms == 0 || now_ms >= dc->v[i].expiry_ms) {
        slot = &dc->v[i];
        break;
      }
  if (!slot) {  // full of live entries -> evict the soonest-expiring
    slot = &dc->v[0];
    for (U64 i = 1; i < DNS_CACHE_CAP; ++i)
      if (dc->v[i].expiry_ms < slot->expiry_ms) slot = &dc->v[i];
  }

  String8 h = str8_cstring(host);
  U64 n = h.size < sizeof slot->host - 1 ? h.size : sizeof slot->host - 1;
  MemoryCopy(slot->host, h.str, n);
  slot->host[n] = 0;
  MemoryCopy(&slot->addr, addr, len);
  slot->addr_len = len;
  slot->expiry_ms = now_ms + dc->ttl_ms;
}

void dns_cache_evict(DnsCache *dc, const char *host) {
  if (!dc || !host) return;
  for (U64 i = 0; i < DNS_CACHE_CAP; ++i)
    if (dc->v[i].expiry_ms != 0 && dns_host_eq(dc->v[i].host, host)) {
      dc->v[i].expiry_ms = 0;
      return;
    }
}

void dns_sockaddr_set_port(struct sockaddr_storage *ss, U16 port) {
  if (ss->ss_family == AF_INET)
    ((struct sockaddr_in *)ss)->sin_port = htons(port);
  else if (ss->ss_family == AF_INET6)
    ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
}
