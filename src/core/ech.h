// ECH config retrieval — extract a host's serialized ECHConfigList from a
// DNS-over-HTTPS (dns.google JSON) response for its HTTPS resource record (type
// 65). The bytes returned are exactly what SSL_set1_ech_config_list() expects
// (base64-decoded from the `ech` SvcParam, key 5). Empty result => no ECH.
#ifndef HOLYTLS_ECH_H
#define HOLYTLS_ECH_H

#include "base/arena.h"
#include "base/string8.h"

// Parse a dns.google /resolve JSON body and return the raw ECHConfigList bytes
// (arena-allocated), or str8_zero() if the host publishes no ECH config.
String8 ech_config_from_doh(Arena *arena, String8 doh_json_body);

#endif  // HOLYTLS_ECH_H
