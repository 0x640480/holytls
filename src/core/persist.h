// persist — session serialization. Saves a full client identity to JSON and
// restores it in a new process: TLS 1.3 resumption tickets (+ QUIC 0-RTT transport
// params), the Alt-Svc cache, the ECH config cache (all Client-owned), and the
// cookie jar (Session-owned). This is the "returning visitor" snapshot — restoring
// it lets the next process resume TLS (1-RTT / 0-RTT) and skip alt-svc/ECH discovery.
//
// Time bases differ and are handled here: Alt-Svc/ECH expiries are libuv monotonic
// milliseconds (meaningless across a restart), so they are serialized as remaining
// TTLs and rebased onto the loading client's clock; cookie expiry is wall-clock
// epoch seconds and is stored verbatim. TLS tickets carry their own expiry, which
// BoringSSL enforces when they are next offered.
//
// Threading: like all Client/Session calls, marshal/unmarshal must run on the
// owning loop's thread.
#ifndef HOLYTLS_PERSIST_H
#define HOLYTLS_PERSIST_H

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/session.h"

// Bumped when the on-disk schema changes; unmarshal rejects other versions.
#define HOLYTLS_PERSIST_VERSION 1

// Transport/TLS warm-cache (Client-owned): TLS resumption tickets + QUIC 0-RTT
// transport params, the Alt-Svc cache, and the ECH config cache. Marshal returns
// the JSON document in `arena`. Unmarshal merges the snapshot into `c` (replacing
// per-origin entries by key); it never clears entries already present. Returns 1
// on success, 0 on a parse / version error.
String8 client_state_marshal(Arena *arena, const Client *c, B32 pretty);
B32 client_state_unmarshal(Client *c, String8 json);

// Full session snapshot: the Client transport cache (above) plus the Session's
// cookie jar, in one JSON document. `c` may be 0 to serialize only cookies (and
// `s` may be 0 to serialize only the transport cache). The document is a superset
// of client_state_marshal's, so client_state_unmarshal also accepts it.
String8 session_marshal(Arena *arena, const Session *s, const Client *c,
                        B32 pretty);
B32 session_unmarshal(Session *s, Client *c, String8 json);

// File convenience wrappers (synchronous stdio; not for the hot path). save writes
// pretty JSON. Both return 1 on success, 0 on an I/O / serialization error.
B32 session_save(const Session *s, const Client *c, const char *path);
B32 session_load(Session *s, Client *c, const char *path);

#endif  // HOLYTLS_PERSIST_H
