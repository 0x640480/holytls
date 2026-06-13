// Manager — a thread-safe registry of lightweight Sessions by string ID. It
// owns session STATE, not transport (the caller passes a shared Client to
// session_get). Acquire/release: manager_get_session pins a session (refcount),
// manager_release_session unpins + stamps last-used; idle sessions past the
// timeout are reclaimed lazily at create-time, and only when refcount==0 (so a
// session in use is never destroyed). The mutex guards only this registry —
// session internals stay single-threaded (driven by one holder at a time).
#ifndef HOLYTLS_MANAGER_H
#define HOLYTLS_MANAGER_H

#include <uv.h>

#include "core/session.h"

#define MANAGER_ID_LEN 33  // 32 hex chars + NUL

typedef struct ManagerSlot ManagerSlot;
struct ManagerSlot {
  char id[MANAGER_ID_LEN];
  Session *session;
  int refcount;      // >0 => pinned (in use), not evictable
  U64 last_used_ns;  // uv_hrtime() stamp, set on release
  B32 in_use;
};

typedef struct Manager Manager;
struct Manager {
  uv_mutex_t mutex;
  Arena *arena;  // owns the slots array
  ManagerSlot *slots;
  U64 count;  // slots ever allocated (high-water)
  U64 live;   // currently in_use
  U64 cap;
  U64 max_sessions;        // 0 = unlimited
  U64 session_timeout_ns;  // 0 = no idle eviction
};

void manager_init(Manager *m);
void manager_shutdown(Manager *m);  // destroy every session + the mutex + arena
void manager_set_max_sessions(Manager *m, U64 n);
void manager_set_session_timeout(Manager *m, U64 ms);

// Create a session from cfg; writes its id into out_id. 0 on success; -1 if at
// capacity with nothing evictable, or on allocation failure.
int manager_create_session(Manager *m, const SessionConfig *cfg,
                           char out_id[MANAGER_ID_LEN]);

// Pin + return the session for id (refcount++). 0 if unknown. Pair with
// release.
Session *manager_get_session(Manager *m, const char *id);

// Unpin (refcount--) + stamp last-used. No-op if unknown. Do not touch the
// Session* after release — it may be reclaimed.
void manager_release_session(Manager *m, const char *id);

#endif  // HOLYTLS_MANAGER_H
