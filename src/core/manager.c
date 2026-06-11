#include "core/manager.h"

#include <openssl/rand.h>
#include <string.h>

#include "base/base.h"

void manager_init(Manager *m) {
  MemoryZeroStruct(m);
  uv_mutex_init(&m->mutex);
  m->arena = arena_alloc();
}

void manager_set_max_sessions(Manager *m, U64 n) {
  uv_mutex_lock(&m->mutex);
  m->max_sessions = n;
  uv_mutex_unlock(&m->mutex);
}

void manager_set_session_timeout(Manager *m, U64 ms) {
  uv_mutex_lock(&m->mutex);
  m->session_timeout_ns = ms * 1000000ULL;
  uv_mutex_unlock(&m->mutex);
}

//- helpers (all called under the mutex) -------------------------------------
internal void manager_hex(const U8 *raw, U64 n, char *out) {
  static const char hexd[] = "0123456789abcdef";
  for (U64 i = 0; i < n; ++i) {
    out[i * 2] = hexd[raw[i] >> 4];
    out[i * 2 + 1] = hexd[raw[i] & 0xf];
  }
  out[n * 2] = 0;
}

internal ManagerSlot *manager_find(Manager *m, const char *id) {
  for (U64 i = 0; i < m->count; ++i)
    if (m->slots[i].in_use && strcmp(m->slots[i].id, id) == 0)
      return &m->slots[i];
  return 0;
}

internal ManagerSlot *manager_alloc_slot(Manager *m) {
  for (U64 i = 0; i < m->count; ++i)
    if (!m->slots[i].in_use) return &m->slots[i];  // reuse a freed slot
  if (m->count == m->cap) {
    U64 ncap = m->cap ? m->cap * 2 : 16;
    ManagerSlot *ns = push_array(m->arena, ManagerSlot, ncap);  // zeroed
    if (m->count) MemoryCopy(ns, m->slots, m->count * sizeof(ManagerSlot));
    m->slots = ns;
    m->cap = ncap;
  }
  return &m->slots[m->count++];
}

int manager_create_session(Manager *m, const SessionConfig *cfg,
                           char out_id[MANAGER_ID_LEN]) {
  uv_mutex_lock(&m->mutex);

  if (m->max_sessions && m->live >= m->max_sessions) {
    // Lazy eviction: reclaim the oldest idle (refcount==0) session past the
    // timeout. Safe — an unpinned session has no holder, so it is quiescent.
    U64 now = uv_hrtime();
    ManagerSlot *victim = 0;
    if (m->session_timeout_ns)
      for (U64 i = 0; i < m->count; ++i) {
        ManagerSlot *sl = &m->slots[i];
        if (sl->in_use && sl->refcount == 0 &&
            (now - sl->last_used_ns) >= m->session_timeout_ns &&
            (!victim || sl->last_used_ns < victim->last_used_ns))
          victim = sl;
      }
    if (!victim) {
      uv_mutex_unlock(&m->mutex);
      return -1;  // at capacity, nothing evictable
    }
    session_destroy(victim->session);
    victim->session = 0;
    victim->in_use = 0;
    m->live--;
  }

  Session *sess = session_create(cfg);
  if (!sess) {
    uv_mutex_unlock(&m->mutex);
    return -1;
  }
  ManagerSlot *sl = manager_alloc_slot(m);  // not in_use yet
  do {
    U8 raw[16];
    RAND_bytes(raw, 16);
    manager_hex(raw, 16, sl->id);
  } while (manager_find(m, sl->id));  // regen on the astronomically rare clash
  sl->session = sess;
  sl->refcount = 0;
  sl->last_used_ns = uv_hrtime();
  sl->in_use = 1;
  m->live++;
  memcpy(out_id, sl->id, MANAGER_ID_LEN);

  uv_mutex_unlock(&m->mutex);
  return 0;
}

Session *manager_get_session(Manager *m, const char *id) {
  uv_mutex_lock(&m->mutex);
  ManagerSlot *sl = manager_find(m, id);
  Session *s = 0;
  if (sl) {
    sl->refcount++;
    s = sl->session;
  }
  uv_mutex_unlock(&m->mutex);
  return s;
}

void manager_release_session(Manager *m, const char *id) {
  uv_mutex_lock(&m->mutex);
  ManagerSlot *sl = manager_find(m, id);
  if (sl) {
    if (sl->refcount > 0) sl->refcount--;
    sl->last_used_ns = uv_hrtime();
  }
  uv_mutex_unlock(&m->mutex);
}

void manager_shutdown(Manager *m) {
  uv_mutex_lock(&m->mutex);
  for (U64 i = 0; i < m->count; ++i)
    if (m->slots[i].in_use) {
      session_destroy(m->slots[i].session);
      m->slots[i].in_use = 0;
    }
  m->live = 0;
  uv_mutex_unlock(&m->mutex);
  uv_mutex_destroy(&m->mutex);
  if (m->arena) arena_release(m->arena);
  m->arena = 0;
}
