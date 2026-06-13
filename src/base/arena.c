#include "base/arena.h"

// ASan manual poisoning. A bump allocator hides intra-block overflow and
// use-after-pop / use-after-recycle inside one malloc'd block, so ASan can't
// see them on its own. We poison a block's free space and every popped/recycled
// region, and unpoison exactly what each push hands out — turning ASan into a
// real intra-arena + use-after-recycle detector. Auto-active only when this TU
// is built with -fsanitize=address (HOLYTLS_ASAN=ON); a no-op otherwise, so
// normal builds carry zero overhead.
#if defined(__SANITIZE_ADDRESS__)
#define HOLYTLS_ARENA_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define HOLYTLS_ARENA_ASAN 1
#endif
#endif

#ifdef HOLYTLS_ARENA_ASAN
#include <sanitizer/asan_interface.h>
#define ArenaPoison(p, n) __asan_poison_memory_region((p), (n))
#define ArenaUnpoison(p, n) __asan_unpoison_memory_region((p), (n))
#else
#define ArenaPoison(p, n) ((void)0)
#define ArenaUnpoison(p, n) ((void)0)
#endif

#ifdef HOLYTLS_ARENA_STATS
global ArenaStats g_arena_stats;
internal void arena_stat_block(U64 cap) {
  ArenaStats *s = &g_arena_stats;
  s->blocks_allocated++;
  s->bytes_reserved += cap;
  s->live_bytes += cap;
  if (s->live_bytes > s->peak_live_bytes) s->peak_live_bytes = s->live_bytes;
}
internal void arena_stat_create(void) {
  ArenaStats *s = &g_arena_stats;
  s->arenas_created++;
  s->live_arenas++;
  if (s->live_arenas > s->peak_live_arenas)
    s->peak_live_arenas = s->live_arenas;
}
ArenaStats arena_stats(void) { return g_arena_stats; }
void arena_stats_reset(void) {
  ArenaStats *s = &g_arena_stats;
  s->arenas_created = s->arenas_released = s->blocks_allocated = 0;
  s->bytes_reserved = s->bytes_pushed = 0;
  s->peak_live_arenas =
      s->live_arenas;  // rebase peaks to the current live state
  s->peak_live_bytes = s->live_bytes;
}
#else
ArenaStats arena_stats(void) {
  ArenaStats z;
  MemoryZeroStruct(&z);
  return z;
}
void arena_stats_reset(void) {}
#endif

internal ArenaBlock *arena_block_new(U64 cap, U64 base_pos) {
  // The header is 4 * 8 = 32 bytes, so the payload (header + 1) is 16-byte
  // aligned (malloc returns >= 16-aligned); arena_push handles larger aligns.
  ArenaBlock *b = (ArenaBlock *)malloc(sizeof(ArenaBlock) + cap);
  if (!b) Fatal("arena out of memory");
  b->next = 0;
  b->cap = cap;
  b->used = 0;
  b->base_pos = base_pos;
  // gcc -Wmaybe-uninitialized false-positives here: it sees a pointer into the
  // freshly malloc'd (uninitialized) payload handed to
  // __asan_poison_memory_region, but poisoning only marks shadow — it never
  // reads the bytes. Silence just this.
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
  ArenaPoison((U8 *)(b + 1),
              cap);  // free space starts poisoned; push unpoisons
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
#ifdef HOLYTLS_ARENA_STATS
  arena_stat_block(cap);
#endif
  return b;
}

Arena *arena_alloc_sized(U64 block_size) {
  if (block_size == 0) block_size = ARENA_DEFAULT_BLOCK;
  Arena *a = (Arena *)malloc(sizeof(Arena));
  if (!a) Fatal("arena out of memory");
  a->first = a->current = arena_block_new(block_size, 0);
  a->block_size = block_size;
  a->recycle_next = 0;
#ifdef HOLYTLS_ARENA_STATS
  arena_stat_create();
#endif
  return a;
}

Arena *arena_alloc(void) { return arena_alloc_sized(ARENA_DEFAULT_BLOCK); }

void arena_release(Arena *arena) {
  if (!arena) return;
#ifdef HOLYTLS_ARENA_STATS
  U64 freed = 0;
#endif
  for (ArenaBlock *b = arena->first; b;) {
    ArenaBlock *next = b->next;
#ifdef HOLYTLS_ARENA_STATS
    freed += b->cap;
#endif
    // Clean before free, or our manual poison leaks into the next malloc that
    // reuses this chunk (a false positive on legitimate access).
    ArenaUnpoison((U8 *)(b + 1), b->cap);
    free(b);
    b = next;
  }
  free(arena);
#ifdef HOLYTLS_ARENA_STATS
  g_arena_stats.arenas_released++;
  g_arena_stats.live_arenas--;
  g_arena_stats.live_bytes -= freed;
#endif
}

void *arena_push(Arena *arena, U64 size, U64 align) {
#ifdef HOLYTLS_ARENA_STATS
  g_arena_stats.bytes_pushed += size;
#endif
  for (;;) {
    ArenaBlock *b = arena->current;
    U8 *data = (U8 *)(b + 1);
    U64 base = (U64)(uintptr_t)(data + b->used);
    U64 aligned = AlignPow2(base, align);
    U64 need = (aligned - base) + size;
    if (b->used + need <= b->cap) {
      b->used += need;
      // Unpoison just the allocation; the alignment pad before it and the free
      // space after stay poisoned as redzones (catch over/underflow).
      ArenaUnpoison((void *)(uintptr_t)aligned, size);
      return (void *)(uintptr_t)aligned;
    }
    if (b->next) {  // a reset block downstream may have room
      arena->current = b->next;
      continue;
    }
    U64 cap = Max(arena->block_size, size + align);
    ArenaBlock *nb = arena_block_new(cap, b->base_pos + b->cap);
    b->next = nb;
    arena->current = nb;
  }
}

void *arena_push_zero(Arena *arena, U64 size, U64 align) {
  void *p = arena_push(arena, size, align);
  MemoryZero(p, size);
  return p;
}

U64 arena_pos(Arena *arena) {
  return arena->current->base_pos + arena->current->used;
}

void arena_pop_to(Arena *arena, U64 pos) {
  ArenaBlock *b = arena->first;
  while (b->next && pos > b->base_pos + b->cap) b = b->next;
  b->used = pos - b->base_pos;
  arena->current = b;
  // Re-poison everything freed by the pop so use of it (use-after-temp / -clear
  // / -recycle) traps; subsequent pushes unpoison what they hand back out.
  ArenaPoison((U8 *)(b + 1) + b->used, b->cap - b->used);
  for (ArenaBlock *n = b->next; n; n = n->next) {
    n->used = 0;
    ArenaPoison((U8 *)(n + 1), n->cap);
  }
}

void arena_clear(Arena *arena) { arena_pop_to(arena, 0); }

Temp temp_begin(Arena *arena) {
  Temp t = {arena, arena_pos(arena)};
  return t;
}

void temp_end(Temp temp) { arena_pop_to(temp.arena, temp.pos); }

//- thread-local scratch pool
global thread_local Arena *g_scratch[2];

Temp scratch_begin(Arena **conflicts, U64 conflict_count) {
  if (!g_scratch[0]) {
    g_scratch[0] = arena_alloc();
    g_scratch[1] = arena_alloc();
  }
  for (int i = 0; i < 2; ++i) {
    B32 conflict = 0;
    for (U64 j = 0; j < conflict_count; ++j) {
      if (conflicts[j] == g_scratch[i]) {
        conflict = 1;
        break;
      }
    }
    if (!conflict) return temp_begin(g_scratch[i]);
  }
  return temp_begin(g_scratch[0]);
}

//- thread-local arena recycle pool
// Mirrors g_scratch: a thread_local free-list head, never torn down (every
// pooled arena stays reachable through it, so LSAN sees still-reachable, not
// leaked).
#define ARENA_RECYCLE_MAX 64  // cap free-list depth; beyond it, release

global thread_local Arena *g_recycle_head;
global thread_local U32 g_recycle_count;

Arena *arena_acquire(void) {
  Arena *a = g_recycle_head;
  if (a) {
    g_recycle_head = a->recycle_next;
    a->recycle_next = 0;
    g_recycle_count--;
    return a;  // already cleared at recycle time; first block's used == 0
  }
  return arena_alloc();
}

void arena_recycle(Arena *arena) {
  if (!arena) return;
  // arena_clear keeps ALL blocks, so pooling an arena that grew past its first
  // block would retain that bloat forever — release those instead. Also cap
  // depth.
  if (arena->first->next != 0 || g_recycle_count >= ARENA_RECYCLE_MAX) {
    arena_release(arena);
    return;
  }
  arena_clear(arena);
  arena->recycle_next = g_recycle_head;
  g_recycle_head = arena;
  g_recycle_count++;
}
