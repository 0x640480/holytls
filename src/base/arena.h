// Arena allocator — a chain of malloc'd blocks, bump-allocated. Allocations are
// pointer-stable and freed in bulk (release) or rewound to a saved position
// (pop_to / Temp / scratch). No per-object free; payloads need no destructor.
//
// This is the raddebugger arena API (push / pos / pop_to / Temp / scratch) over
// a malloc-block backend, which suits holytls's short-lived per-request arenas
// (no per-arena mmap syscall cost). Region growth is O(1); a Reset/pop reuses
// the existing blocks.
#ifndef HOLYTLS_ARENA_H
#define HOLYTLS_ARENA_H

#include "base/base.h"

#define ARENA_DEFAULT_BLOCK KB(64)

typedef struct ArenaBlock ArenaBlock;
struct ArenaBlock {
  ArenaBlock *next;
  U64 cap;       // payload capacity in bytes (data follows this header)
  U64 used;      // bytes consumed
  U64 base_pos;  // cumulative bytes in all blocks before this one
};

typedef struct Arena Arena;
struct Arena {
  ArenaBlock *first;
  ArenaBlock *current;
  U64 block_size;       // default block payload size
  Arena *recycle_next;  // intrusive link for the thread-local recycle free-list
};

typedef struct Temp Temp;
struct Temp {
  Arena *arena;
  U64 pos;
};

//- lifetime
Arena *arena_alloc(void);
Arena *arena_alloc_sized(U64 block_size);
void arena_release(Arena *arena);

//- thread-local recycle pool (for hot, short-lived per-request arenas). acquire()
//  hands back a cleared, ready-to-use arena — popping the free-list, else
//  arena_alloc'ing; recycle() returns one to the pool (clearing it) instead of
//  freeing, so the next acquire() skips the malloc. Single loop thread => no lock.
//  An arena that grew past its first block is released, not pooled (see arena.c).
Arena *arena_acquire(void);
void arena_recycle(Arena *arena);

//- allocation
void *arena_push(Arena *arena, U64 size, U64 align);
void *arena_push_zero(Arena *arena, U64 size, U64 align);
#define push_array_no_zero(a, T, c) \
  ((T *)arena_push((a), sizeof(T) * (U64)(c), _Alignof(T)))
#define push_array(a, T, c) \
  ((T *)arena_push_zero((a), sizeof(T) * (U64)(c), _Alignof(T)))
#define push_struct(a, T) push_array((a), T, 1)

//- position / rewind
U64 arena_pos(Arena *arena);
void arena_pop_to(Arena *arena, U64 pos);
void arena_clear(Arena *arena);  // pop to 0, keep blocks for reuse

//- scoped temporaries
Temp temp_begin(Arena *arena);
void temp_end(Temp temp);

// A scratch temp from a thread-local pool, avoiding the given conflict arenas.
Temp scratch_begin(Arena **conflicts, U64 conflict_count);
#define scratch_end(t) temp_end(t)

//- allocation profiling (compiled in only with HOLYTLS_ARENA_STATS; otherwise the
//  accessors return zeros and the hot path is untouched). Cumulative counters plus
//  current/peak live tallies. Single-process-wide; not thread-synchronized.
typedef struct ArenaStats ArenaStats;
struct ArenaStats {
  U64 arenas_created, arenas_released, blocks_allocated;
  U64 bytes_reserved;  // sum of block payload caps malloc'd
  U64 bytes_pushed;    // sum of arena_push request sizes
  U64 live_arenas, peak_live_arenas;
  U64 live_bytes, peak_live_bytes;  // reserved bytes currently held
};
ArenaStats arena_stats(void);
// Zero the cumulative counters (keeps the live tallies, and rebases the peaks to
// the current live values) so a caller can profile one phase in isolation.
void arena_stats_reset(void);

#endif  // HOLYTLS_ARENA_H
