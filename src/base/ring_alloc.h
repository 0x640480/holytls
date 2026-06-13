/*
 * ring_alloc.h — single-header SPSC ring-buffer allocator (C11, 64-bit).
 *
 * A wait-free, lock-free arena that hands out variable-sized, contiguous,
 * 16-byte-aligned blocks from a circular region of memory. One thread
 * allocates (producer), one thread frees (consumer), frees happen in FIFO
 * order. Producer and consumer may be the same thread (e.g. an epoll-driven
 * HTTP client event loop).
 *
 * Design follows "Optimizing a ring buffer for throughput" (rigtorp.se):
 *
 *   1. head/tail are *monotonically increasing byte offsets*, wrapped only
 *      when indexing via `off & mask` (capacity is a power of two). This
 *      kills the empty-vs-full ambiguity, wastes no slot, and replaces
 *      modulo with a mask.
 *
 *   2. Each shared index lives on its own cache line (RA_CACHELINE), and —
 *      the key optimization from the article — each side keeps a *cached
 *      copy of the opposite index* on a line private to it. The producer
 *      only touches the shared `tail` line when its cached view says the
 *      ring looks full; the consumer only touches the shared `head` line
 *      when its cached view says the ring looks empty. After observing N
 *      bytes of slack once, the next allocations/releases pay zero
 *      coherency traffic on the index lines. Define RA_NO_CACHE to disable
 *      this (for benchmarking the difference, as in the article).
 *
 *   3. Only relaxed loads of your own index, acquire loads of the other
 *      side's index, release stores of your own index. No seq_cst, no RMW,
 *      no fences.
 *
 *   4. Optional huge-page backing via ra_mem_map() to cut TLB misses
 *      (Linux; falls back to 4K pages + MADV_HUGEPAGE).
 *
 * Allocator-specific machinery on top of the queue from the article:
 *
 *   - Every block is preceded by a 16-byte inline header {size, tag}. The
 *     header travels on the same cache lines the consumer is about to read
 *     anyway, so the metadata is effectively free (data-oriented: one flat
 *     stream, no side tables, no pointer chasing).
 *
 *   - Blocks are contiguous; when a block would straddle the physical end
 *     of the buffer, the producer writes a SKIP marker (a header with the
 *     top bit set) covering the tail-end padding and places the block at
 *     offset 0. Because everything is 16-byte granular, a skip marker
 *     always fits. The consumer hops over skip markers transparently.
 *
 *   - reserve/commit split: ra_reserve() returns the largest contiguous
 *     writable span (>= min_size); you may commit any amount up to that.
 *     This is the zero-copy recv() pattern: reserve, read() straight into
 *     the ring, commit exactly the bytes received. ra_alloc() is just
 *     reserve+commit of an exact size.
 *
 * API (producer side / consumer side must each be a single thread):
 *
 *   int      ra_init(ra_ring*, void *mem, U64 capacity);  // pow2 cap
 *   void     ra_reset(ra_ring*);                  // both sides quiesced
 *
 *   void    *ra_reserve(ra_ring*, U64 min_size, U64 *max_size);
 *   void    *ra_commit (ra_ring*, U64 size, U64 tag);
 *   void     ra_abort  (ra_ring*);                // cancel reservation
 *   void    *ra_alloc  (ra_ring*, U64 size, U64 tag);
 *
 *   ra_block ra_peek   (ra_ring*);                // oldest live block
 *   void     ra_release(ra_ring*);                // free oldest live block
 *   void     ra_free   (ra_ring*, void *p);       // release + FIFO assert
 *
 *   U64   ra_capacity(ra_ring*), ra_used(ra_ring*), ra_free_space(ra_ring*);
 *   void    *ra_mem_map(U64, B32 try_huge);    // Linux helper
 *   void     ra_mem_unmap(void*, U64);
 *
 * Guarantees & limits:
 *   - Returned pointers are 16-byte aligned; per-block overhead is 16 bytes
 *     of header plus padding of the size to a multiple of 16.
 *   - A block of size <= capacity/2 - 16 always fits in an empty ring,
 *     regardless of where head currently sits. Larger blocks (up to
 *     capacity - 32) fit only when head's phase allows it.
 *   - At most one un-committed reservation at a time.
 *   - Offsets are U64 and never wrap in practice (2^64 bytes).
 *   - 64-bit platforms only (lock-free 8-byte atomics assumed).
 */
#ifndef RING_ALLOC_H
#define RING_ALLOC_H

#include <assert.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base/base.h"  // holytls scalar types (U8 / U32 / U64 / B32)

_Static_assert(sizeof(void *) == 8, "ring_alloc assumes a 64-bit platform");

/* Cache line size used to partition the control block. 64 on x86-64 and
 * most ARM; some parts (Apple M-series, POWER) prefetch/pair lines — build
 * with -DRA_CACHELINE=128 there. This mirrors the article's note about
 * std::hardware_destructive_interference_size. */
#ifndef RA_CACHELINE
#define RA_CACHELINE 64
#endif

#define RA_ALIGN 16u           /* block alignment & granularity */
#define RA_HDR_BYTES 16u       /* inline header size            */
#define RA_SKIP ((U64)1 << 63) /* header flag: wrap padding     */

typedef struct ra_hdr {
  U64 size_flags; /* bits 0..62: data size in bytes; bit 63: SKIP */
  U64 tag;        /* opaque user data (request id, conn ptr, ...) */
} ra_hdr;

_Static_assert(sizeof(ra_hdr) == RA_HDR_BYTES, "header must be 16 bytes");

typedef struct ra_block {
  void *data; /* NULL when the ring is empty */
  U64 size;
  U64 tag;
} ra_block;

/*
 * Control block, partitioned by access pattern (data-oriented layout):
 *
 *   line 0: buf, mask          read-only after init, shared by both cores;
 *                              settles into S state, never bounces.
 *   line 1: head               written by producer, polled by consumer.
 *   line 2: tail_cache, rsv_*  producer-private working set: exactly one
 *                              line that stays in M state on the producer's
 *                              core forever.
 *   line 3: tail               written by consumer, polled by producer.
 *   line 4: head_cache         consumer-private; stays on consumer's core.
 *
 * Keeping the private caches off the shared-index lines is deliberate (and
 * matches the article's ringbuffer2 layout): a private variable must never
 * share a line with one the other core polls, or those polls keep yanking
 * the line out from under your fast path.
 */
typedef struct ra_ring {
  /* -- shared, read-only after init ---------------------------------- */
  U8 *buf;
  U64 mask; /* capacity - 1; capacity is a power of two */

  /* -- producer-published --------------------------------------------- */
  _Alignas(RA_CACHELINE) _Atomic U64 head; /* committed bytes  */

  /* -- producer-private ------------------------------------------------ */
  _Alignas(RA_CACHELINE) U64 tail_cache; /* last seen tail   */
  U64 rsv_hdr;    /* monotonic offset of the staged header        */
  U64 rsv_max;    /* max committable data bytes for staged rsv    */
  B32 rsv_active; /* a reservation is outstanding                 */

  /* -- consumer-published ---------------------------------------------- */
  _Alignas(RA_CACHELINE) _Atomic U64 tail; /* released bytes   */

  /* -- consumer-private ------------------------------------------------ */
  _Alignas(RA_CACHELINE) U64 head_cache; /* last seen head   */
} ra_ring;

/* ---------------------------------------------------------------------- */
/* internals                                                                */
/* ---------------------------------------------------------------------- */

static inline U64 ra__pad(U64 n) {
  return (n + (RA_ALIGN - 1)) & ~(U64)(RA_ALIGN - 1);
}

/* Headers are written/read through memcpy: the backing storage is a plain
 * byte buffer, and memcpy of 16 bytes compiles to two 8-byte moves while
 * staying strict-aliasing clean. */
static inline void ra__hdr_write(ra_ring *ra, U64 off, U64 size_flags,
                                 U64 tag) {
  U8 *p = ra->buf + (off & ra->mask);
  memcpy(p, &size_flags, 8);
  memcpy(p + 8, &tag, 8);
}

static inline ra_hdr ra__hdr_read(ra_ring *ra, U64 off) {
  ra_hdr h;
  memcpy(&h, ra->buf + (off & ra->mask), sizeof h);
  return h;
}

/* ---------------------------------------------------------------------- */
/* lifecycle                                                                */
/* ---------------------------------------------------------------------- */

/* mem must be at least 16-byte aligned and `capacity` bytes (a power of
 * two, >= 32). Returns 0 on success, -1 on bad arguments. */
static inline int ra_init(ra_ring *ra, void *mem, U64 capacity) {
  if (!ra || !mem) return -1;
  if (capacity < 2 * RA_HDR_BYTES) return -1;
  if ((capacity & (capacity - 1)) != 0) return -1; /* pow2 only */
  if (((uintptr_t)mem & (RA_ALIGN - 1)) != 0) return -1;
  ra->buf = (U8 *)mem;
  ra->mask = (U64)capacity - 1;
  atomic_init(&ra->head, 0);
  atomic_init(&ra->tail, 0);
  ra->tail_cache = 0;
  ra->head_cache = 0;
  ra->rsv_hdr = 0;
  ra->rsv_max = 0;
  ra->rsv_active = 0;
  return 0;
}

/* Only when neither thread is touching the ring. */
static inline void ra_reset(ra_ring *ra) {
  atomic_store_explicit(&ra->head, 0, memory_order_relaxed);
  atomic_store_explicit(&ra->tail, 0, memory_order_relaxed);
  ra->tail_cache = 0;
  ra->head_cache = 0;
  ra->rsv_active = 0;
  ra->rsv_max = 0;
}

/* ---------------------------------------------------------------------- */
/* producer side                                                            */
/* ---------------------------------------------------------------------- */

/*
 * Reserve a contiguous, 16-byte-aligned span of at least `min_size` bytes.
 * Returns a writable pointer, or NULL if the ring cannot satisfy the
 * request right now. If `max_size` is non-NULL it receives the number of
 * bytes that may actually be committed (>= min_size) — i.e. the largest
 * contiguous span available at the chosen position. Nothing is visible to
 * the consumer until ra_commit().
 */
static inline void *ra_reserve(ra_ring *ra, U64 min_size, U64 *max_size) {
  assert(!ra->rsv_active &&
         "ra_reserve: previous reservation not committed/aborted");

  U64 const cap = ra->mask + 1;
  if ((U64)min_size > cap) return NULL; /* can never fit */
  U64 const need = ra__pad((U64)min_size);

  /* `head` is producer-owned: relaxed load is just reading our own var. */
  U64 const head = atomic_load_explicit(&ra->head, memory_order_relaxed);
  U64 to_end = cap - (head & ra->mask); /* contiguous bytes to wrap */

  /* Header + data must not straddle the wrap: pad to the end if needed.
   * to_end is always a multiple of 16, so a skip marker always fits. */
  U64 const skip = (to_end < RA_HDR_BYTES + need) ? to_end : 0;
  U64 const total_min = skip + RA_HDR_BYTES + need;

#ifdef RA_NO_CACHE
  /* Benchmark mode: behave like the article's naive ring buffer and read
   * the shared tail index on every operation. */
  ra->tail_cache = atomic_load_explicit(&ra->tail, memory_order_acquire);
#endif

  /* The article's optimization: test against our cached view of tail
   * first; only on apparent exhaustion refresh it from the shared line.
   * The acquire pairs with the consumer's release store and is what makes
   * it safe to recycle the bytes the consumer has finished reading. */
  U64 free_bytes = cap - (head - ra->tail_cache);
  if (free_bytes < total_min) {
    ra->tail_cache = atomic_load_explicit(&ra->tail, memory_order_acquire);
    free_bytes = cap - (head - ra->tail_cache);
    if (free_bytes < total_min) return NULL; /* genuinely full */
  }

  U64 hdr_off = head;
  if (skip) {
    /* Wrap padding. Not yet visible: head is only published at commit,
     * and any published head always lands past skip + following block. */
    ra__hdr_write(ra, hdr_off, RA_SKIP | (skip - RA_HDR_BYTES), 0);
    hdr_off += skip;
    to_end = cap; /* now at offset 0 */
  }

  /* Largest committable size: bounded by the physical end of the buffer
   * and by how much free space remains after the skip + header. */
  U64 const room_end = to_end - RA_HDR_BYTES;
  U64 const free_data = free_bytes - skip - RA_HDR_BYTES;
  U64 const max_data = room_end < free_data ? room_end : free_data;

  ra->rsv_hdr = hdr_off;
  ra->rsv_max = max_data;
  ra->rsv_active = 1;
  if (max_size) *max_size = (U64)max_data;
  return ra->buf + ((hdr_off + RA_HDR_BYTES) & ra->mask);
}

/*
 * Publish `size` bytes (<= the reservation's max) of the reserved span to
 * the consumer, with `tag` carried in the header. Returns the block's data
 * pointer. The release store on head is the only synchronizing write: it
 * makes the header, the payload, and any skip marker visible together.
 */
static inline void *ra_commit(ra_ring *ra, U64 size, U64 tag) {
  assert(ra->rsv_active && "ra_commit: no active reservation");
  assert((U64)size <= ra->rsv_max && "ra_commit: size exceeds reservation");

  U64 const hdr_off = ra->rsv_hdr;
  ra__hdr_write(ra, hdr_off, (U64)size, tag);
  ra->rsv_active = 0;
  ra->rsv_max = 0;

  U64 const new_head = hdr_off + RA_HDR_BYTES + ra__pad((U64)size);
  atomic_store_explicit(&ra->head, new_head, memory_order_release);
  return ra->buf + ((hdr_off + RA_HDR_BYTES) & ra->mask);
}

/* Cancel the outstanding reservation. Any skip marker written by reserve
 * was never published and is simply recomputed by the next reserve. */
static inline void ra_abort(ra_ring *ra) {
  assert(ra->rsv_active && "ra_abort: no active reservation");
  ra->rsv_active = 0;
  ra->rsv_max = 0;
}

/* Exact-size allocation: reserve + commit. NULL if it doesn't fit. */
static inline void *ra_alloc(ra_ring *ra, U64 size, U64 tag) {
  if (!ra_reserve(ra, size, NULL)) return NULL;
  return ra_commit(ra, size, tag);
}

/* ---------------------------------------------------------------------- */
/* consumer side                                                            */
/* ---------------------------------------------------------------------- */

/*
 * Oldest committed-but-unreleased block, or {NULL,0,0} if the ring is
 * empty. Pure read apart from refreshing the consumer-private head cache.
 */
static inline ra_block ra_peek(ra_ring *ra) {
  ra_block b = {0, 0, 0};

  U64 tail = atomic_load_explicit(&ra->tail, memory_order_relaxed);

#ifdef RA_NO_CACHE
  ra->head_cache = atomic_load_explicit(&ra->head, memory_order_acquire);
#endif

  /* Mirror of the producer's trick: consult the cached head first; only
   * touch the shared head line when the cache can't prove data is there.
   * The acquire pairs with commit's release store, making header +
   * payload reads safe.
   *
   * One subtlety vs. the article: its queue moves in uniform steps of one
   * item and checks the cache on every pop, so the consumer index lands
   * exactly on the cached value before passing it and `==` suffices. Here
   * steps are variable-sized and ra_release() may be called without a
   * peek, so tail can leap over a stale cache value; the comparison must
   * be ordered, not equality. (Offsets are monotonic u64 — they do not
   * wrap in any realistic lifetime.) */
  if (tail >= ra->head_cache) { /* cache proves nothing */
    ra->head_cache = atomic_load_explicit(&ra->head, memory_order_acquire);
    if (tail == ra->head_cache) /* tail never passes head */
      return b;                 /* empty */
  }

  ra_hdr h = ra__hdr_read(ra, tail);
  if (h.size_flags & RA_SKIP) {
    tail += RA_HDR_BYTES + (h.size_flags & ~RA_SKIP);
    /* A skip marker is only ever published together with the block that
     * follows it, so any head that exposes the skip also exposes that
     * block: the hopped position is still strictly below head_cache. */
    assert(tail < ra->head_cache);
    h = ra__hdr_read(ra, tail);
    assert(!(h.size_flags & RA_SKIP));
  }

  b.data = ra->buf + ((tail + RA_HDR_BYTES) & ra->mask);
  b.size = (U64)h.size_flags;
  b.tag = h.tag;
  return b;
}

/*
 * Free the oldest live block. Must only be called when the ring is known
 * to be non-empty (e.g. after a successful ra_peek). The release store
 * hands the bytes (including any skip padding) back to the producer.
 */
static inline void ra_release(ra_ring *ra) {
  U64 tail = atomic_load_explicit(&ra->tail, memory_order_relaxed);
  assert(tail != atomic_load_explicit(&ra->head, memory_order_acquire) &&
         "ra_release: ring is empty");

  ra_hdr h = ra__hdr_read(ra, tail);
  if (h.size_flags & RA_SKIP) {
    tail += RA_HDR_BYTES + (h.size_flags & ~RA_SKIP);
    h = ra__hdr_read(ra, tail);
    assert(!(h.size_flags & RA_SKIP));
  }

  tail += RA_HDR_BYTES + ra__pad(h.size_flags);
  atomic_store_explicit(&ra->tail, tail, memory_order_release);
}

/* malloc/free-flavored spelling of ra_release. In debug builds, asserts
 * that `p` really is the oldest live block, catching out-of-order frees. */
static inline void ra_free(ra_ring *ra, void *p) {
#ifndef NDEBUG
  ra_block b = ra_peek(ra);
  assert(b.data == p &&
         "ra_free: not the oldest live block (frees must be FIFO)");
#else
  (void)p;
#endif
  ra_release(ra);
}

/* ---------------------------------------------------------------------- */
/* introspection (racy snapshots; fine for stats and backpressure hints)    */
/* ---------------------------------------------------------------------- */

static inline U64 ra_capacity(ra_ring *ra) { return (U64)(ra->mask + 1); }

static inline U64 ra_used(ra_ring *ra) { /* bytes incl. headers/padding */
  U64 h = atomic_load_explicit(&ra->head, memory_order_relaxed);
  U64 t = atomic_load_explicit(&ra->tail, memory_order_relaxed);
  return (U64)(h - t);
}

static inline U64 ra_free_space(ra_ring *ra) {
  return ra_capacity(ra) - ra_used(ra);
}

/* Polite spin hint for busy-wait loops around this ring. */
static inline void ra_cpu_relax(void) {
#if defined(__x86_64__) || defined(__i386__)
  __builtin_ia32_pause();
#elif defined(__aarch64__)
  __asm__ __volatile__("yield");
#endif
}

/* ---------------------------------------------------------------------- */
/* backing memory helpers (Linux)                                           */
/* ---------------------------------------------------------------------- */

#if defined(__linux__)
#include <sys/mman.h>

/* Map `capacity` bytes for the ring. With try_huge, attempts explicit huge
 * pages (MAP_HUGETLB) first to cut TLB misses — the article's "further
 * optimizations" — then falls back to normal pages with MADV_HUGEPAGE so
 * THP can still kick in. Returns NULL on failure. */
static inline void *ra_mem_map(U64 capacity, B32 try_huge) {
  void *p = MAP_FAILED;
#ifdef MAP_HUGETLB
  if (try_huge)
    p = mmap(NULL, capacity, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
#endif
  if (p == MAP_FAILED) {
    p = mmap(NULL, capacity, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#ifdef MADV_HUGEPAGE
    if (p != MAP_FAILED && try_huge) (void)madvise(p, capacity, MADV_HUGEPAGE);
#endif
  }
  return p == MAP_FAILED ? NULL : p;
}

static inline void ra_mem_unmap(void *p, U64 capacity) {
  if (p) munmap(p, capacity);
}
#endif /* __linux__ */

#endif /* RING_ALLOC_H */
