// Base-layer test: ring_alloc (SPSC ring-buffer allocator backing the
// per-connection egress write ring). Ported from a standalone harness. Covers
// init validation, exact-fit + wrap on a tiny ring, the
// reserve/commit/abort split (partial commit, zero-size blocks, oversize
// refusal), wrap/skip-marker handling at every 16-byte phase, a randomized
// single-thread fill/drain with content verification (the producer==consumer
// shape connection.c uses), and a cross-thread SPSC stress with deterministic
// per-sequence sizes and byte patterns verified on the consumer side.
#include "base/ring_alloc.h"

#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

#include "base/base.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

// splitmix-style mixer: deterministic size/pattern per sequence number,
// recomputable independently on both sides of the queue.
internal U64 mix(U64 x) {
  x += 0x9e3779b97f4a7c15ull;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
  return x ^ (x >> 31);
}
internal U64 size_for(U64 seq, U64 max) { return mix(seq) % (max + 1); }
internal U8 byte_for(U64 seq, U64 j) { return (U8)(mix(seq) + 131u * j); }

internal void fill_block(void *p, U64 seq, U64 n) {
  U8 *b = (U8 *)p;
  for (U64 j = 0; j < n; ++j) b[j] = byte_for(seq, j);
}

// One CHECK per block (not per byte) keeps the hot loops fast.
internal B32 block_matches(const ra_block *b, U64 seq, U64 n) {
  if (!b->data || b->tag != seq || b->size != n) return 0;
  if (((uintptr_t)b->data & (RA_ALIGN - 1)) != 0) return 0;
  const U8 *p = (const U8 *)b->data;
  for (U64 j = 0; j < n; ++j)
    if (p[j] != byte_for(seq, j)) return 0;
  return 1;
}

internal void test_init_validation(void) {
  ra_ring ra;
  _Alignas(64) unsigned char mem[128];
  CHECK(ra_init(&ra, 0, 128) == -1);
  CHECK(ra_init(&ra, mem, 100) == -1);     // not a power of two
  CHECK(ra_init(&ra, mem, 16) == -1);      // too small
  CHECK(ra_init(&ra, mem + 1, 64) == -1);  // misaligned
  CHECK(ra_init(&ra, mem, 128) == 0);
  CHECK(ra_capacity(&ra) == 128);
  CHECK(ra_used(&ra) == 0);
}

internal void test_tiny_ring(void) {
  ra_ring ra;
  _Alignas(64) unsigned char mem[64];
  CHECK(ra_init(&ra, mem, 64) == 0);

  // Two 16-byte blocks fill the ring exactly (no wasted slot thanks to
  // monotonic offsets); a third must fail.
  void *a = ra_alloc(&ra, 16, 1);
  void *b = ra_alloc(&ra, 16, 2);
  CHECK(a && b);
  CHECK(ra_alloc(&ra, 1, 3) == 0);
  CHECK(ra_free_space(&ra) == 0);

  ra_block blk = ra_peek(&ra);
  CHECK(blk.data == a && blk.tag == 1 && blk.size == 16);
  ra_free(&ra, a);

  void *c = ra_alloc(&ra, 16, 3);  // wraps to offset 0
  CHECK(c != 0);
  blk = ra_peek(&ra);
  CHECK(blk.data == b && blk.tag == 2);
  ra_release(&ra);
  blk = ra_peek(&ra);
  CHECK(blk.data == c && blk.tag == 3);
  ra_release(&ra);
  CHECK(ra_peek(&ra).data == 0);
  CHECK(ra_used(&ra) == 0);
}

internal void test_reserve_commit_abort(void) {
  ra_ring ra;
  _Alignas(64) unsigned char mem[256];
  CHECK(ra_init(&ra, mem, 256) == 0);

  // Empty ring at offset 0: max contiguous = cap - header.
  size_t maxsz = 0;
  void *p = ra_reserve(&ra, 1, &maxsz);
  CHECK(p && maxsz == 256 - RA_HDR_BYTES);

  // Abort, re-reserve: identical result.
  ra_abort(&ra);
  size_t maxsz2 = 0;
  void *p2 = ra_reserve(&ra, 1, &maxsz2);
  CHECK(p2 == p && maxsz2 == maxsz);

  // Commit less than reserved; the slack is reusable immediately.
  fill_block(p2, 7, 40);
  void *q = ra_commit(&ra, 40, 7);
  CHECK(q == p2);
  CHECK(ra_used(&ra) == RA_HDR_BYTES + 48);  // 40 padded to 48

  ra_block blk = ra_peek(&ra);
  CHECK(block_matches(&blk, 7, 40));
  ra_release(&ra);

  // Zero-size block: header only, tag still delivered.
  CHECK(ra_alloc(&ra, 0, 99) != 0);
  blk = ra_peek(&ra);
  CHECK(blk.size == 0 && blk.tag == 99);
  ra_release(&ra);

  // Oversized requests are refused, ring left intact.
  CHECK(ra_reserve(&ra, 1024, 0) == 0);
  CHECK(ra_alloc(&ra, 256, 0) == 0);  // cap - hdr doesn't fit hdr
  CHECK(ra_alloc(&ra, 100, 5) != 0);
  blk = ra_peek(&ra);
  CHECK(blk.size == 100 && blk.tag == 5);
  ra_release(&ra);
}

// Walk head through every 16-byte phase of the ring and allocate a block
// large enough to force a skip marker at most phases. Verifies wrap handling
// and skip-hopping at every alignment.
internal void test_wrap_phases(void) {
  enum { CAP = 128 };
  for (unsigned phase = 0; phase < CAP / 16; ++phase) {
    ra_ring ra;
    _Alignas(64) unsigned char mem[CAP];
    CHECK(ra_init(&ra, mem, CAP) == 0);

    // Advance head to phase*16 using zero-size blocks.
    for (unsigned k = 0; k < phase; ++k) {
      CHECK(ra_alloc(&ra, 0, k) != 0);
      ra_release(&ra);
    }

    // 40-byte block: hdr16 + pad48 = 64 total; forces a skip whenever fewer
    // than 64 contiguous bytes remain before the wrap.
    U64 seq = 1000 + phase;
    void *p = ra_alloc(&ra, 40, seq);
    CHECK(p != 0);
    fill_block(p, seq, 40);

    ra_block blk = ra_peek(&ra);
    CHECK(block_matches(&blk, seq, 40));
    ra_free(&ra, blk.data);
    CHECK(ra_peek(&ra).data == 0);
    CHECK(ra_used(&ra) == 0);  // skip padding fully reclaimed
  }
}

// Single-threaded randomized fill/drain with a sliding window of live blocks;
// exercises full, empty, wrap and skip paths with verification. This is the
// producer==consumer shape the connection egress ring runs in.
internal void test_randomized_single(void) {
  enum { CAP = 1024, ITERS = 200000, MAXSZ = 200 };
  ra_ring ra;
  void *mem = aligned_alloc(64, CAP);
  CHECK(mem && ra_init(&ra, mem, CAP) == 0);

  U64 alloc_seq = 0, free_seq = 0;
  U64 rng = 0x1234abcd;
  B32 all_ok = 1;

  for (int i = 0; i < ITERS; ++i) {
    rng = mix(rng);
    if ((rng & 1) && alloc_seq > free_seq) {
      U64 n = size_for(free_seq, MAXSZ);
      ra_block blk = ra_peek(&ra);
      all_ok = all_ok && block_matches(&blk, free_seq, n);
      ra_free(&ra, blk.data);
      free_seq += 1;
    } else {
      U64 n = size_for(alloc_seq, MAXSZ);
      void *p = ra_alloc(&ra, n, alloc_seq);
      while (!p) {  // full: drain until it fits (one free of a tiny block may
                    // not release enough for a worst-case skip + header +
                    // padded-payload footprint)
        CHECK(alloc_seq > free_seq);
        U64 fn = size_for(free_seq, MAXSZ);
        ra_block blk = ra_peek(&ra);
        all_ok = all_ok && block_matches(&blk, free_seq, fn);
        ra_release(&ra);
        free_seq += 1;
        p = ra_alloc(&ra, n, alloc_seq);
      }
      fill_block(p, alloc_seq, n);
      alloc_seq += 1;
    }
  }
  while (free_seq < alloc_seq) {
    U64 n = size_for(free_seq, MAXSZ);
    ra_block blk = ra_peek(&ra);
    all_ok = all_ok && block_matches(&blk, free_seq, n);
    ra_release(&ra);
    free_seq += 1;
  }
  CHECK(all_ok);  // every drained block had the right seq/size/tag/bytes
  CHECK(ra_used(&ra) == 0);
  free(mem);
}

//- SPSC stress: a producer thread allocates variable-size blocks with a
// deterministic pattern; the consumer (main thread) verifies sequence, sizes
// and contents. The only cross-thread coupling is the ring itself.

enum { SPSC_MAXSZ = 1024 };

typedef struct SpscArg SpscArg;
struct SpscArg {
  ra_ring *ra;
  U64 n_msgs;
};

internal void spin_pause(unsigned *spins) {
  ra_cpu_relax();
  if (++*spins >= 256) {  // be a good citizen on small/shared machines
    sched_yield();
    *spins = 0;
  }
}

internal void spsc_producer(void *argp) {
  SpscArg *a = (SpscArg *)argp;
  unsigned spins = 0;
  for (U64 seq = 0; seq < a->n_msgs; ++seq) {
    U64 n = size_for(seq, SPSC_MAXSZ);
    void *p;
    while ((p = ra_reserve(a->ra, n, 0)) == 0) spin_pause(&spins);
    fill_block(p, seq, n);
    ra_commit(a->ra, n, seq);
  }
}

internal void test_spsc(U64 n_msgs) {
  enum { CAP = 1u << 20 };
  ra_ring ra;
  void *mem = aligned_alloc(64, CAP);
  CHECK(mem && ra_init(&ra, mem, CAP) == 0);

  SpscArg arg = {&ra, n_msgs};
  uv_thread_t prod;
  CHECK(uv_thread_create(&prod, spsc_producer, &arg) == 0);

  unsigned spins = 0;
  B32 all_ok = 1;
  for (U64 seq = 0; seq < n_msgs; ++seq) {
    ra_block blk;
    while ((blk = ra_peek(&ra)).data == 0) spin_pause(&spins);
    all_ok = all_ok && block_matches(&blk, seq, size_for(seq, SPSC_MAXSZ));
    ra_release(&ra);
  }
  CHECK(all_ok);  // every message arrived in order with the right bytes
  CHECK(uv_thread_join(&prod) == 0);
  CHECK(ra_used(&ra) == 0);
  free(mem);
}

int main(int argc, char **argv) {
  U64 n = argc > 1 ? strtoull(argv[1], 0, 0) : 500000ull;
  test_init_validation();
  test_tiny_ring();
  test_reserve_commit_abort();
  test_wrap_phases();
  test_randomized_single();
  test_spsc(n);

  fprintf(stderr, "[ring_alloc_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
