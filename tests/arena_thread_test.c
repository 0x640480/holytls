// Arena thread auto-cleanup: spawn worker threads that touch both thread-local
// arena pools (scratch + recycle) and EXIT WITHOUT calling arena_thread_cleanup.
// On POSIX a pthread_key destructor (armed on first pool use) must free those
// pools at thread exit. This binary exits 0 everywhere; under the ASan/LSan CI
// job a missing/broken destructor surfaces as N leaked thread pools (LSan fails
// the process). Also checks the manual cleanup stays an idempotent no-op.
#include <stdio.h>

#include <uv.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

global uv_mutex_t g_mu;
global int g_ran;

internal void worker(void *arg) {
  (void)arg;
  // Touch the scratch pool (lazily allocates g_scratch[2]).
  Temp t = scratch_begin(0, 0);
  (void)push_array_no_zero(t.arena, U8, 4096);
  scratch_end(t);
  // Populate the recycle free-list (acquire -> recycle keeps it pooled).
  Arena *a = arena_acquire();
  (void)push_array(a, U8, 1024);
  arena_recycle(a);
  Arena *b = arena_acquire();  // pop one back
  (void)push_array(b, U8, 256);
  arena_recycle(b);
  uv_mutex_lock(&g_mu);
  g_ran++;
  uv_mutex_unlock(&g_mu);
  // Deliberately NO arena_thread_cleanup() — the destructor must free the pools.
}

int main(void) {
  uv_mutex_init(&g_mu);
  enum { N = 64 };
  uv_thread_t th[N];
  for (int i = 0; i < N; ++i) CHECK(uv_thread_create(&th[i], worker, 0) == 0);
  for (int i = 0; i < N; ++i) uv_thread_join(&th[i]);
  CHECK(g_ran == N);  // every worker ran (and exited without manual cleanup)

  // The main thread used no arenas here, but the manual call is always a safe
  // idempotent no-op (and on POSIX the destructor would run at process exit).
  arena_thread_cleanup();
  arena_thread_cleanup();

  uv_mutex_destroy(&g_mu);
  fprintf(stderr, "[arena_thread_test] %d checks, %d failures\n", g_checks,
          g_fails);
  return g_fails ? 1 : 0;
}
