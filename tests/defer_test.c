// Offline defer tests: runs on normal scope exit in LIFO order, on early return,
// on break/continue out of a loop body, and (GCC) captures locals by reference so
// the deferred block sees later mutations. Compiled with -Wno-pedantic because the
// GCC defer path uses nested functions (see CMakeLists / defer.h).
#include <stdio.h>

#include "base/base.h"
#include "base/defer.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

global int g_seq[16];
global int g_n;
internal void rec(int v) { g_seq[g_n++] = v; }

internal void test_lifo(void) {
  g_n = 0;
  {
    defer { rec(1); };  // registered first -> runs last
    defer { rec(2); };  // registered second -> runs first
    rec(0);             // body runs before any defer
  }  // scope exit: 2 then 1
  CHECK(g_n == 3 && g_seq[0] == 0 && g_seq[1] == 2 && g_seq[2] == 1);
}

internal void ret_helper(B32 early) {
  defer { rec(9); };  // must run even on the early return
  rec(0);
  if (early) return;
  rec(1);  // skipped when early
}
internal void test_return(void) {
  g_n = 0;
  ret_helper(1);
  CHECK(g_n == 2 && g_seq[0] == 0 && g_seq[1] == 9);  // 1 was skipped, 9 still ran
}

internal void test_loop(void) {
  g_n = 0;
  for (int i = 0; i < 3; ++i) {
    defer { rec(100 + i); };  // per-iteration; runs at each body-scope exit
    if (i == 0) continue;     // -> rec(100)
    if (i == 2) break;        // -> rec(102)
    rec(i);                   // i==1: rec(1) then rec(101)
  }
  CHECK(g_n == 4 && g_seq[0] == 100 && g_seq[1] == 1 && g_seq[2] == 101 &&
        g_seq[3] == 102);
}

internal void test_capture(void) {
  g_n = 0;
  {
    int x = 1;
    defer { rec(x); };  // GCC captures by reference -> sees x's final value
    x = 42;
  }
  CHECK(g_n == 1 && g_seq[0] == 42);
}

int main(void) {
  test_lifo();
  test_return();
  test_loop();
  test_capture();
  fprintf(stderr, "[defer_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
