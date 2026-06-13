/*
 * defer.h — a `defer` statement for C.
 *
 * Runs a block of code when the *enclosing scope* exits, no matter how it
 * exits: falling off the end, `return`, `break`, `continue`, or `goto` out
 * of the scope. Multiple defers in one scope run in reverse (LIFO) order,
 * matching Go and Zig semantics.
 *
 * Usage (identical on both compilers):
 *
 *     FILE *f = fopen(path, "r");
 *     if (!f) return -1;
 *     defer { fclose(f); };        // <- note the trailing semicolon
 *
 * Requirements:
 *   - GCC:   works out of the box (uses nested functions).
 *   - Clang: compile with -fblocks (and link -lBlocksRuntime on non-Apple
 *            platforms; on macOS/iOS it's built in).
 *
 * holytls note: this project builds with -Wpedantic, and the GCC path uses
 * nested functions (a GNU extension), so any translation unit that *uses*
 * `defer` must drop -Wpedantic for that file (e.g. add -Wno-pedantic to the
 * target). Including this header without using `defer` is warning-clean. The
 * library's unity TU does not use defer; it's provided for future opt-in use.
 *
 * Caveats (inherent to any C defer):
 *   - Does NOT run on longjmp() past the scope, exit(), abort(), or thread
 *     cancellation. Scope exit only.
 *   - GCC nested functions capture locals by reference; Clang blocks
 *     capture by value (declare the local `__block` if the deferred code
 *     must see later mutations). Capture variables before mutating them
 *     if you need portable behavior.
 */
#ifndef HOLYTLS_DEFER_H
#define HOLYTLS_DEFER_H

#define DEFER_CAT_(a, b) a##b
#define DEFER_CAT(a, b) DEFER_CAT_(a, b)

#if defined(__clang__) && defined(__BLOCKS__)

/* Clang: a block pointer with a cleanup attribute that invokes it. */
typedef void (^defer_block_t)(void);
static inline void defer_run_(defer_block_t *b) { (*b)(); }

#define defer                                                           \
  __attribute__((cleanup(defer_run_), unused)) defer_block_t DEFER_CAT( \
      defer_, __COUNTER__) = ^

#elif defined(__GNUC__)

/* GCC: a nested function registered as the cleanup handler of a dummy
 * variable. The cleanup call is direct (not through a pointer), so no
 * executable-stack trampoline is generated. */
#define DEFER_IMPL_(n)                                                     \
  auto void DEFER_CAT(defer_fn_, n)(int *);                                \
  __attribute__((cleanup(DEFER_CAT(defer_fn_, n)), unused)) int DEFER_CAT( \
      defer_var_, n);                                                      \
  void DEFER_CAT(defer_fn_, n)(int *defer_arg_ __attribute__((unused)))

#define defer DEFER_IMPL_(__COUNTER__)

#else
#error "defer.h requires GCC (nested functions) or Clang with -fblocks"
#endif

#endif /* HOLYTLS_DEFER_H */
