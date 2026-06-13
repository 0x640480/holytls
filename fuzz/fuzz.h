// Shared scaffolding for the libFuzzer harnesses. Each fuzz_*.c implements
// LLVMFuzzerTestOneInput(); the build links it with either libFuzzer (clang,
// -fsanitize=fuzzer) or standalone.c (any compiler) so the same target can be
// fuzzed in CI and replayed/regressed on a seed corpus from the normal build.
#ifndef HOLYTLS_FUZZ_H
#define HOLYTLS_FUZZ_H

#include <stddef.h>
#include <stdint.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"

// The fuzz entry point (defined by each harness; called by libFuzzer or the
// standalone driver). Declared here so the standalone driver can call it.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

// Borrow the fuzz input as a String8 (valid only for the duration of the call).
static inline String8 fuzz_str8(const uint8_t *data, size_t size) {
  return str8((U8 *)data, (U64)size);
}

// A per-iteration scratch arena, rewound by the caller via temp_begin/temp_end
// so a multi-million-input run doesn't grow without bound. libFuzzer is
// single-threaded, so one process-wide arena is fine.
static inline Arena *fuzz_arena(void) {
  static Arena *a;
  if (!a) a = arena_alloc();
  return a;
}

#endif  // HOLYTLS_FUZZ_H
