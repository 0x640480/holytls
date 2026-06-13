// Fuzz the base64 decoder: arbitrary bytes -> base64_decode (arena-backed).
#include "base/base64.h"
#include "fuzz/fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Arena *a = fuzz_arena();
  Temp t = temp_begin(a);
  String8 out = base64_decode(a, fuzz_str8(data, size));
  (void)out;
  temp_end(t);
  return 0;
}
