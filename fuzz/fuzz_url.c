// Fuzz the URL parser: arbitrary bytes -> url_parse. Returns views into the
// input and allocates nothing, so no arena is needed.
#include "core/url.h"
#include "fuzz/fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ParsedUrl u = url_parse(fuzz_str8(data, size));
  (void)u;
  return 0;
}
