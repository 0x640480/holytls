// Fuzz the Alt-Svc header parser: arbitrary bytes -> alt_svc_parse. Returns a
// small by-value struct, no allocation.
#include "core/alt_svc.h"
#include "fuzz/fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  AltSvcInfo info = alt_svc_parse(fuzz_str8(data, size));
  (void)info;
  return 0;
}
