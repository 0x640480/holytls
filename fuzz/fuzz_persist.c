// Fuzz session restore: arbitrary bytes as the persisted JSON snapshot fed to
// session_unmarshal with a null Client (parses the JSON + restores the cookie
// jar — the attacker-controlled-blob path). A lightweight Session needs no
// loop.
#include "core/persist.h"
#include "core/session.h"
#include "fuzz/fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Session s;
  SessionConfig cfg;
  session_config_default(&cfg);
  session_init(&s, &cfg);
  session_unmarshal(&s, /*client=*/0, fuzz_str8(data, size));
  session_cleanup(&s);
  return 0;
}
