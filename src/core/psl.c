#include "core/psl.h"

// The generated blob is one ~140KB string literal — far past C99's 4095-byte
// translation minimum, which -Wpedantic flags. Every supported compiler
// (GCC/Clang) handles it; silence just that diagnostic for the include.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#include "core/psl_data.h"  // psl_blob + sorted offset tables (generated)
#pragma GCC diagnostic pop

internal B32 psl_table_has(const U32 *off, U64 count, const char *key) {
  U64 lo = 0, hi = count;
  while (lo < hi) {
    U64 mid = lo + (hi - lo) / 2;
    int c = strcmp(key, psl_blob + off[mid]);
    if (c == 0) return 1;
    if (c < 0)
      hi = mid;
    else
      lo = mid + 1;
  }
  return 0;
}

B32 psl_is_public_suffix(String8 domain) {
  // Lowercase into a NUL-terminated buffer (a valid domain is <= 253 bytes;
  // anything longer can't match a rule).
  char d[256];
  if (domain.size == 0 || domain.size >= sizeof d) return 0;
  for (U64 i = 0; i < domain.size; ++i) {
    U8 ch = domain.str[i];
    d[i] = (char)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
  }
  U64 n = domain.size;
  if (d[n - 1] == '.') n -= 1;  // tolerate one trailing dot (FQDN form)
  if (n == 0) return 0;
  d[n] = 0;

  if (psl_table_has(psl_exception_off, PSL_EXCEPTION_COUNT, d))
    return 0;  // "!rule": explicitly carved out of a wildcard
  if (psl_table_has(psl_exact_off, PSL_EXACT_COUNT, d)) return 1;
  const char *dot = strchr(d, '.');
  if (!dot) return 1;  // unlisted single label: the PSL's default '*' rule
  // "*.parent" makes every direct child of `parent` a suffix (one label only).
  return psl_table_has(psl_wildcard_off, PSL_WILDCARD_COUNT, dot + 1);
}
