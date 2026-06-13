// Standalone driver for the fuzz harnesses when NOT building with libFuzzer
// (i.e. the normal gcc build). It feeds each file named on the command line to
// LLVMFuzzerTestOneInput once — so the harnesses compile in the regular build
// and run as a seed-corpus regression check under ctest, no clang required.
// (Mirrors LLVM's StandaloneFuzzTargetMain.c.)
#include <stdio.h>
#include <stdlib.h>

#include "fuzz/fuzz.h"

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    FILE *f = fopen(argv[i], "rb");
    if (!f) {
      fprintf(stderr, "standalone: cannot open %s\n", argv[i]);
      return 1;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) {
      fclose(f);
      return 1;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, got);
    free(buf);
  }
  return 0;
}
