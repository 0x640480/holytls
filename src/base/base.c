// Unity translation unit for the base layer.
// Compile the stb_sprintf implementation (extern linkage; all other TUs get
// only the declarations via base.h).  Must come before the sub-files so
// STB_SPRINTF_IMPLEMENTATION is set before the guard fires the first time.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
// Force aligned word accesses in stb_sprintf. Its default fast paths do unaligned
// uint32 loads/stores (benign on x86/ARM64 but technically UB), which UBSan's
// alignment check flags; this keeps UBSan clean without disabling the check for
// our own code.
#define STB_SPRINTF_NOUNALIGNED
#define STB_SPRINTF_IMPLEMENTATION
#include "vendor/stb_sprintf.h"
#undef STB_SPRINTF_IMPLEMENTATION  // prevent re-impl on subsequent includes via
                                   // base.h
#pragma GCC diagnostic pop
#include "base/arena.c"
#include "base/string8.c"
#include "base/u8buf.c"
