// holytls base layer — scalar types, core macros, intrusive-list helpers.
// Data-oriented C in the raddebugger/Fleury idiom: plain structs + free
// functions, explicit Arena* allocation, no per-object hidden state.
#ifndef HOLYTLS_BASE_H
#define HOLYTLS_BASE_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vendor/stb_sprintf.h"
// Route all snprintf/vsnprintf calls through stb_sprintf (faster, no locale
// overhead, consistent cross-platform behaviour).
#define snprintf stbsp_snprintf
#define vsnprintf stbsp_vsnprintf

//- scalar types
typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef uint64_t U64;
typedef int8_t S8;
typedef int16_t S16;
typedef int32_t S32;
typedef int64_t S64;
typedef int8_t B8;
typedef int32_t B32;
typedef float F32;
typedef double F64;

//- keywords
#define internal static       // file-local linkage
#define global static         // file/global scope storage
#define local_persist static  // function-scope persistent storage
#define thread_local _Thread_local

//- size helpers
#define KB(n) ((U64)(n) << 10)
#define MB(n) ((U64)(n) << 20)
#define GB(n) ((U64)(n) << 30)

//- arithmetic / array
#define ArrayCount(a) (sizeof(a) / sizeof((a)[0]))
#define Min(a, b) (((a) < (b)) ? (a) : (b))
#define Max(a, b) (((a) > (b)) ? (a) : (b))
#define Clamp(lo, x, hi) (((x) < (lo)) ? (lo) : ((x) > (hi)) ? (hi) : (x))
#define AlignPow2(x, p) (((U64)(x) + ((U64)(p) - 1)) & ~((U64)(p) - 1))
#define IsPow2(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

//- memory
#define MemoryZero(p, n) memset((p), 0, (n))
#define MemoryCopy(d, s, n) memcpy((d), (s), (n))
#define MemoryMove(d, s, n) memmove((d), (s), (n))
#define MemoryCompare(a, b, n) memcmp((a), (b), (n))
#define MemoryZeroStruct(p) MemoryZero((p), sizeof(*(p)))
#define MemoryZeroArray(a) MemoryZero((a), sizeof(a))

//- token paste / stringize
#define Stringify_(x) #x
#define Stringify(x) Stringify_(x)
#define Glue_(a, b) a##b
#define Glue(a, b) Glue_(a, b)

//- statement wrapper
#define Statement(s) \
  do {               \
    s                \
  } while (0)

//- intrusive singly-linked list: stack (LIFO) and queue (FIFO)
#define SLLStackPush_N(f, n, next) ((n)->next = (f), (f) = (n))
#define SLLStackPop_N(f, next) ((f) = (f)->next)
#define SLLQueuePush_N(f, l, n, next)            \
  (((f) == 0) ? ((f) = (l) = (n), (n)->next = 0) \
              : ((l)->next = (n), (l) = (n), (n)->next = 0))
#define SLLStackPush(f, n) SLLStackPush_N(f, n, next)
#define SLLQueuePush(f, l, n) SLLQueuePush_N(f, l, n, next)

//- abort with a message (the never-null allocation / fatal-error path)
#define Fatal(msg) \
  Statement(fprintf(stderr, "holytls fatal: %s\n", (msg)); abort();)

//- debug assert: contract checks compiled out under NDEBUG (release builds)
#ifdef NDEBUG
#define Assert(x) ((void)0)
#else
#define Assert(x)                                                        \
  Statement(if (!(x)) {                                                  \
    fprintf(stderr, "holytls assert failed: %s (%s:%d)\n", #x, __FILE__, \
            __LINE__);                                                   \
    abort();                                                             \
  })
#endif

#endif  // HOLYTLS_BASE_H
