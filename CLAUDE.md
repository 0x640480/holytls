# Writing C in the holytls style

This is the house style for holytls and any project built on it. It is
**data-oriented C** in the raddebugger / Ryan Fleury idiom: plain data + free
functions, explicit arena allocation, no OOP, no hidden control flow. When you
add or extend code, it should read like the code already here — match the
vocabulary below, not generic "modern C++/C".

## The shape of the code

- **Plain structs + free functions.** No methods, no vtables, no inheritance, no
  RAII. A type is a `struct` of data; behavior is free functions that take a
  `T *` (or `T` by value for small views). State is explicit and visible, never
  hidden behind an object.
- **The caller owns storage.** Types are typically caller-allocated (on the stack
  or in an arena). A `thing_init(Thing *, ...)` / `thing_cleanup(Thing *)` pair
  brackets a lifetime; init does not allocate the struct, cleanup does not free
  it. Mirror this for anything with a lifecycle.
- **No exceptions, no error objects.** Return `B32` (1 = ok), a sentinel, or
  fill an out-param. The fatal/never-null allocation path uses `Fatal(msg)`.
- **Unity build.** `src/<lib>.c` `#include`s every subsystem `.c` in dependency
  order — one translation unit, whole-program inlining. New `.c` files are added
  to that include list, not compiled separately. Headers still guard with
  `#ifndef`.
- **Comments explain WHY and the contract** — ownership, lifetime, "valid only
  during the callback", invariants — not what the line obviously does.

## Vocabulary (base/base.h — use these, not the raw C spellings)

- **Scalars:** `U8 U16 U32 U64`, `S8 S16 S32 S64`, `B8 B32` (booleans), `F32 F64`.
  Use `B32` for flags, `U64` for sizes/counts.
- **Keywords:** `internal` (file-local `static`), `global` (`static` storage),
  `local_persist` (function-static), `thread_local`. Free functions in a `.c` are
  `internal` unless they're the public API declared in the `.h`. Header helpers
  are `internal inline`.
- **Macros:** `ArrayCount(a)`, `Min/Max/Clamp`, `AlignPow2`, `KB/MB/GB`,
  `MemoryCopy/MemoryZero/MemoryMove/MemoryZeroStruct/MemoryZeroArray`,
  `Statement(...)` (multi-statement macro body). Intrusive lists:
  `SLLStackPush(f,n)`, `SLLStackPop`, `SLLQueuePush(f,l,n)` (the `next`-field form
  is the default; `_N` variants take the field name).
- **Asserts:** `Assert(x)` (contract checks; compiled out under `NDEBUG`).
  `Fatal(msg)` aborts. Don't use bare `assert.h`.

## Memory: arenas (base/arena.h) — the central pattern

Allocate from an `Arena`, free in bulk. **No per-object `free`.** Payloads need
no destructors.

```c
Arena *a = arena_alloc();              // or arena_alloc_sized(block)
Thing *t  = push_struct(a, Thing);     // zeroed
Item  *xs = push_array(a, Item, n);    // zeroed; push_array_no_zero to skip
// ... fill, use ...
arena_release(a);                       // frees everything at once
```

- **One arena per natural lifetime** (e.g. one per request/task); release it when
  that scope ends. This is how holytls manages per-request memory — short-lived,
  bulk-freed, no leaks to track.
- Need a temporary within a scope? `Temp t = temp_begin(arena); ...; temp_end(t);`
  rewinds the bump pointer. `scratch_begin(conflicts, n)` gives a thread-local
  scratch arena.
- Growable byte output → `U8Buf` (base/u8buf.h): `u8buf_init(&b, arena, cap)`,
  `u8buf_append(&b, p, n)`, `u8buf_str8(&b)`. Append-only, arena-backed.
- `malloc`/`free` directly is rare and deliberate — only for things that must
  outlive an arena or have a libuv-handle lifetime (freed in a uv close callback).

## Strings: String8 (base/string8.h) — never raw `char*` internally

`String8` is `{ U8 *str; U64 size; }` — a length-carrying view, not
NUL-terminated. Build/borrow, slice, compare; never `strlen`/`strcpy` in logic.

```c
String8 a = str8_lit("accept");        // compile-time, zero-cost
String8 b = str8_cstring(some_cstr);   // wraps a C string (strlen once)
String8 c = push_str8_copy(arena, a);  // owned copy in the arena
if (str8_match_ci(name, str8_lit("content-length"))) { ... }
printf("ja4=" STR8_Fmt "\n", STR8_Arg(c));   // printf integration
```

Slicing returns sub-views (no copy): `str8_prefix/skip/substr/chop`, `str8_trim`,
`str8_chop_by_delim`, `str8_find`/`str8_index_of`, `str8_starts_with`. Arena-build
with `push_str8_copy/_cat`, `str8_from_u64`. A `str8_zero()` is the empty/absent
value.

## Async / callbacks (the libuv-loop model)

holytls is single-threaded and callback-driven on one event loop. There is no
blocking I/O and no `std::function` — the C form is a **function pointer + a
`void *user`**:

```c
typedef void (*ResponseFn)(void *user, const Response *resp);
void client_send(Client *c, ..., ResponseFn cb, void *user);
```

- Submit work, then `loop_run`; results arrive in the callback. Data handed to a
  callback (response body, headers) is typically **valid only during the call** —
  copy out anything you keep.
- Re-entrancy contracts are explicit and documented: a callback may start new
  work but must not tear down the thing currently delivering to it (debug builds
  `Assert`). State this in the header when you add a callback.

## Naming & files

- Functions: `snake_case`, `subsystem_verb[_noun]` (`client_set_proxy`,
  `arena_push`, `str8_match_ci`). Types: `PascalCase` (`Client`, `String8`,
  `Arena`). Macros: `PascalCase` or `SCREAMING` (`ArrayCount`, `KB`).
- One subsystem per `src/<area>/<name>.{h,c}`; the `.h` is the public surface
  (declarations + `internal inline` helpers + doc comments), the `.c` the impl.
- `.clang-format` is authoritative — match it (pointer style `T *p`, etc.).

## Ownership of refcounted/borrowed objects

When you hold a refcounted resource (e.g. an `SSL_CTX`, `SSL_SESSION`) across an
async yield, **take the ref at the borrow point and drop it in cleanup** — not at
use — so a cache eviction/replacement in between can't free it underneath you.

## A small canonical example

```c
// widget.h
typedef struct Widget Widget;
struct Widget {
  Arena *arena;          // owns this widget's allocations
  String8 name;
  Item *items; U64 item_count;
};
B32  widget_init(Widget *w, String8 name);   // caller owns the Widget storage
void widget_cleanup(Widget *w);              // releases the arena
void widget_add(Widget *w, String8 item);

// widget.c
B32 widget_init(Widget *w, String8 name) {
  MemoryZeroStruct(w);
  w->arena = arena_alloc();
  w->name = push_str8_copy(w->arena, name);  // own the bytes
  return 1;
}
void widget_cleanup(Widget *w) { arena_release(w->arena); }  // bulk free
```

When in doubt, open a neighboring subsystem and copy its structure, naming, and
comment density verbatim. Consistency with the surrounding code beats cleverness.
