// EventLoop — a thin holder around a single libuv loop. holytls is
// single-threaded and callback-driven: everything runs on this one loop. The
// caller owns the EventLoop value (loop_init / loop_shutdown bracket it).
#ifndef HOLYTLS_LOOP_H
#define HOLYTLS_LOOP_H

#include <uv.h>

#include "base/base.h"

typedef struct EventLoop EventLoop;
struct EventLoop {
  uv_loop_t uv;
};

void loop_init(EventLoop *loop);
// Best effort: walk + close any lingering handles, drain, then close the loop.
void loop_shutdown(EventLoop *loop);
int loop_run(EventLoop *loop);
void loop_stop(EventLoop *loop);
uv_loop_t *loop_uv(EventLoop *loop);

// A one-shot per-request deadline timer. Arm calls `on_timeout(user)` at
// `deadline_ns` (the uv_hrtime clock); the handle's memory is malloc'd and
// freed in its own close callback, decoupled from any request arena (so the
// request can be freed on its normal path; disarm just closes the timer).
// Returns 0 when `deadline_ns == 0` (no timeout). The fire callback only
// invokes on_timeout — it does NOT close the timer, so the request's teardown
// disarms it exactly once.
typedef struct ReqTimer ReqTimer;
ReqTimer *req_timer_arm(EventLoop *loop, U64 deadline_ns,
                        void (*on_timeout)(void *user), void *user);
void req_timer_disarm(ReqTimer *t);  // stop + close (frees); a no-op on 0

#endif  // HOLYTLS_LOOP_H
