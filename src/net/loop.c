#include "net/loop.h"

#include <stdlib.h>

internal void loop_close_walk_cb(uv_handle_t *h, void *user) {
  (void)user;
  if (!uv_is_closing(h)) uv_close(h, 0);
}

void loop_init(EventLoop *loop) { uv_loop_init(&loop->uv); }

void loop_shutdown(EventLoop *loop) {
  uv_walk(&loop->uv, loop_close_walk_cb, 0);
  uv_run(&loop->uv, UV_RUN_DEFAULT);
  uv_loop_close(&loop->uv);
}

int loop_run(EventLoop *loop) { return uv_run(&loop->uv, UV_RUN_DEFAULT); }

void loop_stop(EventLoop *loop) { uv_stop(&loop->uv); }

uv_loop_t *loop_uv(EventLoop *loop) { return &loop->uv; }

//- per-request deadline timer

struct ReqTimer {
  uv_timer_t timer;  // first member: (ReqTimer*)&timer; also timer.data == this
  void (*on_timeout)(void *user);
  void *user;
};

internal void req_timer_close_cb(uv_handle_t *h) { free(h->data); }

// One-shot fire: invoke on_timeout, which drives the request's abort/teardown,
// which in turn disarms (closes) this timer. We do NOT close it here, so it is
// closed exactly once (in disarm) — no double close.
internal void req_timer_fire(uv_timer_t *h) {
  ReqTimer *rt = (ReqTimer *)h->data;
  rt->on_timeout(rt->user);
}

ReqTimer *req_timer_arm(EventLoop *loop, U64 deadline_ns,
                        void (*on_timeout)(void *user), void *user) {
  if (deadline_ns == 0) return 0;  // no timeout configured
  ReqTimer *rt = (ReqTimer *)malloc(sizeof(ReqTimer));
  MemoryZeroStruct(rt);
  rt->on_timeout = on_timeout;
  rt->user = user;
  uv_timer_init(loop_uv(loop), &rt->timer);
  rt->timer.data = rt;
  U64 now = uv_hrtime();
  U64 ms = deadline_ns > now ? (deadline_ns - now) / 1000000 : 0;
  uv_timer_start(&rt->timer, req_timer_fire, ms ? ms : 1, 0);  // past -> fire ASAP
  return rt;
}

void req_timer_disarm(ReqTimer *t) {
  if (!t) return;
  uv_timer_stop(&t->timer);  // a stopped timer never fires
  if (!uv_is_closing((uv_handle_t *)&t->timer))
    uv_close((uv_handle_t *)&t->timer, req_timer_close_cb);
}
