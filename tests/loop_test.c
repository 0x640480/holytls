// libuv event-loop smoke: init a loop, fire a one-shot timer that stops it, run,
// shut down cleanly.
#include "base/base.h"
#include "net/loop.h"

global int g_fired = 0;

internal void on_timer(uv_timer_t *t) {
  g_fired = 1;
  uv_stop(t->loop);
}

int main(void) {
  EventLoop loop;
  loop_init(&loop);
  uv_timer_t t;
  uv_timer_init(loop_uv(&loop), &t);
  uv_timer_start(&t, on_timer, 1, 0);
  loop_run(&loop);
  loop_shutdown(&loop);
  fprintf(stderr, "[loop_test] timer fired=%d\n", g_fired);
  return g_fired ? 0 : 1;
}
