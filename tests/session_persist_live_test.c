// Live cross-instance session persistence: warm up client A (resumption on) so
// it caches a NewSessionTicket, save the session snapshot to disk, then load it
// into a BRAND-NEW client B (as a fresh process would) and assert the next
// request resumes (Response.resumed == 1). This is the "returning visitor
// across a restart" path that session_save / session_load enable.
// Network-gated: set HOLYTLS_LIVE=1 to run (otherwise it skips and passes).
#include <stdio.h>
#include <stdlib.h>

#include "base/base.h"
#include "base/defer.h"
#include "base/string8.h"
#include "core/client.h"
#include "core/persist.h"
#include "core/session.h"
#include "net/loop.h"
#include "profile/profile.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

typedef struct Ctx Ctx;
struct Ctx {
  B32 got;
  int status;
  B32 resumed;
};

internal void on_resp(void *user, const Response *r) {
  Ctx *cx = (Ctx *)user;
  cx->got = r->ok;
  cx->status = r->status;
  cx->resumed = r->resumed;
  if (!r->ok)
    fprintf(stderr, "  request failed: %s\n", r->error ? r->error : "?");
}

internal Ctx fetch_once(Client *c, EventLoop *loop, const char *url) {
  Ctx cx;
  MemoryZeroStruct(&cx);
  client_get(c, str8_cstring(url), on_resp, &cx);
  loop_run(loop);
  return cx;
}

int main(void) {
  if (!getenv("HOLYTLS_LIVE")) {
    printf("[session_persist_live_test] SKIP (set HOLYTLS_LIVE=1 to run)\n");
    return 0;
  }
  const char *url = "https://www.cloudflare.com/";
  const char *path = "/tmp/holytls_session_persist_test.json";

  EventLoop loop;
  loop_init(&loop);
  defer {
    loop_shutdown(&loop);
  };  // clients/sessions A and B are cleaned
      // explicitly below (A before B is created)

  //- client A: warm up + cache a ticket, then save
  //-----------------------------
  Client a;
  client_init(&a, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  CHECK(client_ok(&a));
  client_set_resumption_enabled(&a, 1);
  Session sa;
  session_init(&sa, 0);

  Ctx r1 = fetch_once(&a, &loop, url);  // fresh handshake; caches the ticket
  fprintf(stderr, "  warm:    got=%d status=%d resumed=%d\n", r1.got, r1.status,
          r1.resumed);
  CHECK(r1.got && r1.status == 200);
  CHECK(!r1.resumed);  // the very first connection can't resume

  CHECK(session_save(&sa, &a, path));  // snapshot cookies + tickets to disk

  session_cleanup(&sa);
  client_cleanup(&a);

  //- client B: brand-new, load the snapshot, then resume
  //-----------------------
  Client b;
  client_init(&b, &loop, profile_chrome148(), NULL, HttpVersion_H2,
              /*verify=*/1);
  CHECK(client_ok(&b));
  client_set_resumption_enabled(&b, 1);
  Session sb;
  session_init(&sb, 0);

  CHECK(session_load(&sb, &b, path));   // restore the cached ticket into B
  Ctx r2 = fetch_once(&b, &loop, url);  // offers the restored ticket -> resumes
  fprintf(stderr, "  restore: got=%d status=%d resumed=%d\n", r2.got, r2.status,
          r2.resumed);
  CHECK(r2.got && r2.status == 200);
  CHECK(r2.resumed);  // resumed from a ticket persisted across client instances

  session_cleanup(&sb);
  client_cleanup(&b);

  remove(path);
  fprintf(stderr, "[session_persist_live_test] %d checks, %d failures\n",
          g_checks, g_fails);
  return g_fails ? 1 : 0;
}
