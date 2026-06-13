// Offline Manager tests: id uniqueness, get pins / release unpins, max-sessions
// cap, lazy idle eviction (oldest idle reclaimed, pinned sessions never),
// unknown ids. Lightweight sessions need no network/SSL_CTX, so this runs fully
// offline.
#include "core/manager.h"

#include <stdio.h>
#include <string.h>
#include <uv.h>

#include "base/base.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

int main(void) {
  SessionConfig cfg;
  session_config_default(&cfg);

  //- id uniqueness + get/release + config application
  {
    Manager m;
    manager_init(&m);
    enum { N = 64 };
    char ids[N][MANAGER_ID_LEN];
    for (int i = 0; i < N; ++i)
      CHECK(manager_create_session(&m, &cfg, ids[i]) == 0);
    for (int i = 0; i < N; ++i) {
      CHECK(strlen(ids[i]) == 32);
      for (int j = i + 1; j < N; ++j) CHECK(strcmp(ids[i], ids[j]) != 0);
    }
    Session *s = manager_get_session(&m, ids[0]);
    CHECK(s != 0);
    CHECK(s->cookies_enabled == 1 && s->max_redirects == 10);  // cfg applied
    manager_release_session(&m, ids[0]);
    CHECK(manager_get_session(&m, "deadbeefdeadbeefdeadbeefdeadbeef") == 0);
    manager_release_session(&m, "nope");  // no-op
    manager_shutdown(&m);
  }

  //- capacity + lazy eviction + pinned-never-evicted
  {
    Manager m;
    manager_init(&m);
    manager_set_max_sessions(&m, 2);
    manager_set_session_timeout(&m, 10);  // ms
    char a[MANAGER_ID_LEN], b[MANAGER_ID_LEN], c[MANAGER_ID_LEN],
        d[MANAGER_ID_LEN];
    CHECK(manager_create_session(&m, &cfg, a) == 0);
    CHECK(manager_create_session(&m, &cfg, b) == 0);
    CHECK(manager_create_session(&m, &cfg, c) == -1);  // at cap, nothing idle

    uv_sleep(25);                                     // a,b now idle > 10 ms
    CHECK(manager_create_session(&m, &cfg, c) == 0);  // evicts oldest idle (a)
    CHECK(manager_get_session(&m, a) == 0);           // a evicted
    CHECK(manager_get_session(&m, b) != 0);           // b survived (now pinned)

    uv_sleep(25);                                     // c idle; b pinned
    CHECK(manager_create_session(&m, &cfg, d) == 0);  // must evict c, not b
    CHECK(manager_get_session(&m, c) == 0);           // c evicted
    CHECK(manager_get_session(&m, b) != 0);           // pinned b NOT evicted
    CHECK(manager_get_session(&m, d) != 0);
    manager_shutdown(&m);
  }

  fprintf(stderr, "[manager_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
