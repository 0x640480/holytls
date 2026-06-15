// Offline profile-data snapshot. Locks the wire-relevant field VALUES of each
// profile that the JA4 / Akamai ClientHello fingerprints do NOT hash — most
// importantly the QUIC transport parameters + H3 SETTINGS, which are otherwise
// only verified live (fingerprint_h3_test). Together with ja4_test (TLS
// ClientHello) + h2_test (Akamai) this makes the whole wire surface offline-
// checkable, so a refactor of how profiles are stored can be proven value-exact.
// Also exercises the by-name profile registry.
#include <stdio.h>

#include "base/base.h"
#include "base/string8.h"
#include "profile/profile.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

// Chrome's H2 fingerprint (shared by 148/149).
static void snap_h2(const Profile *p) {
  CHECK(p->h2.settings_count == 4);
  CHECK(p->h2.settings[0].id == H2Setting_HeaderTableSize &&
        p->h2.settings[0].value == 65536);
  CHECK(p->h2.settings[1].id == H2Setting_EnablePush &&
        p->h2.settings[1].value == 0);
  CHECK(p->h2.settings[2].id == H2Setting_InitialWindowSize &&
        p->h2.settings[2].value == 6291456);
  CHECK(p->h2.settings[3].id == H2Setting_MaxHeaderListSize &&
        p->h2.settings[3].value == 262144);
  CHECK(p->h2.connection_window_increment == 15663105);
  CHECK(p->h2.use_priority && p->h2.priority_weight == 256 &&
        p->h2.priority_exclusive && p->h2.priority_dep_stream == 0);
  CHECK(p->h2.pseudo_count == 4 && p->h2.pseudo_order[0] == Pseudo_Method &&
        p->h2.pseudo_order[1] == Pseudo_Authority &&
        p->h2.pseudo_order[2] == Pseudo_Scheme &&
        p->h2.pseudo_order[3] == Pseudo_Path);
  CHECK(p->default_header_count == 14);
}

// Chrome's QUIC transport params + H3 SETTINGS (shared by 148/149).
static void snap_h3(const QuicProfile *q) {
  CHECK(q->h3.initial_max_data == 15728640);
  CHECK(q->h3.initial_max_stream_data_bidi_local == 6291456);
  CHECK(q->h3.initial_max_stream_data_bidi_remote == 6291456);
  CHECK(q->h3.initial_max_stream_data_uni == 6291456);
  CHECK(q->h3.initial_max_streams_bidi == 100);
  CHECK(q->h3.initial_max_streams_uni == 103);
  CHECK(q->h3.max_idle_timeout_ms == 30000);
  CHECK(q->h3.max_udp_payload_size == 1472);
  CHECK(q->h3.max_datagram_frame_size == 65536);
  CHECK(q->h3.settings_count == 4);
  CHECK(q->h3.settings[0].id == 0x01 && q->h3.settings[0].value == 65536);
  CHECK(q->h3.settings[1].id == 0x06 && q->h3.settings[1].value == 262144);
  CHECK(q->h3.settings[2].id == 0x07 && q->h3.settings[2].value == 100);
  CHECK(q->h3.settings[3].id == 0x33 && q->h3.settings[3].value == 1);
  CHECK(q->h3.settings_grease && q->h3.send_grease_frame &&
        q->h3.send_priority_update);
  CHECK(q->h3.pseudo_count == 4);
  CHECK(q->default_header_count == 14);
}

// Firefox 151 H2 + QUIC field values (captured; differ from Chrome).
static void snap_firefox(void) {
  const Profile *p = profile_firefox151();
  CHECK(p->h2.settings_count == 4);
  CHECK(p->h2.settings[2].id == H2Setting_InitialWindowSize &&
        p->h2.settings[2].value == 131072);  // 131072, not Chrome's 6291456
  CHECK(p->h2.settings[3].id == H2Setting_MaxFrameSize &&
        p->h2.settings[3].value == 16384);
  CHECK(p->h2.connection_window_increment == 12517377);
  CHECK(p->h2.use_priority && p->h2.priority_weight == 42);
  CHECK(p->h2.pseudo_order[1] == Pseudo_Path);  // H2: m,p,a,s
  CHECK(p->default_header_count == 13);

  const QuicProfile *q = profile_firefox151_h3();
  CHECK(q->h3.initial_max_data == 25165824);
  CHECK(q->h3.initial_max_stream_data_bidi_local == 12582912);
  CHECK(q->h3.initial_max_stream_data_bidi_remote == 1048576);
  CHECK(q->h3.max_datagram_frame_size == 65535);  // 65535, not Chrome's 65536
  CHECK(q->h3.settings_count == 6);
  CHECK(q->h3.settings[2].id == 727725890 && q->h3.settings[2].value == 0);
  CHECK(q->h3.settings[3].id == 16765559 && q->h3.settings[3].value == 1);
  CHECK(q->h3.pseudo_order[1] == Pseudo_Scheme);  // H3: m,s,a,p (differs from H2)
  // No sec-ch-ua / client-hints.
  CHECK(profile_sec_ch_ua(p).size == 0);
  CHECK(str8_contains(profile_user_agent(p), str8_lit("Firefox/151.0")));
}

int main(void) {
  snap_h2(profile_chrome148());
  snap_h2(profile_chrome149());
  snap_h3(profile_chrome148_h3());
  snap_h3(profile_chrome149_h3());
  snap_firefox();

  // UA / sec-ch-ua are the per-version deltas; confirm they carry the version.
  CHECK(str8_contains(profile_user_agent(profile_chrome148()),
                      str8_lit("Chrome/148.0.0.0")));
  CHECK(str8_contains(profile_user_agent(profile_chrome149()),
                      str8_lit("Chrome/149.0.0.0")));
  CHECK(str8_contains(profile_sec_ch_ua(profile_chrome149()),
                      str8_lit("v=\"149\"")));

  // Registry + by-name resolution (the selection surface the capi/Python use).
  U64 n = 0;
  const ProfileEntry *reg = profile_registry(&n);
  CHECK(n >= 3);
  CHECK(reg[0].h2() == profile_chrome149());  // entry 0 = default (newest)
  CHECK(profile_by_name(str8_lit("chrome148")) == profile_chrome148());
  CHECK(profile_by_name(str8_lit("CHROME149")) == profile_chrome149());  // ci
  CHECK(profile_quic_by_name(str8_lit("chrome148")) == profile_chrome148_h3());
  CHECK(profile_by_name(str8_lit("firefox151")) == profile_firefox151());
  CHECK(profile_quic_by_name(str8_lit("Firefox151")) == profile_firefox151_h3());
  CHECK(profile_by_name(str8_lit("safari")) == 0);  // unknown -> 0
  CHECK(profile_quic_by_name(str8_lit("nope")) == 0);

  fprintf(stderr, "[profile_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
