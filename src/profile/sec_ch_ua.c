#include "profile/sec_ch_ua.h"

#include "base/u8buf.h"

// Constants copied verbatim (and in exact order) from Chromium
// components/embedder_support/user_agent_utils.cc.
//   greasey_chars  : the 11 separator characters
//   greased_versions: the 3 GREASE version strings
//   k_order3       : the 3-brand permutation table (orders3), indexed by
//                    `major % 6`. order[i] is the DESTINATION slot for the i-th
//                    pre-shuffle element (scatter, not gather).
global const char *const k_grease_chars[] = {" ", "(", ":", "-", ".", "/",
                                             ")", ";", "=", "?", "_"};
global const char *const k_grease_versions[] = {"8", "99", "24"};
global const U8 k_order3[6][3] = {{0, 1, 2}, {0, 2, 1}, {1, 0, 2},
                                  {1, 2, 0}, {2, 0, 1}, {2, 1, 0}};

// Assemble the permuted brand list. `real_ver` is the version string for the two
// real brands ("Chromium", "Google Chrome"); `grease_ver` is the GREASE brand's
// version. The GREASE brand NAME (Not<sep>A<sep>Brand) and the brand ORDER are
// derived from `major` (the GREASE seed) exactly as Chromium does. Version
// strings are appended byte-wise (no NUL assumption — `real_ver` may be a
// caller-supplied view).
internal String8 sec_ch_ua_format(Arena *arena, U32 major, String8 real_ver,
                                  String8 grease_ver) {
  const char *sep1 = k_grease_chars[major % ArrayCount(k_grease_chars)];
  const char *sep2 = k_grease_chars[(major + 1) % ArrayCount(k_grease_chars)];
  char gbrand[16];
  snprintf(gbrand, sizeof gbrand, "Not%sA%sBrand", sep1, sep2);

  // Pre-shuffle list: [0]=GREASE, [1]=Chromium, [2]=Google Chrome.
  const char *names[3] = {gbrand, "Chromium", "Google Chrome"};
  String8 vers[3] = {grease_ver, real_ver, real_ver};

  // Permute: out[order[i]] = built[i].
  const U8 *order = k_order3[major % ArrayCount(k_order3)];
  const char *out_names[3];
  String8 out_vers[3];
  for (int i = 0; i < 3; ++i) {
    out_names[order[i]] = names[i];
    out_vers[order[i]] = vers[i];
  }

  // Render: "Name";v="ver", "Name";v="ver", "Name";v="ver".
  U8Buf buf;
  u8buf_init(&buf, arena, 192);
  for (int i = 0; i < 3; ++i) {
    if (i) u8buf_append(&buf, (const U8 *)", ", 2);
    u8buf_append(&buf, (const U8 *)"\"", 1);
    u8buf_append(&buf, (const U8 *)out_names[i], strlen(out_names[i]));
    u8buf_append(&buf, (const U8 *)"\";v=\"", 5);
    u8buf_append(&buf, out_vers[i].str, out_vers[i].size);
    u8buf_append(&buf, (const U8 *)"\"", 1);
  }
  return u8buf_str8(&buf);
}

String8 sec_ch_ua_brands(Arena *arena, U32 major) {
  char ver[16];
  snprintf(ver, sizeof ver, "%u", major);
  const char *gver = k_grease_versions[major % ArrayCount(k_grease_versions)];
  return sec_ch_ua_format(arena, major, str8_cstring(ver), str8_cstring(gver));
}

String8 sec_ch_ua_full_version_list(Arena *arena, U32 major,
                                    String8 full_version) {
  char fallback[16];
  if (full_version.size == 0) {  // UA-frozen best effort when no build supplied
    snprintf(fallback, sizeof fallback, "%u.0.0.0", major);
    full_version = str8_cstring(fallback);
  }
  // The GREASE brand's version in the full list is the greased digit + ".0.0.0".
  const char *digit = k_grease_versions[major % ArrayCount(k_grease_versions)];
  char gver[16];
  snprintf(gver, sizeof gver, "%s.0.0.0", digit);
  return sec_ch_ua_format(arena, major, full_version, str8_cstring(gver));
}
