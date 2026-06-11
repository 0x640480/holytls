#include "core/persist.h"

#include <openssl/mem.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <uv.h>

#include "base/base64.h"
#include "core/cookie.h"
#include "core/json.h"
#include "net/loop.h"

// resume_cache_put / resume_cache_put_tp are internal helpers in client.c; this
// file is included into the unity TU after client.c (like pool.c / session.c), so
// their definitions are already in scope.

// ---------------------------------------------------------------------------
// build (marshal)
// ---------------------------------------------------------------------------
// Serializes the Client transport caches into `root`. Alt-Svc/ECH expiries are
// libuv monotonic ms; we emit remaining TTLs so the loading client can rebase.
internal void persist_build_client(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                   const Client *c, Arena *scratch) {
  U64 now = c->loop ? uv_now(loop_uv(c->loop)) : 0;

  yyjson_mut_val *ts = yyjson_mut_arr(doc);
  yyjson_mut_obj_add_val(doc, root, "tls_sessions", ts);
  for (int i = 0; i < c->resume_cache_count; ++i) {
    const ResumeCacheEntry *e = &c->resume_cache[i];
    if (!e->session) continue;
    uint8_t *der = 0;
    size_t der_len = 0;
    if (!SSL_SESSION_to_bytes(e->session, &der, &der_len) || der_len == 0) {
      if (der) OPENSSL_free(der);
      continue;
    }
    String8 tk = base64_encode(scratch, str8(der, der_len));
    OPENSSL_free(der);
    if (!tk.size) continue;
    yyjson_mut_val *o = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, o, "origin", e->origin);
    yyjson_mut_obj_add_strncpy(doc, o, "ticket", (const char *)tk.str, tk.size);
    if (e->zrtt_tp_len) {
      String8 tp = base64_encode(scratch, str8((U8 *)e->zrtt_tp, e->zrtt_tp_len));
      if (tp.size)
        yyjson_mut_obj_add_strncpy(doc, o, "zrtt_tp", (const char *)tp.str,
                                   tp.size);
    }
    yyjson_mut_arr_add_val(ts, o);
  }

  yyjson_mut_val *as = yyjson_mut_arr(doc);
  yyjson_mut_obj_add_val(doc, root, "alt_svc", as);
  for (int i = 0; i < c->alt_svc_count; ++i) {
    const AltSvcEntry *e = &c->alt_svc[i];
    U64 ttl = e->expiry_ms > now ? e->expiry_ms - now : 0;
    if (ttl == 0) continue;  // already expired -> nothing to carry over
    yyjson_mut_val *o = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, o, "origin", e->origin);
    yyjson_mut_obj_add_bool(doc, o, "h3", e->h3 != 0);
    yyjson_mut_obj_add_uint(doc, o, "ttl_ms", ttl);
    yyjson_mut_arr_add_val(as, o);
  }

  yyjson_mut_val *ec = yyjson_mut_arr(doc);
  yyjson_mut_obj_add_val(doc, root, "ech", ec);
  for (int i = 0; i < c->ech_cache_count; ++i) {
    const EchConfigEntry *e = &c->ech_cache[i];
    U64 ttl = e->expiry_ms > now ? e->expiry_ms - now : 0;
    if (ttl == 0) continue;
    yyjson_mut_val *o = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strcpy(doc, o, "origin", e->origin);
    if (e->config_len) {
      String8 cfg = base64_encode(scratch, str8((U8 *)e->config, e->config_len));
      yyjson_mut_obj_add_strncpy(doc, o, "config", (const char *)cfg.str,
                                 cfg.size);
    } else {
      yyjson_mut_obj_add_strcpy(doc, o, "config", "");  // cached negative result
    }
    yyjson_mut_obj_add_uint(doc, o, "ttl_ms", ttl);
    yyjson_mut_arr_add_val(ec, o);
  }
}

internal void persist_build_cookies(yyjson_mut_doc *doc, yyjson_mut_val *root,
                                    const CookieJar *jar) {
  yyjson_mut_val *arr = yyjson_mut_arr(doc);
  yyjson_mut_obj_add_val(doc, root, "cookies", arr);
  for (U64 i = 0; i < jar->count; ++i) {
    const Cookie *ck = &jar->v[i];
    yyjson_mut_val *o = yyjson_mut_obj(doc);
    yyjson_mut_obj_add_strncpy(doc, o, "name", (const char *)ck->name.str,
                               ck->name.size);
    yyjson_mut_obj_add_strncpy(doc, o, "value", (const char *)ck->value.str,
                               ck->value.size);
    yyjson_mut_obj_add_strncpy(doc, o, "domain", (const char *)ck->domain.str,
                               ck->domain.size);
    yyjson_mut_obj_add_strncpy(doc, o, "path", (const char *)ck->path.str,
                               ck->path.size);
    yyjson_mut_obj_add_uint(doc, o, "expires", ck->expires_epoch);
    yyjson_mut_obj_add_bool(doc, o, "host_only", ck->host_only != 0);
    yyjson_mut_obj_add_bool(doc, o, "secure", ck->secure != 0);
    yyjson_mut_obj_add_bool(doc, o, "http_only", ck->http_only != 0);
    yyjson_mut_obj_add_uint(doc, o, "same_site", ck->same_site);
    yyjson_mut_arr_add_val(arr, o);
  }
}

String8 client_state_marshal(Arena *arena, const Client *c, B32 pretty) {
  if (!c) return str8_zero();
  Temp scr = scratch_begin(&arena, 1);
  yyjson_mut_doc *doc = json_mut(scr.arena);
  yyjson_mut_val *root = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, root);
  yyjson_mut_obj_add_int(doc, root, "version", HOLYTLS_PERSIST_VERSION);
  persist_build_client(doc, root, c, scr.arena);
  String8 out = json_mut_write(arena, doc, pretty);
  scratch_end(scr);
  return out;
}

String8 session_marshal(Arena *arena, const Session *s, const Client *c,
                        B32 pretty) {
  Temp scr = scratch_begin(&arena, 1);
  yyjson_mut_doc *doc = json_mut(scr.arena);
  yyjson_mut_val *root = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, root);
  yyjson_mut_obj_add_int(doc, root, "version", HOLYTLS_PERSIST_VERSION);
  if (c) persist_build_client(doc, root, c, scr.arena);
  if (s) persist_build_cookies(doc, root, &s->jar);
  String8 out = json_mut_write(arena, doc, pretty);
  scratch_end(scr);
  return out;
}

// ---------------------------------------------------------------------------
// restore (unmarshal)
// ---------------------------------------------------------------------------
internal void persist_put_alt_svc(Client *c, String8 origin, B32 h3,
                                  U64 expiry_ms) {
  for (int i = 0; i < c->alt_svc_count; ++i)
    if (str8_match(origin, str8_cstring(c->alt_svc[i].origin))) {
      c->alt_svc[i].h3 = h3;
      c->alt_svc[i].expiry_ms = expiry_ms;
      return;
    }
  if (c->alt_svc_count >= (int)ArrayCount(c->alt_svc)) return;
  AltSvcEntry *e = &c->alt_svc[c->alt_svc_count++];
  U64 n = origin.size < sizeof e->origin - 1 ? origin.size : sizeof e->origin - 1;
  MemoryCopy(e->origin, origin.str, n);
  e->origin[n] = 0;
  e->h3 = h3;
  e->expiry_ms = expiry_ms;
}

internal void persist_put_ech(Client *c, String8 origin, const U8 *cfg,
                              U64 cfg_len, U64 expiry_ms) {
  EchConfigEntry *e = 0;
  for (int i = 0; i < c->ech_cache_count; ++i)
    if (str8_match(origin, str8_cstring(c->ech_cache[i].origin))) {
      e = &c->ech_cache[i];
      break;
    }
  if (!e) {
    if (c->ech_cache_count >= (int)ArrayCount(c->ech_cache)) return;
    e = &c->ech_cache[c->ech_cache_count++];
    U64 n =
        origin.size < sizeof e->origin - 1 ? origin.size : sizeof e->origin - 1;
    MemoryCopy(e->origin, origin.str, n);
    e->origin[n] = 0;
  }
  U64 n = cfg_len < sizeof e->config ? cfg_len : sizeof e->config;
  if (n) MemoryCopy(e->config, cfg, n);
  e->config_len = n;
  e->expiry_ms = expiry_ms;
}

// Merges the transport caches from `root` into `c` (per-origin replace; never
// clears). `scratch` backs base64 decoding; restored data is copied out of it
// (SSL_SESSIONs are heap, alt-svc/ech into the client's fixed arrays) so it is
// safe to release after.
internal void persist_restore_client(Client *c, yyjson_val *root, Arena *scratch) {
  U64 now = c->loop ? uv_now(loop_uv(c->loop)) : 0;

  yyjson_val *ts = yyjson_obj_get(root, "tls_sessions");
  if (ts && yyjson_is_arr(ts) && c->ctx.ctx) {
    size_t idx, max;
    yyjson_val *it;
    yyjson_arr_foreach(ts, idx, max, it) {
      String8 origin = json_obj_str(it, "origin");
      String8 tk = json_obj_str(it, "ticket");
      if (!origin.size || !tk.size) continue;
      String8 der = base64_decode(scratch, tk);
      if (!der.size) continue;
      SSL_SESSION *sess = SSL_SESSION_from_bytes(der.str, der.size, c->ctx.ctx);
      if (!sess) continue;
      resume_cache_put(c, origin, sess);  // adopts ownership
      String8 ztp = json_obj_str(it, "zrtt_tp");
      if (ztp.size) {
        String8 tp = base64_decode(scratch, ztp);
        if (tp.size) resume_cache_put_tp(c, origin, tp.str, tp.size);
      }
    }
  }

  yyjson_val *as = yyjson_obj_get(root, "alt_svc");
  if (as && yyjson_is_arr(as)) {
    size_t idx, max;
    yyjson_val *it;
    yyjson_arr_foreach(as, idx, max, it) {
      String8 origin = json_obj_str(it, "origin");
      if (!origin.size) continue;
      B32 h3 = yyjson_get_bool(yyjson_obj_get(it, "h3"));
      U64 ttl = yyjson_get_uint(yyjson_obj_get(it, "ttl_ms"));
      persist_put_alt_svc(c, origin, h3, now + ttl);
    }
  }

  yyjson_val *ec = yyjson_obj_get(root, "ech");
  if (ec && yyjson_is_arr(ec)) {
    size_t idx, max;
    yyjson_val *it;
    yyjson_arr_foreach(ec, idx, max, it) {
      String8 origin = json_obj_str(it, "origin");
      if (!origin.size) continue;
      U64 ttl = yyjson_get_uint(yyjson_obj_get(it, "ttl_ms"));
      String8 cfgb64 = json_obj_str(it, "config");
      String8 cfg = cfgb64.size ? base64_decode(scratch, cfgb64) : str8_zero();
      persist_put_ech(c, origin, cfg.str, cfg.size, now + ttl);
    }
  }
}

internal void persist_restore_cookies(Session *s, yyjson_val *root) {
  yyjson_val *arr = yyjson_obj_get(root, "cookies");
  if (!arr || !yyjson_is_arr(arr)) return;
  size_t idx, max;
  yyjson_val *it;
  yyjson_arr_foreach(arr, idx, max, it) {
    String8 name = json_obj_str(it, "name");
    if (!name.size) continue;
    String8 value = json_obj_str(it, "value");
    String8 domain = json_obj_str(it, "domain");
    String8 path = json_obj_str(it, "path");
    U64 expires = yyjson_get_uint(yyjson_obj_get(it, "expires"));
    B32 host_only = yyjson_get_bool(yyjson_obj_get(it, "host_only"));
    B32 secure = yyjson_get_bool(yyjson_obj_get(it, "secure"));
    B32 http_only = yyjson_get_bool(yyjson_obj_get(it, "http_only"));
    U8 same_site = (U8)yyjson_get_uint(yyjson_obj_get(it, "same_site"));
    cookie_jar_put(&s->jar, name, value, domain, path, expires, host_only, secure,
                   http_only, same_site);
  }
}

// Common gate: parse + version check. Returns the root obj (in `scratch`) or 0.
internal yyjson_val *persist_open(Arena *scratch, String8 json) {
  yyjson_doc *doc = json_parse(scratch, json);
  if (!doc) return 0;
  yyjson_val *root = json_root(doc);
  if (!yyjson_is_obj(root)) return 0;
  if (yyjson_get_int(yyjson_obj_get(root, "version")) != HOLYTLS_PERSIST_VERSION)
    return 0;
  return root;
}

B32 client_state_unmarshal(Client *c, String8 json) {
  if (!c) return 0;
  Temp scr = scratch_begin(0, 0);
  yyjson_val *root = persist_open(scr.arena, json);
  B32 ok = 0;
  if (root) {
    persist_restore_client(c, root, scr.arena);
    ok = 1;
  }
  scratch_end(scr);
  return ok;
}

B32 session_unmarshal(Session *s, Client *c, String8 json) {
  Temp scr = scratch_begin(0, 0);
  yyjson_val *root = persist_open(scr.arena, json);
  B32 ok = 0;
  if (root) {
    if (c) persist_restore_client(c, root, scr.arena);
    if (s) persist_restore_cookies(s, root);
    ok = 1;
  }
  scratch_end(scr);
  return ok;
}

// ---------------------------------------------------------------------------
// file wrappers (synchronous stdio)
// ---------------------------------------------------------------------------
B32 session_save(const Session *s, const Client *c, const char *path) {
  Arena *a = arena_alloc();
  String8 json = session_marshal(a, s, c, /*pretty=*/1);
  B32 ok = 0;
  if (json.size) {
    // Write-then-rename so a crash mid-write never corrupts an existing file:
    // the rename is atomic, the old contents survive any earlier failure.
    char tmp[1024];
    int n = snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (n > 0 && (U64)n < sizeof tmp) {
      FILE *f = fopen(tmp, "wb");
      if (f) {
        ok = fwrite(json.str, 1, json.size, f) == json.size;
        if (fclose(f) != 0) ok = 0;
        if (ok) ok = rename(tmp, path) == 0;
        if (!ok) remove(tmp);
      }
    }
  }
  arena_release(a);
  return ok;
}

B32 session_load(Session *s, Client *c, const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  B32 ok = 0;
  if (fseek(f, 0, SEEK_END) == 0) {
    long n = ftell(f);
    // Sanity cap: a session file is KBs of JSON; refuse to slurp something
    // wildly larger (corrupt/mistaken path) into memory.
    if (n > (64l << 20)) n = 0;
    if (n > 0 && fseek(f, 0, SEEK_SET) == 0) {
      Arena *a = arena_alloc();
      U8 *buf = push_array_no_zero(a, U8, (U64)n);
      if (fread(buf, 1, (U64)n, f) == (U64)n)
        ok = session_unmarshal(s, c, str8(buf, (U64)n));
      arena_release(a);
    }
  }
  fclose(f);
  return ok;
}
