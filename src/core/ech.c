#include "core/ech.h"

#include "base/base.h"
#include "base/base64.h"
#include "core/json.h"

// Value of the ` ech=` SvcParam token in a presentation-format HTTPS-record
// `data` string (e.g. "1 . alpn=h2 ipv4hint=1.2.3.4 ech=<base64> ipv6hint=..."),
// up to the next space. ech is never the first token (priority + target precede
// it), so the leading space makes this a safe token-boundary match.
internal String8 ech_find_param(String8 data) {
  S64 i = str8_find(data, str8_lit(" ech="));
  if (i < 0) return str8_zero();
  String8 rest = str8_skip(data, (U64)i + 5);
  U64 sp;
  if (str8_index_of(rest, ' ', &sp)) rest = str8_prefix(rest, sp);
  return rest;
}

String8 ech_config_from_doh(Arena *arena, String8 body) {
  yyjson_doc *doc = json_parse(arena, body);
  if (!doc) return str8_zero();
  yyjson_val *answer = yyjson_obj_get(json_root(doc), "Answer");
  if (!answer || !yyjson_is_arr(answer)) return str8_zero();
  size_t idx, max;
  yyjson_val *rec;
  yyjson_arr_foreach(answer, idx, max, rec) {
    if (yyjson_get_int(yyjson_obj_get(rec, "type")) != 65) continue;  // HTTPS RR
    String8 data = json_obj_str(rec, "data");
    String8 ech = ech_find_param(data);
    if (ech.size) return base64_decode(arena, ech);
  }
  return str8_zero();
}
