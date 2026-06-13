// holytls — unity build. This is the single translation unit compiled for the
// library; each subsystem slice appends its #include here (one cc invocation,
// whole-program visibility, cross-file inlining).
#include "base/base.c"
#include "base/base64.c"
#include "core/alt_svc.c"
#include "core/client.c"
#include "core/cookie.c"
#include "core/decompress.c"
#include "core/ech.c"
#include "core/header.c"
#include "core/header_order.c"
#include "core/json.c"
#include "core/manager.c"  // after session.c: registry of sessions
#include "core/persist.c"  // after session.c: marshals Client + Session state
#include "core/pool.c"  // after client.c: reuses its internal request helpers
#include "core/psl.c"   // before cookie.c: the jar's public-suffix guard
#include "core/sec_fetch.c"
#include "core/session.c"  // after client.c: uses client_send + url/redirect helpers
#include "core/url.c"
#include "h1/h1.c"
#include "h2/h2.c"
#include "h3/h3_control.c"
#include "h3/h3_session.c"
#include "net/connection.c"
#include "net/dns_cache.c"  // before connection.c: the resolve path uses it
#include "net/loop.c"
#include "net/proxy.c"  // before connection.c: the proxy negotiation framing
#include "net/quic_connection.c"
#include "profile/profiles.c"
#include "profile/sec_ch_ua.c"
#include "tls/cert_compress.c"
#include "tls/cert_pin.c"
#include "tls/ja4.c"
#include "tls/keylog.c"
#include "tls/ssl_conn.c"
#include "tls/ssl_ctx.c"
