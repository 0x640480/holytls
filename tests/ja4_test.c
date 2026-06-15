// JA4 golden: validate the JA4 implementation against canonical vectors, then
// build the template + chrome148 SSL_CTX with the BoringSSL fork, capture the
// ClientHello each emits (offline, via a memory BIO), and assert the full JA4
// byte-for-byte.
#include "tls/ja4.h"

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "profile/profile.h"
#include "tls/ssl_ctx.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal ClientHelloInfo capture_tls(const TlsProfile *tls, CtxResult *cr) {
  *cr = build_ctx(tls, 0);
  ClientHelloInfo info;
  MemoryZeroStruct(&info);
  if (!ctx_ok(cr)) return info;

  SSL *ssl = SSL_new(cr->ctx);
  BIO *rbio = BIO_new(BIO_s_mem());
  BIO *wbio = BIO_new(BIO_s_mem());
  SSL_set_bio(ssl, rbio, wbio);  // takes ownership of both
  SSL_set_connect_state(ssl);
  configure_ssl(ssl, tls, "tls.browserleaks.com", 0, 0, 0, 0);
  SSL_do_handshake(ssl);  // emits ClientHello into wbio, then WANT_READ

  const U8 *data = 0;
  size_t len = 0;
  BIO_mem_contents(wbio, &data, &len);
  if (data && len) info = ja4_parse_record(data, len);
  SSL_free(ssl);  // frees rbio/wbio
  return info;
}
internal ClientHelloInfo capture_client_hello(const Profile *prof,
                                              CtxResult *cr) {
  return capture_tls(&prof->tls, cr);
}

//- Part A: validate the JA4 implementation with independent vectors.
internal void test_ja4_impl(Arena *a) {
  CHECK(ja4_is_grease(0x0a0a));
  CHECK(ja4_is_grease(0xfafa));
  CHECK(!ja4_is_grease(0x1301));
  CHECK(!ja4_is_grease(0x000d));
  // Canonical SHA-256("abc") truncated to 12 hex chars.
  CHECK(str8_match(ja4_sha256_hex(a, str8_lit("abc"), 12),
                   str8_lit("ba7816bf8f01")));

  ClientHelloInfo in;
  MemoryZeroStruct(&in);
  in.ok = 1;
  in.transport = 't';
  in.legacy_version = 0x0303;
  U16 ciphers[] = {0x0a0a, 0x1301, 0x1302, 0xc02b};
  MemoryCopy(in.cipher_suites, ciphers, sizeof ciphers);
  in.cipher_count = 4;
  U16 exts[] = {0x0000, 0x0010, 0x000d, 0x0a0a, 0x0017};
  MemoryCopy(in.extensions, exts, sizeof exts);
  in.ext_count = 5;
  U16 sigs[] = {0x0403, 0x0804};
  MemoryCopy(in.sig_algs, sigs, sizeof sigs);
  in.sig_count = 2;
  in.supported_versions[0] = 0x0304;
  in.sv_count = 1;
  in.has_sni = 1;
  in.alpn_first[0] = 'h';
  in.alpn_first[1] = '2';
  in.alpn_len = 2;

  Fingerprints fp = ja4_compute(a, &in);
  CHECK(str8_match(fp.ja4_r,
                   str8_lit("t13d0304h2_1301,1302,c02b_000d,0017_0403,0804")));
}

//- Part B: capture a real ClientHello and assert the full JA4.
internal void test_profile(Arena *a, const Profile *prof, const char *golden) {
  CtxResult cr;
  ClientHelloInfo info = capture_client_hello(prof, &cr);
  CHECK(ctx_ok(&cr));
  CHECK(info.ok);
  if (info.ok) {
    Fingerprints fp = ja4_compute(a, &info);
    fprintf(stderr, "  %-13s JA4 = %.*s  golden = %s\n", prof->name,
            (int)fp.ja4.size, fp.ja4.str, golden);
    CHECK(str8_match(fp.ja4, str8_cstring(golden)));
  }
  if (cr.ctx) SSL_CTX_free(cr.ctx);
}

// Capture the TLS half of a QUIC/H3 profile's ClientHello (h3 ALPN, TLS1.3-only,
// h3 sig-algs) and assert its JA4. Locks every h3 TlsProfile field offline (the
// QUIC transport params ride QUIC separately and are value-locked in profile_test).
internal void test_quic_profile(Arena *a, const QuicProfile *prof,
                                const char *golden) {
  CtxResult cr;
  ClientHelloInfo info = capture_tls(&prof->tls, &cr);
  CHECK(ctx_ok(&cr));
  CHECK(info.ok);
  if (info.ok) {
    Fingerprints fp = ja4_compute(a, &info);
    fprintf(stderr, "  %-13s JA4 = %.*s  golden = %s\n", prof->name,
            (int)fp.ja4.size, fp.ja4.str, golden);
    CHECK(str8_match(fp.ja4, str8_cstring(golden)));
  }
  if (cr.ctx) SSL_CTX_free(cr.ctx);
}

int main(void) {
  Arena *a = arena_alloc();
  test_ja4_impl(a);
  test_profile(a, profile_template(), "t13d1717h2_5b57614c22b0_3cbfd9057e0d");
  test_profile(a, profile_chrome148(), "t13d1516h2_8daaf6152771_d8a2da3f94cd");
  // Chrome 149 is wire-identical to 148, so its ClientHello must hash to the
  // same JA4 — which is exactly the JA4 captured from real Chrome 149
  // (powhttp).
  test_profile(a, profile_chrome149(), "t13d1516h2_8daaf6152771_d8a2da3f94cd");

  // WebSocket ClientHello: a fresh browser WebSocket connection offers an
  // http/1.1-only ALPN and DROPS the ALPS (application_settings, 0x4469)
  // extension — 15 extensions instead of 16, same ciphers/sig-algs. This is the
  // transformation src/ws/ws.c applies (ws_h1_tls). Must hash to the JA4
  // captured from real Chrome 149 opening wss://echo.websocket.org (powhttp):
  // t13d1515h1_8daaf6152771_0a20fe35d3a5 (note the h1 + 1515 vs the h2 + 1516
  // above; the cipher hash 8daaf6152771 is unchanged).
  {
    static const U8 ws_alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    Profile ws = *profile_chrome149();
    ws.name = "chrome149-ws";
    ws.tls.alpn_wire = ws_alpn;
    ws.tls.alpn_wire_len = (U16)sizeof ws_alpn;
    ws.tls.alps_count = 0;
    test_profile(a, &ws, "t13d1515h1_8daaf6152771_0a20fe35d3a5");
  }

  // HTTP/3 (QUIC) profiles — the TLS half of the ClientHello. Both 148/149 h3
  // are wire-identical; locks the h3 TlsProfile fields offline.
  test_quic_profile(a, profile_chrome148_h3(), "t13d0310h3_55b375c5d22e_7e133008cbfb");
  test_quic_profile(a, profile_chrome149_h3(), "t13d0310h3_55b375c5d22e_7e133008cbfb");

  // Firefox 151 — a genuinely different fingerprint: no GREASE, FFDHE groups, no
  // ALPS, fixed extension order. H2 JA4 captured from real Firefox 151
  // (browserleaks). H3 JA4 is the build_ctx TLS-form of the QUIC profile.
  test_profile(a, profile_firefox151(), "t13d1617h2_86a278354501_3cbfd9057e0d");
  // Firefox H3: offline build_ctx JA4 == the live q13d0315h3 minus the
  // quic_transport_parameters(0039) ext ngtcp2 injects at runtime (same -1 as
  // Chrome's 0311->0310). Includes the Firefox-only EMS(0017)+reneg(ff01) the
  // fork patch re-enables, and the H3 sigalgs order.
  test_quic_profile(a, profile_firefox151_h3(), "t13d0314h3_55b375c5d22e_056779b56822");

  arena_release(a);
  fprintf(stderr, "[ja4_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
