// JA4 golden: validate the JA4 implementation against canonical vectors, then
// build the template + chrome148 SSL_CTX with the BoringSSL fork, capture the
// ClientHello each emits (offline, via a memory BIO), and assert the full JA4
// byte-for-byte.
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "profile/profile.h"
#include "tls/ja4.h"
#include "tls/ssl_ctx.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                  \
  Statement(g_checks += 1; if (!(c)) {                            \
    g_fails += 1;                                                 \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

internal ClientHelloInfo capture_client_hello(const Profile *prof,
                                              CtxResult *cr) {
  *cr = build_ctx(&prof->tls, 0);
  ClientHelloInfo info;
  MemoryZeroStruct(&info);
  if (!ctx_ok(cr)) return info;

  SSL *ssl = SSL_new(cr->ctx);
  BIO *rbio = BIO_new(BIO_s_mem());
  BIO *wbio = BIO_new(BIO_s_mem());
  SSL_set_bio(ssl, rbio, wbio);  // takes ownership of both
  SSL_set_connect_state(ssl);
  configure_ssl(ssl, &prof->tls, "tls.browserleaks.com", 0, 0, 0, 0);
  SSL_do_handshake(ssl);  // emits ClientHello into wbio, then WANT_READ

  const U8 *data = 0;
  size_t len = 0;
  BIO_mem_contents(wbio, &data, &len);
  if (data && len) info = ja4_parse_record(data, len);
  SSL_free(ssl);  // frees rbio/wbio
  return info;
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
  CHECK(str8_match(
      fp.ja4_r, str8_lit("t13d0304h2_1301,1302,c02b_000d,0017_0403,0804")));
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

int main(void) {
  Arena *a = arena_alloc();
  test_ja4_impl(a);
  test_profile(a, profile_template(), "t13d1717h2_5b57614c22b0_3cbfd9057e0d");
  test_profile(a, profile_chrome148(), "t13d1516h2_8daaf6152771_d8a2da3f94cd");
  // Chrome 149 is wire-identical to 148, so its ClientHello must hash to the
  // same JA4 — which is exactly the JA4 captured from real Chrome 149 (powhttp).
  test_profile(a, profile_chrome149(), "t13d1516h2_8daaf6152771_d8a2da3f94cd");
  arena_release(a);
  fprintf(stderr, "[ja4_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
