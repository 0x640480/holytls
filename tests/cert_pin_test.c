// Offline certificate-pinning tests: pin add/validation (base64, 32-byte length,
// table-full), host matching (exact / subdomains / suffix-trick), and the
// SPKI-SHA256 extraction + match path exercised against a freshly generated
// self-signed certificate. The live handshake rejection is in cert_pin_live_test.
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/x509.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/base64.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"
#include "tls/cert_pin.h"

global int g_checks = 0;
global int g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

// base64 of `n` bytes into a NUL-terminated C buffer (for the const char* API).
internal void b64_cstr(Arena *a, const U8 *raw, U64 n, char *out, U64 cap) {
  String8 b = base64_encode(a, str8((U8 *)raw, n));
  U64 m = b.size < cap - 1 ? b.size : cap - 1;
  MemoryCopy(out, b.str, m);
  out[m] = 0;
}

internal X509 *gen_self_signed(void) {
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0);
  EVP_PKEY *pkey = 0;
  if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
      EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return 0;
  }
  EVP_PKEY_CTX_free(pctx);
  X509 *x = X509_new();
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), 0);
  X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
  X509_set_pubkey(x, pkey);
  X509_NAME *nm = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                             (const unsigned char *)"holytls-test", -1, -1, 0);
  X509_set_issuer_name(x, nm);
  X509_sign(x, pkey, EVP_sha256());
  EVP_PKEY_free(pkey);
  return x;
}

internal void test_add_validation(Arena *a) {
  CertPinStore s;
  MemoryZeroStruct(&s);
  U8 buf32[32], buf16[16];
  for (int i = 0; i < 32; ++i) buf32[i] = (U8)i;
  for (int i = 0; i < 16; ++i) buf16[i] = (U8)i;
  char b32[128], b16[128];
  b64_cstr(a, buf32, 32, b32, sizeof b32);
  b64_cstr(a, buf16, 16, b16, sizeof b16);

  CHECK(cert_pin_add(&s, "h.com", b32, 0));               // valid 32-byte pin
  CHECK(!cert_pin_add(&s, "h.com", b16, 0));              // wrong length (16B)
  CHECK(!cert_pin_add(&s, "h.com", "not valid base64!", 0));  // bad base64
  CHECK(!cert_pin_add(&s, 0, b32, 0));                    // null host
  CHECK(s.count == 1);                                     // only the valid one

  // Fill to capacity, then reject the overflow.
  CertPinStore full;
  MemoryZeroStruct(&full);
  for (int i = 0; i < CERT_PIN_MAX; ++i)
    CHECK(cert_pin_add(&full, "h.com", b32, 0));
  CHECK(!cert_pin_add(&full, "h.com", b32, 0));  // table full
}

internal void test_host_matching(Arena *a) {
  U8 raw[32];
  for (int i = 0; i < 32; ++i) raw[i] = (U8)(i + 1);
  char b32[128];
  b64_cstr(a, raw, 32, b32, sizeof b32);

  CertPinStore s;
  MemoryZeroStruct(&s);
  cert_pin_add(&s, "exact.com", b32, /*subdomains=*/0);
  cert_pin_add(&s, "sub.com", b32, /*subdomains=*/1);

  CHECK(cert_pin_host_has(&s, "exact.com"));
  CHECK(cert_pin_host_has(&s, "EXACT.com"));        // case-insensitive
  CHECK(!cert_pin_host_has(&s, "a.exact.com"));     // no subdomains for exact.com
  CHECK(!cert_pin_host_has(&s, "other.com"));

  CHECK(cert_pin_host_has(&s, "sub.com"));          // the apex
  CHECK(cert_pin_host_has(&s, "a.sub.com"));        // a subdomain
  CHECK(cert_pin_host_has(&s, "b.a.sub.com"));      // a deeper subdomain
  CHECK(!cert_pin_host_has(&s, "notsub.com"));      // suffix but not a label
  CHECK(!cert_pin_host_has(&s, "sub.com.evil.com")); // sub.com is not a suffix here
}

internal void test_spki_extract_and_match(Arena *a) {
  X509 *cert = gen_self_signed();
  CHECK(cert != 0);
  if (!cert) return;

  U8 spki[32], spki2[32];
  CHECK(cert_pin_compute_spki_sha256(cert, spki));
  CHECK(cert_pin_compute_spki_sha256(cert, spki2));
  CHECK(memcmp(spki, spki2, 32) == 0);  // deterministic

  char b64[128];
  b64_cstr(a, spki, 32, b64, sizeof b64);

  CertPinStore s;
  MemoryZeroStruct(&s);
  CHECK(cert_pin_add(&s, "pinned.com", b64, 0));
  CHECK(cert_pin_match(&s, "pinned.com", spki));     // the real pin matches
  CHECK(!cert_pin_match(&s, "other.com", spki));     // wrong host

  U8 wrong[32];
  MemoryCopy(wrong, spki, 32);
  wrong[0] ^= 0xff;                                   // one flipped byte
  CHECK(!cert_pin_match(&s, "pinned.com", wrong));    // mismatch is rejected

  // A second, different key yields a different SPKI hash.
  X509 *cert2 = gen_self_signed();
  CHECK(cert2 != 0);
  if (cert2) {
    U8 other[32];
    CHECK(cert_pin_compute_spki_sha256(cert2, other));
    CHECK(memcmp(spki, other, 32) != 0);
    X509_free(cert2);
  }
  X509_free(cert);
}

internal void test_client_api(Arena *a) {
  U8 raw[32];
  for (int i = 0; i < 32; ++i) raw[i] = (U8)(i * 3);
  char b32[128];
  b64_cstr(a, raw, 32, b32, sizeof b32);

  EventLoop loop;
  loop_init(&loop);
  Client c;
  client_init(&c, &loop, profile_chrome148(), /*verify=*/1);
  CHECK(client_ok(&c));

  CHECK(client_pin_certificate(&c, "api.example.com", b32, 0));   // ok
  CHECK(!client_pin_certificate(&c, "api.example.com", "bad!", 0));  // bad b64
  CHECK(c.pin_store.count == 1);
  CHECK(cert_pin_host_has(&c.pin_store, "api.example.com"));

  client_cleanup(&c);
  loop_shutdown(&loop);
}

int main(void) {
  Arena *a = arena_alloc();
  test_add_validation(a);
  test_host_matching(a);
  test_spki_extract_and_match(a);
  test_client_api(a);
  arena_release(a);
  fprintf(stderr, "[cert_pin_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
