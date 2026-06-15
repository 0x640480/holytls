// Offline mutual-TLS (client certificate) test. A loopback origin requests a
// client cert (CertificateRequest, accept-any) and reports — in the response
// body — whether the connection presented one. We confirm: (1) without a cert
// the request still completes and the server sees none; (2) after
// client_set_client_cert the server sees the presented cert; (3) the cert is
// FINGERPRINT-NEUTRAL — a ClientHello captured with the cert loaded hashes to
// the unchanged Chrome JA4 (the cert is sent only after the ServerHello). Run
// under ASan to prove no leaks in the cert/key handling.
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <uv.h>

#include "base/arena.h"
#include "base/base.h"
#include "base/string8.h"
#include "core/client.h"
#include "net/loop.h"
#include "profile/profile.h"
#include "support/loopback_server.h"
#include "tls/ja4.h"
#include "tls/ssl_ctx.h"

global int g_checks = 0, g_fails = 0;
#define CHECK(c)                                                   \
  Statement(g_checks += 1; if (!(c)) {                             \
    g_fails += 1;                                                  \
    fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
  })

global EventLoop *g_loop;

// Echo whether a client cert was presented.
static void mtls_handler(const LbRequest *req, LbResponse *resp, void *user) {
  (void)user;
  resp->status = 200;
  resp->body = (const U8 *)(req->client_cert ? "yes" : "no");
  resp->body_len = req->client_cert ? 3 : 2;
}

typedef struct RC {
  B32 got;
  int status;
  char body[16];
} RC;
static void on_resp(void *user, const Response *r) {
  RC *rc = (RC *)user;
  rc->got = 1;
  rc->status = r->status;
  U64 n = r->body_len < sizeof rc->body - 1 ? r->body_len : sizeof rc->body - 1;
  if (r->body && n) MemoryCopy(rc->body, r->body, n);
  rc->body[n] = 0;
  uv_stop(loop_uv(g_loop));
}

// Capture a ClientHello from a Chrome ctx WITH the client cert loaded, and
// compute its JA4 — to prove the cert doesn't perturb the ClientHello.
static String8 ja4_with_client_cert(Arena *a, const char *certp,
                                    const char *keyp) {
  const Profile *p = profile_chrome149();
  CtxResult cr = build_ctx(&p->tls, 0);
  if (!ctx_ok(&cr)) return str8_zero();
  SSL_CTX_use_certificate_chain_file(cr.ctx, certp);
  SSL_CTX_use_PrivateKey_file(cr.ctx, keyp, SSL_FILETYPE_PEM);
  SSL *ssl = SSL_new(cr.ctx);
  BIO *rb = BIO_new(BIO_s_mem()), *wb = BIO_new(BIO_s_mem());
  SSL_set_bio(ssl, rb, wb);
  SSL_set_connect_state(ssl);
  configure_ssl(ssl, &p->tls, "example.com", 0, 0, 0, 0);
  SSL_do_handshake(ssl);  // emits the ClientHello into wb
  const U8 *data = 0;
  size_t len = 0;
  BIO_mem_contents(wb, &data, &len);
  ClientHelloInfo info;
  MemoryZeroStruct(&info);
  if (data && len) info = ja4_parse_record(data, len);
  Fingerprints fp = ja4_compute(a, &info);
  SSL_free(ssl);
  SSL_CTX_free(cr.ctx);
  return fp.ja4;
}

int main(void) {
  const char *certp = "/tmp/holytls_mtls_cert.pem";
  const char *keyp = "/tmp/holytls_mtls_key.pem";
  CHECK(lb_write_test_cert(certp, keyp, /*passphrase=*/0));

  // (3) Fingerprint-neutrality: a loaded client cert must not change the JA4.
  Arena *a = arena_alloc();
  String8 ja4 = ja4_with_client_cert(a, certp, keyp);
  fprintf(stderr, "  JA4 with client cert = " STR8_Fmt "\n", STR8_Arg(ja4));
  CHECK(str8_match(ja4, str8_lit("t13d1516h2_8daaf6152771_d8a2da3f94cd")));

  EventLoop loop;
  loop_init(&loop);
  g_loop = &loop;
  U16 port = 0;
  LbServer *srv = lb_mtls_server_start(&loop, LB_ALPN_H2, mtls_handler, 0, &port);
  char url[64];
  snprintf(url, sizeof url, "https://127.0.0.1:%u/", port);

  Client c;
  client_init(&c, &loop, profile_chrome149(), NULL, HttpVersion_H2,
              /*verify=*/0);
  client_set_timeout_ms(&c, 8000);

  // (1) No client cert: the request still completes; the server sees none.
  RC rc1;
  MemoryZeroStruct(&rc1);
  client_get(&c, str8_cstring(url), on_resp, &rc1);
  loop_run(&loop);
  CHECK(rc1.got && rc1.status == 200 && strcmp(rc1.body, "no") == 0);

  // (2) Present a client cert: the server now sees it.
  CHECK(client_set_client_cert(&c, str8_cstring(certp), str8_cstring(keyp),
                               str8_zero()));
  RC rc2;
  MemoryZeroStruct(&rc2);
  client_get(&c, str8_cstring(url), on_resp, &rc2);
  loop_run(&loop);
  CHECK(rc2.got && rc2.status == 200 && strcmp(rc2.body, "yes") == 0);

  // (4) Encrypted key + the correct passphrase loads + presents the cert.
  const char *encp = "/tmp/holytls_mtls_enc_cert.pem";
  const char *enck = "/tmp/holytls_mtls_enc_key.pem";
  CHECK(lb_write_test_cert(encp, enck, "test-pw"));
  CHECK(client_set_client_cert(&c, str8_cstring(encp), str8_cstring(enck),
                               str8_lit("test-pw")));
  RC rc3;
  MemoryZeroStruct(&rc3);
  client_get(&c, str8_cstring(url), on_resp, &rc3);
  loop_run(&loop);
  CHECK(rc3.got && rc3.status == 200 && strcmp(rc3.body, "yes") == 0);

  // The WRONG passphrase fails to load (a throwaway client so the partial load
  // can't taint c).
  Client c2;
  client_init(&c2, &loop, profile_chrome149(), NULL, HttpVersion_H2,
              /*verify=*/0);
  CHECK(!client_set_client_cert(&c2, str8_cstring(encp), str8_cstring(enck),
                                str8_lit("wrong-pw")));
  client_cleanup(&c2);

  client_cleanup(&c);
  lb_server_stop(srv);
  for (int g = 0; g < 500 && uv_run(loop_uv(&loop), UV_RUN_NOWAIT); ++g) {
  }
  loop_shutdown(&loop);
  arena_release(a);

  fprintf(stderr, "[mtls_test] %d checks, %d failures\n", g_checks, g_fails);
  return g_fails ? 1 : 0;
}
