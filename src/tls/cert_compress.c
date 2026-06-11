#include "tls/cert_compress.h"

#include <openssl/pool.h>

#include "profile/profile.h"

#ifdef HOLYTLS_HAVE_ZLIB
#include <zlib.h>
#endif

// brotli / zstd dev headers may be absent even when the runtime libs are
// present; declare the minimal one-shot decode prototypes ourselves.
#ifdef HOLYTLS_HAVE_BROTLI
int BrotliDecoderDecompress(size_t encoded_size, const U8 *encoded_buffer,
                            size_t *decoded_size, U8 *decoded_buffer);
#endif
#ifdef HOLYTLS_HAVE_ZSTD
size_t ZSTD_decompress(void *dst, size_t dst_cap, const void *src,
                       size_t src_size);
unsigned ZSTD_isError(size_t code);
#endif

// Each decompressor allocates an output CRYPTO_BUFFER of exactly the advertised
// uncompressed length, decodes into it, and verifies the produced size.
#ifdef HOLYTLS_HAVE_ZLIB
internal int zlib_dec(SSL *ssl, CRYPTO_BUFFER **out, size_t ulen, const U8 *in,
                      size_t in_len) {
  (void)ssl;
  U8 *data = 0;
  CRYPTO_BUFFER *buf = CRYPTO_BUFFER_alloc(&data, ulen);
  if (!buf) return 0;
  uLongf dlen = (uLongf)ulen;
  int r = uncompress(data, &dlen, in, (uLong)in_len);
  if (r != Z_OK || dlen != ulen) {
    CRYPTO_BUFFER_free(buf);
    return 0;
  }
  *out = buf;
  return 1;
}
#endif

#ifdef HOLYTLS_HAVE_BROTLI
internal int brotli_dec(SSL *ssl, CRYPTO_BUFFER **out, size_t ulen, const U8 *in,
                        size_t in_len) {
  (void)ssl;
  U8 *data = 0;
  CRYPTO_BUFFER *buf = CRYPTO_BUFFER_alloc(&data, ulen);
  if (!buf) return 0;
  size_t dlen = ulen;
  if (BrotliDecoderDecompress(in_len, in, &dlen, data) != 1 || dlen != ulen) {
    CRYPTO_BUFFER_free(buf);
    return 0;
  }
  *out = buf;
  return 1;
}
#endif

#ifdef HOLYTLS_HAVE_ZSTD
internal int zstd_dec(SSL *ssl, CRYPTO_BUFFER **out, size_t ulen, const U8 *in,
                      size_t in_len) {
  (void)ssl;
  U8 *data = 0;
  CRYPTO_BUFFER *buf = CRYPTO_BUFFER_alloc(&data, ulen);
  if (!buf) return 0;
  size_t r = ZSTD_decompress(data, ulen, in, in_len);
  if (ZSTD_isError(r) || r != ulen) {
    CRYPTO_BUFFER_free(buf);
    return 0;
  }
  *out = buf;
  return 1;
}
#endif

int register_cert_decompressors(SSL_CTX *ctx, const U16 *algs, int count,
                                const char **skipped, int *skipped_n) {
  int registered = 0;
  if (skipped_n) *skipped_n = 0;
  for (int i = 0; i < count; ++i) {
    ssl_cert_decompression_func_t fn = 0;
    const char *name = "unknown";
    switch (algs[i]) {
      case CertCompress_Zlib:
        name = "zlib";
#ifdef HOLYTLS_HAVE_ZLIB
        fn = zlib_dec;
#endif
        break;
      case CertCompress_Brotli:
        name = "brotli";
#ifdef HOLYTLS_HAVE_BROTLI
        fn = brotli_dec;
#endif
        break;
      case CertCompress_Zstd:
        name = "zstd";
#ifdef HOLYTLS_HAVE_ZSTD
        fn = zstd_dec;
#endif
        break;
      default:
        break;
    }
    if (fn && SSL_CTX_add_cert_compression_alg(ctx, algs[i], /*compress=*/0, fn)) {
      registered += 1;
    } else if (skipped && skipped_n && *skipped_n < 8) {
      skipped[(*skipped_n)++] = name;
    }
  }
  return registered;
}
