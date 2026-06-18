#!/usr/bin/env bash
# Generate a self-signed CA + leaf cert for the local benchmark origin
# (127.0.0.1 / localhost). EC P-256 (browser-realistic + fast handshake). The CA
# is trusted by every client harness (NOT skip-verify) so TLS-verify cost is
# uniform across clients. Idempotent: regenerates on each call. Outputs into
# bench/config/: ca.pem, ca.key, leaf.pem, leaf.key.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cfg="$here/config"
mkdir -p "$cfg"
cd "$cfg"

# CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 \
  -subj "/CN=holytls-bench local CA" -out ca.pem

# Leaf (SAN: 127.0.0.1 + localhost)
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key -subj "/CN=127.0.0.1" -out leaf.csr
cat > leaf.ext <<'EXT'
subjectAltName = IP:127.0.0.1, DNS:localhost
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EXT
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 3650 -sha256 -extfile leaf.ext -out leaf.pem
rm -f leaf.csr leaf.ext ca.srl

echo "[gen_cert] wrote $cfg/{ca.pem,ca.key,leaf.pem,leaf.key}"
openssl x509 -in leaf.pem -noout -subject -ext subjectAltName | sed 's/^/  /'
