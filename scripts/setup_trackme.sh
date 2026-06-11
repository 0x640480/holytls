#!/usr/bin/env bash
# Set up a local, no-sudo TrackMe — the open-source backend behind tls.peet.ws
# (github.com/pagpeter/TrackMe) — as a self-hosted TLS/HTTP-2 fingerprint oracle for
# holytls. Builds pure-Go (no libpcap, no root), listens on 127.0.0.1:8443.
#
#   ./scripts/setup_trackme.sh [REPO_DIR]      # default REPO_DIR=$HOME/trackme
#   cd "$REPO_DIR" && ./out/app                # run it (foreground)
#   HOLYTLS_TRACKME=1 ./build/trackme_local_test   # cross-check holytls against it
#
# Why patch? Upstream pkg/tcp does TCP/IP fingerprinting via gopacket/pcap, which needs
# cgo+libpcap to BUILD and CAP_NET_RAW to RUN (and log.Fatal()s if it can't). We don't
# need that half (JA3/JA4/Akamai/PeetPrint come from the userspace TLS/H2 parsers), so we
# replace pkg/tcp/tcp.go with a no-op stub — the only source delta from upstream.
set -euo pipefail

REPO="${1:-$HOME/trackme}"
PORT_TLS="8443"
PORT_HTTP="8080"

command -v go >/dev/null || { echo "ERROR: Go toolchain not found"; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl not found"; exit 1; }

if [ ! -d "$REPO/.git" ] && [ ! -f "$REPO/go.mod" ]; then
  echo ">> cloning TrackMe into $REPO"
  git clone --depth 1 https://github.com/pagpeter/TrackMe "$REPO"
else
  echo ">> reusing existing checkout at $REPO"
fi
cd "$REPO"

echo ">> patching pkg/tcp/tcp.go -> pure-Go no-op stub (drops gopacket/pcap)"
cat > pkg/tcp/tcp.go <<'EOF'
package tcp

// PURE-GO STUB (holytls local-oracle build). Drops the gopacket/pcap TCP/IP sniffer so
// the server builds without libpcap/cgo and runs unprivileged. SniffTCP keeps its
// upstream signature and is a no-op; with config "device":"" it is never called.
import "github.com/pagpeter/trackme/pkg/server"

func SniffTCP(device string, tlsPort int, srv *server.Server) {
	_ = device
	_ = tlsPort
	_ = srv
}
EOF

if [ ! -f certs/chain.pem ] || [ ! -f certs/key.pem ]; then
  echo ">> generating self-signed cert (certs/chain.pem, certs/key.pem)"
  mkdir -p certs
  openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/key.pem -out certs/chain.pem -days 825 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:tls.peet.ws,DNS:tls.browserleaks.com,IP:127.0.0.1"
else
  echo ">> reusing existing certs/"
fi

echo ">> writing config.json (ports $PORT_TLS/$PORT_HTTP, device disabled, QUIC off)"
cat > config.json <<EOF
{
  "log_to_db": false,
  "tls_port": "$PORT_TLS",
  "http_port": "$PORT_HTTP",
  "cert_file": "certs/chain.pem",
  "key_file": "certs/key.pem",
  "host": "127.0.0.1",
  "http_redirect": "https://localhost:$PORT_TLS",
  "device": "",
  "cors_key": "X-CORS",
  "enable_quic": false
}
EOF

echo ">> building (CGO_ENABLED=0, pure-Go static binary)"
mkdir -p out
CGO_ENABLED=0 go build -o ./out/app ./cmd/main.go

echo
echo "OK. TrackMe oracle ready at $REPO"
echo "  run:    (cd '$REPO' && ./out/app)"
echo "  test:   curl -sk --http2 https://127.0.0.1:$PORT_TLS/api/clean"
echo "  holytls cross-check: HOLYTLS_TRACKME=1 ./build/trackme_local_test"
