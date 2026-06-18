#!/usr/bin/env bash
# Download a version-pinned Caddy v2 binary (the local H1/H2/H3 origin) into
# bench/server/. On first run it records the sha256 into server/caddy.sha256;
# subsequent runs verify against it (reproducibility). Pin a new version by
# bumping CADDY_VERSION and deleting caddy.sha256.
set -euo pipefail
CADDY_VERSION="${CADDY_VERSION:-2.8.4}"
arch="amd64"; case "$(uname -m)" in aarch64|arm64) arch="arm64";; esac
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
srv="$here/server"
mkdir -p "$srv"
bin="$srv/caddy"
tarball="caddy_${CADDY_VERSION}_linux_${arch}.tar.gz"
url="https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/${tarball}"

if [ -x "$bin" ] && "$bin" version 2>/dev/null | grep -q "v${CADDY_VERSION}"; then
  echo "[fetch_caddy] caddy v${CADDY_VERSION} already present: $bin"; exit 0
fi

echo "[fetch_caddy] downloading $url"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/$tarball"
sum="$(sha256sum "$tmp/$tarball" | awk '{print $1}')"
shafile="$srv/caddy.sha256"
if [ -f "$shafile" ]; then
  want="$(cat "$shafile")"
  [ "$sum" = "$want" ] || { echo "[fetch_caddy] sha256 MISMATCH: got $sum want $want" >&2; exit 1; }
  echo "[fetch_caddy] sha256 verified against pinned $shafile"
else
  echo "$sum" > "$shafile"
  echo "[fetch_caddy] recorded sha256 -> $shafile ($sum)"
fi
tar -xzf "$tmp/$tarball" -C "$tmp" caddy
install -m 0755 "$tmp/caddy" "$bin"
"$bin" version
