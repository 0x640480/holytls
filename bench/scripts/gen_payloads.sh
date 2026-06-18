#!/usr/bin/env bash
# Generate deterministic (zero-filled) payload files the origin serves, and pin
# their sha256 so every client receives byte-identical bodies across runs.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$here/server/payloads"
mkdir -p "$out"
declare -A sizes=( [0.bin]=0 [1k.bin]=1024 [100k.bin]=102400 [1m.bin]=1048576 )
for f in "${!sizes[@]}"; do
  head -c "${sizes[$f]}" /dev/zero > "$out/$f"
done
( cd "$out" && sha256sum -- *.bin > CHECKSUMS )
echo "[gen_payloads] wrote $out/{0,1k,100k,1m}.bin + CHECKSUMS"
sed 's/^/  /' "$out/CHECKSUMS"
