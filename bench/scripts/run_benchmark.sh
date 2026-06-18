#!/usr/bin/env bash
# Orchestrate the cross-client benchmark. Captures the environment, starts the
# Caddy origin (pinned to its own cores), then runs the focused v1 matrix in two
# fairness groups — single-thread (taskset -c 0, --single-thread 1) and
# full-power (a core set, --single-thread 0) — for each client × protocol ×
# scenario × payload × run, writing one JSON per cell. Finally aggregates into a
# report. Tunables via env: RUNS, REQUESTS, REQUESTS_COLD, WARMUP, CONCURRENCIES.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
. config/origin.env
CA="$here/config/ca.pem"

RUNS="${RUNS:-3}"
REQUESTS="${REQUESTS:-2000}"
REQUESTS_COLD="${REQUESTS_COLD:-800}"
WARMUP="${WARMUP:-200}"
CONCURRENCIES="${CONCURRENCIES:-1 8 64}"   # keepalive sweep (single-thread group)
FULLPOWER_C="${FULLPOWER_C:-64}"
ST_CORE="${ST_CORE:-0}"                      # single-thread pin
FP_CORES="${FP_CORES:-0-7}"                  # full-power pin (a set)
SRV_CORES="${SRV_CORES:-8-15}"               # origin pin (disjoint from clients)

TS="$(date +%Y%m%d-%H%M%S)"
OUT="$here/results/$TS"; JSON="$OUT/json"
mkdir -p "$JSON"

declare -A BIN=(
  [holytls]="$here/../build-bench/bench_holytls"
  [tls-client]="$here/go/tls_client/bench_tls_client"
  [httpcloak]="$here/go/httpcloak/bench_httpcloak"
  [wreq]="$here/rust/wreq/target/release/bench_wreq"
)
declare -A PROTOS=(
  [holytls]="h1 h2 h3"
  [tls-client]="h1 h2"
  [httpcloak]="h1 h2 h3"
  [wreq]="h1 h2"
)
CLIENTS="${CLIENTS:-holytls tls-client httpcloak wreq}"
PAYLOADS="${PAYLOADS:-1k.bin 100k.bin}"

have_taskset() { command -v taskset >/dev/null 2>&1; }
pin() { if have_taskset; then taskset -c "$1" "${@:2}"; else "${@:2}"; fi; }

capture_env() {
  {
    echo "date: $(date -u +%FT%TZ)"
    echo "host: $(uname -a)"
    echo "wsl: $(uname -r | grep -qi microsoft && echo yes || echo no)"
    echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
    echo "nproc: $(nproc)"
    echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'n/a (uncontrollable, e.g. WSL2)')"
    echo "taskset: $(have_taskset && echo yes || echo no)"
    echo "caddy: $("$here/server/caddy" version 2>/dev/null | head -1)"
    echo "go: $(go version 2>/dev/null)"
    echo "rustc: $(rustc --version 2>/dev/null)"
    echo "cc: $(cc --version 2>/dev/null | head -1)"
    echo "holytls_git: $(git -C "$here" rev-parse --short HEAD 2>/dev/null)"
    echo "params: RUNS=$RUNS REQUESTS=$REQUESTS REQUESTS_COLD=$REQUESTS_COLD WARMUP=$WARMUP CONCURRENCIES='$CONCURRENCIES' FULLPOWER_C=$FULLPOWER_C"
    echo "pins: single-thread=core $ST_CORE  full-power=cores $FP_CORES  origin=cores $SRV_CORES"
  } | tee "$OUT/env.txt"
}

cell() { # client proto mode conc payload group single_thread cores run
  local client="$1" proto="$2" mode="$3" conc="$4" payload="$5" group="$6" st="$7" cores="$8" run="$9"
  local reqs="$REQUESTS"; [ "$mode" = cold ] && reqs="$REQUESTS_COLD"
  local f="$JSON/${client}__${proto}__${mode}__c${conc}__${payload%.bin}__${group}__r${run}.json"
  pin "$cores" "${BIN[$client]}" --url "$ORIGIN_URL_BASE/$payload" --protocol "$proto" \
      --mode "$mode" --requests "$reqs" --concurrency "$conc" --warmup "$WARMUP" \
      --single-thread "$st" --ca "$CA" --out "$f" >/dev/null 2>>"$OUT/errors.log"
  local rc=$?
  printf "  %-10s %-3s %-9s c=%-3s %-8s %-12s run%s -> rc=%s\n" \
    "$client" "$proto" "$mode" "$conc" "${payload%.bin}" "$group" "$run" "$rc"
}

echo "== env =="; capture_env
echo "== setup =="
bash scripts/gen_cert.sh >/dev/null && bash scripts/gen_payloads.sh >/dev/null
bash scripts/fetch_caddy.sh >/dev/null 2>&1 || true
bash scripts/start_origin.sh stop >/dev/null 2>&1 || true
SRV_PIN=""; have_taskset && SRV_PIN="taskset -c $SRV_CORES"
$SRV_PIN bash scripts/start_origin.sh start; sleep 1.5
trap 'bash scripts/start_origin.sh stop >/dev/null 2>&1 || true' EXIT

echo "== single-thread group (apples-to-apples; core $ST_CORE) =="
for client in $CLIENTS; do
  for proto in ${PROTOS[$client]}; do
    for payload in $PAYLOADS; do
      for run in $(seq 1 "$RUNS"); do
        cell "$client" "$proto" cold 1 "$payload" single-thread 1 "$ST_CORE" "$run"
        for c in $CONCURRENCIES; do
          cell "$client" "$proto" keepalive "$c" "$payload" single-thread 1 "$ST_CORE" "$run"
        done
      done
    done
  done
done

echo "== full-power group (per-runtime; cores $FP_CORES; NOT directly comparable) =="
for client in $CLIENTS; do
  for proto in ${PROTOS[$client]}; do
    for payload in $PAYLOADS; do
      for run in $(seq 1 "$RUNS"); do
        cell "$client" "$proto" keepalive "$FULLPOWER_C" "$payload" full-power 0 "$FP_CORES" "$run"
      done
    done
  done
done

bash scripts/start_origin.sh stop >/dev/null 2>&1 || true
trap - EXIT
echo "== analyze =="
python3 scripts/analyze_results.py "$OUT"
echo "Results: $OUT"
