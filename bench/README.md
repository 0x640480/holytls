# holytls cross-client benchmark

A reproducible benchmark comparing **holytls** (C) against three other
TLS-impersonation HTTP clients across **HTTP/1.1, HTTP/2, and HTTP/3**:

| Client | Lang | TLS / H3 stack | H1 | H2 | H3 |
|---|---|---|---|---|---|
| [holytls](../) | C | lexiforest/BoringSSL + nghttp2 + ngtcp2 | ✅ | ✅ | ✅ |
| [tls-client](https://github.com/bogdanfinn/tls-client) | Go | utls + Go net/http2 | ✅ | ✅ | — |
| [wreq](https://github.com/0x676e67/wreq) | Rust | BoringSSL (btls) | ✅ | ✅ | — |
| [httpcloak](https://github.com/sardanioss/httpcloak) | Go | sardanioss utls + quic-go | ✅ | ✅ | ✅ |

Each client is driven by a tiny native harness that shares one CLI + JSON
contract (**[HARNESS.md](HARNESS.md)**), against a pinned local **Caddy** origin
that speaks all three protocols. Results are reported in two fairness groups:
a **single-thread** apples-to-apples group (the headline) and a **full-power**
per-runtime group (not directly comparable). See **[SAMPLE_REPORT.md](SAMPLE_REPORT.md)**
for an example and the full caveats.

## Prerequisites
- Linux, a C toolchain + CMake (to build holytls), **Go** (tls-client, httpcloak),
  **Rust/cargo** (wreq), `openssl`, `curl`, `python3`, `taskset`.
- Network access on first run (downloads pinned Caddy + the Go/Rust deps).

## Run
```sh
# 1. Build the holytls harness (reuses the holytls build; arena counters on):
cmake -B build-bench -DHOLYTLS_BUILD_BENCH=ON -DHOLYTLS_ARENA_STATS=ON
cmake --build build-bench --target bench_holytls

# 2. Build the competitor harnesses:
( cd bench/go/tls_client && go build -o bench_tls_client . )
( cd bench/go/httpcloak  && go build -o bench_httpcloak . )
( cd bench/rust/wreq     && cargo build --release )

# 3. Run the full matrix (sets up cert/payloads/Caddy itself):
bash bench/scripts/run_benchmark.sh
#    -> bench/results/<timestamp>/report.md  +  aggregate.csv  +  json/

# Quick pass (fewer runs/requests):
RUNS=2 REQUESTS=1200 REQUESTS_COLD=400 bash bench/scripts/run_benchmark.sh
```
The orchestrator captures the environment, starts Caddy (pinned to its own
cores), runs every cell in both fairness groups with `taskset` pinning, and
aggregates into a median+IQR report.

## Layout
```
bench/
  HARNESS.md           the shared CLI + JSON contract
  SAMPLE_REPORT.md     an example results report (with caveats)
  c/bench_holytls.c    holytls harness (built via -DHOLYTLS_BUILD_BENCH)
  go/tls_client/       tls-client harness (pinned go.mod)
  go/httpcloak/        httpcloak harness (pinned go.mod)
  rust/wreq/           wreq harness (pinned Cargo.toml/lock)
  server/              Caddy origin (fetched, sha-pinned) + deterministic payloads
  config/              Caddyfile, origin.env, self-signed CA (regenerated)
  scripts/             gen_cert, gen_payloads, fetch_caddy, start_origin,
                       run_benchmark, analyze_results
```

## Scope (v1) and honesty
v1 is a **focused matrix** (H1/H2 for all four + H3 for holytls/httpcloak; cold +
keepalive + a concurrency sweep; 1K/100K payloads; both fairness groups) against
a controlled local origin. It is **not** a marketing artifact — the report's
caveats (single-loop vs multi-threaded, four different TLS stacks, cold TLS
resumption, the H3 feature gap, WSL2 timing) are required reading. Publication
numbers should be re-run on bare-metal Linux. A small real-endpoint phase, an
open-loop latency-tail test, and plots are planned for v1.5.
