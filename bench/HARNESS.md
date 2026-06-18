# Harness contract

Every client harness (`bench/c`, `bench/go/*`, `bench/rust/*`) is a standalone
native program with the **same CLI** and the **same JSON output**, so the
orchestrator drives them identically and the results are directly comparable.

## CLI

```
--url <URL>            full target URL, e.g. https://localhost:18443/1k.bin (required)
--protocol h1|h2|h3    wire protocol to force (default h2)
--mode cold|keepalive  cold = fresh connection per request; keepalive = reuse (default keepalive)
--requests N           measured requests (default 1000)
--concurrency C        in-flight requests / workers (default 1)
--warmup W             warmup requests, discarded (default 200)
--single-thread 0|1    1 = pin the runtime to one thread (GOMAXPROCS=1 / tokio current_thread /
                       holytls is always 1 loop). The orchestrator also taskset-pins. (default 1)
--max-conns N          max pooled connections per origin (optional; default derived from mode:
                       keepalive=1, cold=0/non-pooled)
--ca <pem>             PEM CA to trust for the origin (the harness must TRUST it, not skip-verify)
--out <file>           write the JSON here (default stdout)
```

A harness MUST: force the requested protocol and **fail** (exit non-zero) if the
negotiated ALPN differs (no silent downgrade); trust `--ca` (never skip-verify);
disable redirects + cookie jar; drain the full response body; and report honest
`connections_created` (so the orchestrator can assert keepalive reuse). H3 on a
client that lacks it must exit non-zero with `"errors"` set, not pretend.

## JSON output

```json
{
  "client": "holytls|tls-client|wreq|httpcloak",
  "client_version": "string",
  "protocol_requested": "h1|h2|h3",
  "protocol_negotiated": "h1|h2|h3",
  "mode": "cold|keepalive",
  "concurrency": 8,
  "single_thread": 1,
  "requests": 1000,
  "warmup": 200,
  "throughput_rps": 28772.0,
  "latency_ms": { "p50": 0.27, "p90": 0.4, "p99": 0.46, "p999": 1.1, "max": 2.0 },
  "handshake_ms": { "p50": 1.0 },
  "connections_created": 1,
  "pool_reuses": 999,
  "bytes_received": 1024000,
  "status": 200,
  "errors": 0,
  "error_sample": "",
  "peak_rss_kb": 9452,
  "cpu_user_ms": 18.0,
  "cpu_sys_ms": 2.0,
  "wall_ms": 34.8,
  "alloc": { "arenas_created": 0, "bytes_reserved": 0 }
}
```

Notes:
- **latency_ms** = per-request service time (closed loop: each worker waits for full
  body delivery before its next request). Percentiles are nearest-rank.
- **throughput_rps** = measured requests / measured wall seconds.
- **handshake_ms.p50** = median TLS/QUIC handshake (meaningful in `cold`; ~0 on reuse).
- **connections_created**: keepalive should be 1 (the orchestrator asserts this);
  cold ≈ requests. Counted from each client's pool/connection stats where available.
- **peak_rss_kb / cpu_*_ms** via `getrusage(RUSAGE_SELF)` (CPU deltas around the
  measured phase; RSS is the process peak).
- **alloc** is holytls-only (arena counters when built `-DHOLYTLS_ARENA_STATS=ON`);
  other clients emit `{ "arenas_created": 0, "bytes_reserved": 0 }`.
