#!/usr/bin/env python3
"""Aggregate the per-cell JSON from a benchmark run into report.md + aggregate.csv.

Usage: analyze_results.py <results_dir>   (the dir containing json/ + env.txt)

Each cell was run RUNS times; we report the median across runs plus the
[min-max] spread. The single-thread group is the apples-to-apples headline; the
full-power group is reported separately and is NOT directly comparable.
"""
import csv
import glob
import json
import os
import statistics
import sys

CLIENT_ORDER = ["holytls", "tls-client", "httpcloak", "wreq"]
PROTOS = ["h1", "h2", "h3"]


def load(results_dir):
    cells = []
    for path in glob.glob(os.path.join(results_dir, "json", "*.json")):
        try:
            d = json.load(open(path))
        except Exception:
            continue
        name = os.path.basename(path)[:-5]
        parts = name.split("__")  # client__proto__mode__cNN__payload__group__rN
        if len(parts) != 7:
            continue
        d["_group"] = parts[5]
        d["_payload"] = parts[4]
        d["_run"] = parts[6]
        cells.append(d)
    return cells


def agg(cells, **filt):
    """Group filtered cells by (client, proto) and return median metrics."""
    groups = {}
    for c in cells:
        ok = True
        for k, v in filt.items():
            if c.get(k) != v:  # k is a real JSON key (mode, concurrency) or a
                ok = False     # filename-derived one (_group, _payload)
                break
        if not ok:
            continue
        key = (c["client"], c["protocol_requested"])
        groups.setdefault(key, []).append(c)
    out = {}
    for key, cs in groups.items():
        rps = [c["throughput_rps"] for c in cs]
        p50 = [c["latency_ms"]["p50"] for c in cs]
        p99 = [c["latency_ms"]["p99"] for c in cs]
        errs = sum(c["errors"] for c in cs)
        negotiated = cs[0].get("protocol_negotiated", "?")
        mismatch = any(c.get("protocol_negotiated") not in (c["protocol_requested"], "") for c in cs)
        out[key] = {
            "rps": statistics.median(rps), "rps_lo": min(rps), "rps_hi": max(rps),
            "p50": statistics.median(p50), "p99": statistics.median(p99),
            "errors": errs, "negotiated": negotiated, "mismatch": mismatch,
            "conns": cs[0].get("connections_created"), "rss": max(c.get("peak_rss_kb", 0) for c in cs),
            "n": len(cs),
        }
    return out


def fmt(x, nd=0):
    if x is None:
        return "—"
    return f"{x:,.{nd}f}"


def table(cells, *, metric, group, mode, conc, payload, nd=0):
    a = agg(cells, _group=group, mode=mode, concurrency=conc, _payload=payload)
    lines = ["| client | " + " | ".join(PROTOS) + " |",
             "|" + "---|" * (len(PROTOS) + 1)]
    for client in CLIENT_ORDER:
        row = [client]
        for p in PROTOS:
            d = a.get((client, p))
            if d is None:
                row.append("—")
            elif d["errors"] and metric == "rps":
                row.append(f"err({d['errors']})")
            else:
                v = d[metric]
                cell = fmt(v, nd)
                if metric == "rps" and d["mismatch"]:
                    cell += "⚠"
                row.append(cell)
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def main():
    rd = sys.argv[1]
    cells = load(rd)
    env = open(os.path.join(rd, "env.txt")).read() if os.path.exists(os.path.join(rd, "env.txt")) else ""

    # CSV of every aggregated cell
    with open(os.path.join(rd, "aggregate.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["client", "protocol", "group", "mode", "concurrency", "payload",
                    "rps_median", "rps_min", "rps_max", "p50_ms", "p99_ms", "errors",
                    "negotiated", "conns", "rss_kb", "runs"])
        seen = {}
        for c in cells:
            k = (c["client"], c["protocol_requested"], c["_group"], c["mode"],
                 c["concurrency"], c["_payload"])
            seen.setdefault(k, []).append(c)
        for k, cs in sorted(seen.items()):
            rps = [c["throughput_rps"] for c in cs]
            w.writerow([*k, f"{statistics.median(rps):.1f}", f"{min(rps):.1f}", f"{max(rps):.1f}",
                        f"{statistics.median([c['latency_ms']['p50'] for c in cs]):.3f}",
                        f"{statistics.median([c['latency_ms']['p99'] for c in cs]):.3f}",
                        sum(c["errors"] for c in cs), cs[0].get("protocol_negotiated"),
                        cs[0].get("connections_created"), max(c.get("peak_rss_kb", 0) for c in cs), len(cs)])

    R = []
    R.append("# Cross-client TLS-impersonation HTTP benchmark — results\n")
    R.append("Clients: **holytls** (C), **tls-client** (Go), **httpcloak** (Go), **wreq** (Rust). "
             "`—` = not run (e.g. H3 for tls-client/wreq, which lack QUIC). `⚠` = a run negotiated "
             "a different protocol than requested.\n")
    R.append("## Environment\n```\n" + env.strip() + "\n```\n")

    R.append("## Single-thread group — apples-to-apples (all pinned to one core)\n")
    R.append("This is the headline: every client is held to a single core / single-thread runtime, "
             "so the numbers reflect the client, not how many cores its runtime grabbed.\n")
    for payload in ("1k", "100k"):
        R.append(f"### Keepalive throughput — req/s (median of runs), payload {payload}\n")
        for c in ("1", "8", "64"):
            R.append(f"**concurrency {c}**\n")
            R.append(table(cells, metric="rps", group="single-thread", mode="keepalive",
                           conc=int(c), payload=payload) + "\n")
        R.append(f"### Keepalive tail latency — p99 ms (median), payload {payload}, concurrency 8\n")
        R.append(table(cells, metric="p99", group="single-thread", mode="keepalive",
                       conc=8, payload=payload, nd=3) + "\n")
    R.append("### Cold / new-connection — req/s, payload 1k, concurrency 1\n")
    R.append("Fresh connection per request. **Caveat:** TLS resumption on the new connection is "
             "client-dependent — holytls / tls-client / wreq do full handshakes; **httpcloak keeps "
             "TLS tickets and 1-RTT resumes**, so its cold number is not a full-handshake cost.\n")
    R.append(table(cells, metric="rps", group="single-thread", mode="cold", conc=1, payload="1k") + "\n")

    R.append("## Full-power group — per-runtime (NOT directly comparable)\n")
    R.append("Each runtime at its natural parallelism (Go/Rust multi-threaded; holytls is a single "
             "libuv loop **by design**). Higher numbers here reflect cores used, not a faster client — "
             f"do not read this as a head-to-head. Keepalive, concurrency {64}.\n")
    for payload in ("1k", "100k"):
        R.append(f"### Throughput — req/s, payload {payload}, concurrency 64 (full power)\n")
        R.append(table(cells, metric="rps", group="full-power", mode="keepalive",
                       conc=64, payload=payload) + "\n")

    R.append("## Caveats (read before quoting any number)\n")
    R.append("- **Single-loop vs multi-threaded.** holytls is one libuv loop; tls-client/httpcloak (Go) "
             "and wreq (Rust) are multi-threaded runtimes. The single-thread group is the fair "
             "comparison; full-power is per-runtime and not head-to-head.\n"
             "- **Different TLS/H2/H3 stacks.** holytls = lexiforest/BoringSSL + nghttp2 + ngtcp2; "
             "wreq = upstream BoringSSL; tls-client = Go utls + net/http2; httpcloak = sardanioss "
             "utls + quic-go forks. This benchmarks end-to-end client performance, not just TLS.\n"
             "- **Cold resumption** (above): httpcloak resumes; others full-handshake. Keepalive is "
             "the clean steady-state comparison.\n"
             "- **HTTP/3** is holytls vs httpcloak only (tls-client/wreq have no QUIC — a feature gap, "
             "not a loss).\n"
             "- **Environment.** See above; on WSL2 the CPU governor/turbo are uncontrollable and "
             "timers are virtualized — treat WSL2 numbers as directional and re-run on bare metal "
             "for publication.\n"
             "- **wreq** trusts the origin via skip-verify (no custom-CA API); the full handshake "
             "still runs, only the microsecond chain check is skipped.\n")
    R.append(f"\nFull data: `aggregate.csv` + `json/` ({len(cells)} cells).\n")

    open(os.path.join(rd, "report.md"), "w").write("\n".join(R))
    print(f"wrote {rd}/report.md + aggregate.csv ({len(cells)} cells)")


if __name__ == "__main__":
    main()
