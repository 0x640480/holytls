"""concurrent — fetch many URLs in parallel on a single event loop.

holytls's strength is event-loop concurrency: ``get_many`` submits every request
to one loop and runs it once until all complete — true network parallelism in a
single thread, no thread pool, no asyncio. The whole batch is one C call, so the
GIL is held throughout but nothing Python runs while the requests are in flight.

    python examples/concurrent.py
"""
import time

import holytls

URLS = [
    "https://example.com",
    "https://example.org",
    "https://www.iana.org",
    "https://tls.peet.ws/api/clean",
    "https://www.cloudflare.com",
    "https://httpbin.org/get",
]


def main():
    with holytls.Client(http_version="auto", timeout_ms=30000) as client:
        # Concurrent: all six in flight at once.
        start = time.time()
        responses = client.get_many(URLS)
        concurrent_s = time.time() - start

        for url, r in zip(URLS, responses):
            status = f"{r.status_code} {r.alpn}" if r.ok else f"ERR {r.error}"
            print(f"  {status:>12}  {len(r.content):>7} B  {url}")
        print(f"\n{len(URLS)} requests concurrently in {concurrent_s:.2f}s")

        # For contrast: the same URLs one at a time.
        start = time.time()
        for url in URLS:
            client.get(url)
        serial_s = time.time() - start
        print(f"{len(URLS)} requests serially     in {serial_s:.2f}s "
              f"({serial_s / concurrent_s:.1f}x slower)")


if __name__ == "__main__":
    main()
