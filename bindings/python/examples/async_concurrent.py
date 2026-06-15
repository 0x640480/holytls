"""asyncio: many requests concurrently on one native loop.

    python examples/async_concurrent.py

AsyncClient submits without blocking and resolves on your event loop, so
``asyncio.gather`` runs every request at once on holytls's single libuv loop —
true network parallelism, no thread-per-request.
"""
import asyncio
import sys
import time

import holytls

URLS = [
    "https://example.com",
    "https://example.org",
    "https://www.iana.org",
    "https://tls.peet.ws/api/all",
    "https://quic.browserleaks.com/json",
]


async def main():
    # http_version="auto" is Chrome-faithful (H2, then H3 after alt-svc).
    async with holytls.AsyncClient(http_version="auto", timeout_ms=30000) as client:
        # One await.
        r = await client.get("https://example.com")
        print(f"single: {r.status_code} {r.alpn} {len(r.content)} bytes")

        # All in flight at once.
        start = time.time()
        responses = await asyncio.gather(*(client.get(u) for u in URLS))
        elapsed = time.time() - start
        for url, r in zip(URLS, responses):
            mark = "ok " if r.ok else "ERR"
            print(f"  [{mark}] {r.status_code} {r.alpn:2} {url}")
        print(f"{len(URLS)} requests concurrently in {elapsed:.2f}s")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
