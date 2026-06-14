"""streaming — download a large body without buffering it in memory.

Pass on_chunk= to receive the DECODED body in pieces as it arrives (over HTTP/2
this is true bounded-memory streaming); the returned Response carries an empty
content. Streaming forces a single hop (no redirects) and the non-pooled path.

    python examples/streaming.py
"""
import hashlib

import holytls


def main():
    url = "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"

    with holytls.Client(timeout_ms=30000) as client:
        # Stream: accumulate a rolling hash + count chunks, never holding the
        # whole body. (In real use you'd write each chunk to a file/socket.)
        sha = hashlib.sha256()
        chunks = 0
        total = [0]

        def sink(chunk: bytes):
            nonlocal chunks
            sha.update(chunk)
            total[0] += len(chunk)
            chunks += 1

        r = client.get(url, on_chunk=sink)
        print(f"streamed {total[0]} bytes over {r.alpn} in {chunks} chunk(s)")
        print("sha256:", sha.hexdigest())
        print("Response.content is empty (streamed):", len(r.content) == 0)

        # Cross-check against a normal buffered GET of the same (static) file.
        full = client.get(url)
        print("matches buffered GET:",
              hashlib.sha256(full.content).hexdigest() == sha.hexdigest())


if __name__ == "__main__":
    main()
