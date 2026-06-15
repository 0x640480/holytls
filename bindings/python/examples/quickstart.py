"""quickstart — the smallest holytls Python program: one Chrome-fingerprinted
GET, read the response.

    python examples/quickstart.py [url]
"""
import sys

import holytls


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "https://tls.peet.ws/api/all"

    # http_version="auto" is Chrome-faithful (H2, then H3 after alt-svc); verify
    # validates certs as a browser does.
    with holytls.Client(http_version="auto", timeout_ms=30000) as client:
        r = client.get(url)

        if not r.ok:  # a transport/TLS failure, NOT an HTTP error status
            print("request failed:", r.error, file=sys.stderr)
            return 1

        print(f"HTTP {r.status_code} over {r.alpn}  ({len(r.content)} bytes)")
        print("content-type:", r.headers.get("content-type"))
        print("timing(ms):", r.timing)
        print()
        print(r.text[:300] + (" ..." if len(r.text) > 300 else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
