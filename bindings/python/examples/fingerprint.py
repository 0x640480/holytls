"""fingerprint — prove the client really impersonates Chrome by reading back the
JA4 / JA3 / Akamai fingerprints a server computes from our TLS + HTTP/2 bytes,
then confirming the H3 path actually negotiates over QUIC.

``tls.peet.ws`` echoes the fingerprints it observed over HTTP/2 (it is a TCP/H2
oracle and does not serve HTTP/3). For H3 we just connect to a known QUIC host
and check the negotiated ALPN is ``h3``.

    python examples/fingerprint.py
"""
import holytls


def main():
    # HTTP/2: read the fingerprints the oracle computed from our bytes.
    with holytls.Client(timeout_ms=30000) as client:
        r = client.get("https://tls.peet.ws/api/all")
        r.raise_for_status()
        j = r.json()
        tls = j.get("tls", {})
        print(f"HTTP/2 (ALPN {r.alpn}):")
        print("  JA4      :", tls.get("ja4"))
        print("  JA3 hash :", tls.get("ja3_hash"))
        print("  peetprint:", tls.get("peetprint_hash"))
        print("  Akamai H2:", (j.get("http2") or {}).get("akamai_fingerprint_hash"))

    # HTTP/3: confirm the QUIC path negotiates h3 against a real H3 host.
    with holytls.Client(http_version="h3", timeout_ms=30000) as client:
        r = client.get("https://cloudflare-quic.com/")
        print(f"\nHTTP/3: ok={r.ok} status={r.status_code} alpn={r.alpn!r}")


if __name__ == "__main__":
    main()
