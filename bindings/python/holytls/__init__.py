"""holytls — Python bindings for the holytls TLS-impersonation HTTP client.

A `requests`-style API over a C client that reproduces Chrome's byte-exact
TLS / HTTP-2 / HTTP-3 fingerprint.

    import holytls

    with holytls.Client(dual=True) as client:
        r = client.get("https://tls.peet.ws/api/all")
        print(r.status_code, r.alpn)
        print(r.json()["tls"]["ja4"])

        # true concurrency on one event loop:
        for resp in client.get_many(["https://example.com", "https://example.org"]):
            print(resp.status_code, resp.url)

Cookies + redirects (a browser-like identity):

    with holytls.Client() as client:
        sess = holytls.Session(client)
        sess.get("https://httpbin.org/cookies/set?a=1")
        print(sess.get("https://httpbin.org/cookies").json())
"""

from holytls._models import (
    ConnectionClosed,
    FetchMode,
    Headers,
    HolyTLSError,
    HttpVersion,
    Method,
    Profile,
    Response,
    StatusError,
    Timing,
    TransportError,
    WebSocketError,
)

# Importing the client pulls in the native extension; keep it last so the pure
# value types above are importable even when diagnosing a missing build.
from holytls._client import Client, Session, WebSocket, version

__all__ = [
    "Client",
    "Session",
    "WebSocket",
    "Response",
    "Headers",
    "Timing",
    "Method",
    "HttpVersion",
    "FetchMode",
    "Profile",
    "HolyTLSError",
    "TransportError",
    "StatusError",
    "WebSocketError",
    "ConnectionClosed",
    "version",
]

__version__ = "0.1.0"
