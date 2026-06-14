"""session_cookies — a browser-like identity: a cookie jar that persists across
requests, with redirects followed per hop.

A Session layers a cookie jar + redirect loop on a shared Client (the transport
and its fingerprint stay the Client's). Cookies set by one response are attached
to later requests automatically; redirects are followed with the jar applied at
each hop. Create many Sessions on one Client for many independent identities.

    python examples/session_cookies.py
"""
import holytls


def main():
    with holytls.Client(timeout_ms=30000) as client:
        session = holytls.Session(client, cookies=True, max_redirects=10)

        # /cookies/set 302-redirects to /cookies; the Session follows it AND
        # absorbs the Set-Cookie along the way.
        r = session.get("https://httpbin.org/cookies/set?session=holytls&tier=pro")
        print("after set -> final url:", r.url)

        # A later request carries the jar without us re-sending anything.
        jar = session.get("https://httpbin.org/cookies").json()
        print("server sees cookies   :", jar.get("cookies"))

        # A second, independent identity on the same transport has an empty jar.
        other = holytls.Session(client)
        empty = other.get("https://httpbin.org/cookies").json()
        print("a fresh session's jar :", empty.get("cookies"))


if __name__ == "__main__":
    main()
