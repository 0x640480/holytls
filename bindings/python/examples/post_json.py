"""post_json — POST a JSON body with custom headers, parse the reply.

``json=`` serializes the object and adds ``Content-Type: application/json`` when
you didn't set one; ``data=`` sends raw bytes/str unchanged. Extra ``headers=``
are merged into the request in wire order.

    python examples/post_json.py
"""
import holytls


def main():
    with holytls.Client(timeout_ms=30000) as client:
        r = client.post(
            "https://httpbin.org/post",
            json={"project": "holytls", "stars": 1, "nested": {"ok": True}},
            headers={"x-demo": "holytls-python"},
        )
        r.raise_for_status()  # raises on transport failure or 4xx/5xx

        echo = r.json()
        print("status      :", r.status_code, "over", r.alpn)
        print("server saw  :", echo.get("json"))
        print("content-type:", echo.get("headers", {}).get("Content-Type"))
        print("x-demo back :", echo.get("headers", {}).get("X-Demo"))

        # A raw (non-JSON) body:
        r2 = client.post("https://httpbin.org/post", data=b"\x00\x01rawbytes")
        print("raw len back:", r2.json().get("data") and "received")


if __name__ == "__main__":
    main()
