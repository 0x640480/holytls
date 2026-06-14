"""websocket — a RFC 6455 WebSocket over the client's Chrome TLS fingerprint.

client.websocket(url) opens a wss:// connection riding the same fingerprinted
TLS as the HTTP client. It is blocking + single-threaded: recv() runs the loop
until the next message. Over an h2 server it uses RFC 8441 Extended CONNECT;
otherwise the HTTP/1.1 Upgrade (see ws.transport). send() sends a str as a text
frame, bytes as binary; recv() returns str/bytes; the peer closing raises
ConnectionClosed.

    python examples/websocket.py
"""
import holytls


def main():
    with holytls.Client() as client:
        with client.websocket("wss://echo.websocket.org") as ws:
            print("connected, transport:", ws.transport)

            ws.send("hello over websocket")
            ws.send(b"\x00\x01\x02 binary too")

            # echo.websocket.org sends a one-line banner first, then echoes each
            # frame. recv(timeout=) returns whatever arrives; stop when the 5s
            # deadline lapses so a quiet connection can't hang us.
            try:
                while True:
                    msg = ws.recv(timeout=5)
                    kind = "text" if isinstance(msg, str) else "binary"
                    print(f"  <- {kind}: {msg!r}")
            except TimeoutError:
                pass
            except holytls.ConnectionClosed as e:
                print("  closed by peer:", e.code, e.reason)

            ws.close()
            print("closed")


if __name__ == "__main__":
    main()
